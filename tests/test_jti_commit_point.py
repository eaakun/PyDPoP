"""jti commit-point semantics (protocol-infra memo, ruling #1).

The ``jti`` is consumed only at the final commit point: every other
check (signature, htm/htu, iat window, nonce, ath) runs first, and
``check_and_record`` is the last possibly-failing step. A proof that
fails any earlier check never burns its ``jti`` — so "jti consumed"
⇔ "proof accepted". This is a tightening, not a relaxation: under
the old pre-check order, an attacker who tampered with ``ath`` on
an intercepted legitimate proof burned the victim's ``jti`` and the
real client's retry was misjudged as a replay.
"""
from __future__ import annotations

import base64
import json

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from pydpop import (
    DPoPError,
    MemoryJtiStore,
    VerificationFailure,
    generate_key,
    generate_proof,
    verify_proof,
    verify_proof_result,
)
from pydpop.jwk import b64u_encode

HTM = "POST"
HTU = "https://server.example.com/token"
NOW = 1_700_000_000


def _b64u_json(obj: dict) -> str:
    return b64u_encode(json.dumps(obj, separators=(",", ":")).encode("utf-8"))


def _decode_segment(seg: str) -> dict:
    return json.loads(base64.urlsafe_b64decode(seg + "=="))


def _resign(key, header: dict, payload: dict) -> str:
    """Re-sign (possibly modified) header/payload with the real key."""
    signing_input = f"{_b64u_json(header)}.{_b64u_json(payload)}".encode("ascii")
    der_sig = key.sign(signing_input, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der_sig)
    raw_sig = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    return f"{signing_input.decode('ascii')}.{b64u_encode(raw_sig)}"


def _retamper_claims(proof: str, **changes) -> str:
    """Return the proof with claims changed but NOT re-signed, so the
    signature no longer matches the payload (attacker tampering)."""
    head, payload_b64, sig = proof.split(".")
    payload = _decode_segment(payload_b64)
    payload.update(changes)
    return f"{head}.{_b64u_json(payload)}.{sig}"


class _RecordingStore:
    """A ReplayStore that logs every check_and_record call."""

    def __init__(self):
        self.calls: list[tuple[str, int]] = []
        self._seen: set[str] = set()

    def check_and_record(self, jti: str, iat: int) -> bool:
        self.calls.append((jti, iat))
        if jti in self._seen:
            return False
        self._seen.add(jti)
        return True


def test_tampered_ath_does_not_consume_jti():
    """Attacker intercepts a legitimate proof and tampers with ath:
    the tampered proof is rejected, and the ORIGINAL proof with the
    same jti is still accepted afterwards (its jti was not burned)."""
    key = generate_key()
    store = MemoryJtiStore()
    original = generate_proof(
        private_key=key, htm=HTM, htu=HTU, access_token="token-A",
        iat=NOW, jti="victim-jti-1",
    )
    kwargs = {"htm": HTM, "htu": HTU, "access_token": "token-A",
              "now": NOW, "jti_store": store}

    # (a) ath tampered without re-signing -> signature fails
    tampered = _retamper_claims(original, ath="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
    result = verify_proof_result(proof=tampered, **kwargs)
    assert result.reason is VerificationFailure.BAD_SIGNATURE

    # (b) ath replaced and re-signed with the real key -> ath fails
    head_b64, payload_b64, _ = original.split(".")
    header = _decode_segment(head_b64)
    payload = _decode_segment(payload_b64)
    payload["ath"] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    resigned = _resign(key, header, payload)
    result = verify_proof_result(proof=resigned, **kwargs)
    assert result.reason is VerificationFailure.ATH_MISMATCH

    # The original proof is still accepted: neither failure consumed jti.
    assert verify_proof_result(proof=original, **kwargs).valid is True


def test_double_submit_same_proof_is_replay():
    """First submission consumes the jti at the commit point; the
    identical second submission is REPLAY_DETECTED."""
    key = generate_key()
    store = MemoryJtiStore()
    proof = generate_proof(private_key=key, htm=HTM, htu=HTU, iat=NOW)
    kwargs = {"htm": HTM, "htu": HTU, "now": NOW, "jti_store": store}
    assert verify_proof_result(proof=proof, **kwargs).valid is True
    second = verify_proof_result(proof=proof, **kwargs)
    assert second.reason is VerificationFailure.REPLAY_DETECTED
    # ... and the raising API agrees
    with pytest.raises(DPoPError) as excinfo:
        verify_proof(proof=proof, **kwargs)
    assert excinfo.value.reason is VerificationFailure.REPLAY_DETECTED


def test_nonce_failure_does_not_consume_jti():
    """A proof that fails the nonce check does not burn its jti: a
    fresh proof with the SAME jti and the correct nonce is accepted.
    (Nonce expiry is an expected retry path under RFC 9449.)"""
    key = generate_key()
    store = MemoryJtiStore()
    wrong = generate_proof(
        private_key=key, htm=HTM, htu=HTU, iat=NOW,
        jti="retry-jti-1", nonce="stale-nonce",
    )
    result = verify_proof_result(
        proof=wrong, htm=HTM, htu=HTU, now=NOW,
        expected_nonce="srv-nonce-1", jti_store=store,
    )
    assert result.reason is VerificationFailure.NONCE_MISMATCH
    fresh = generate_proof(
        private_key=key, htm=HTM, htu=HTU, iat=NOW,
        jti="retry-jti-1", nonce="srv-nonce-1",
    )
    assert verify_proof_result(
        proof=fresh, htm=HTM, htu=HTU, now=NOW,
        expected_nonce="srv-nonce-1", jti_store=store,
    ).valid is True


def test_expired_iat_does_not_consume_jti():
    """Same commit-point property for the iat window: a stale proof
    is rejected without consuming its jti."""
    key = generate_key()
    store = MemoryJtiStore()
    stale = generate_proof(
        private_key=key, htm=HTM, htu=HTU, iat=NOW - 3600, jti="stale-jti-1",
    )
    result = verify_proof_result(
        proof=stale, htm=HTM, htu=HTU, now=NOW, clock_skew=60,
        jti_store=store,
    )
    assert result.reason is VerificationFailure.EXPIRED_IAT
    # (The jti is free again — but the proof itself is still stale,
    # so re-submitting it must fail on iat, not on replay.)
    again = verify_proof_result(
        proof=stale, htm=HTM, htu=HTU, now=NOW, clock_skew=60,
        jti_store=store,
    )
    assert again.reason is VerificationFailure.EXPIRED_IAT


def test_check_and_record_called_once_and_last():
    """The store is consulted exactly once per verification, and only
    after every other check has passed: proofs failing signature,
    nonce or ath never reach it."""
    key = generate_key()
    store = _RecordingStore()

    def verify(proof, **kw):
        return verify_proof_result(
            proof=proof, htm=HTM, htu=HTU, now=NOW,
            replay_store=store, **kw,
        )

    # signature failure -> store never consulted
    proof = generate_proof(private_key=key, htm=HTM, htu=HTU, iat=NOW)
    tampered_sig = proof.rsplit(".", 1)[0] + ".AAAA"
    assert verify(tampered_sig).reason is VerificationFailure.BAD_SIGNATURE
    assert store.calls == []

    # nonce failure -> store never consulted
    wrong_nonce = generate_proof(
        private_key=key, htm=HTM, htu=HTU, iat=NOW, nonce="wrong",
    )
    assert verify(wrong_nonce, expected_nonce="srv-1").reason is (
        VerificationFailure.NONCE_MISMATCH
    )
    assert store.calls == []

    # ath failure -> store never consulted
    wrong_ath = generate_proof(
        private_key=key, htm=HTM, htu=HTU, iat=NOW, access_token="token-A",
    )
    assert verify(wrong_ath, access_token="token-B").reason is (
        VerificationFailure.ATH_MISMATCH
    )
    assert store.calls == []

    # valid proof -> exactly one call, with the proof's jti
    good = generate_proof(
        private_key=key, htm=HTM, htu=HTU, iat=NOW, jti="commit-jti-1",
    )
    assert verify(good).valid is True
    assert store.calls == [("commit-jti-1", NOW)]

    # replay -> exactly one more call, returning False
    assert verify(good).reason is VerificationFailure.REPLAY_DETECTED
    assert store.calls == [("commit-jti-1", NOW), ("commit-jti-1", NOW)]
