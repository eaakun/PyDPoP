"""Executable security invariants (protocol-infra memo §2).

These are the properties an auditor can re-run with one command::

    python -m pytest tests/test_invariants.py -v

Each invariant is checked against :func:`verify_proof_result` with a
recording :class:`ReplayStore`, so the harness tests the library as
shipped, not a model of it.

1. No proof returns valid=True while its jti was not recorded.
2. With a server-issued nonce required, any valid=True result
   implies a nonce the server issued inside its window.
3. ath failure and signature failure are distinguishable in the
   result object, and an ath failure does not consume the jti.
"""
from __future__ import annotations

import base64
import json

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from pydpop import (
    MemoryJtiStore,
    VerificationFailure,
    generate_key,
    generate_proof,
    verify_proof_result,
)
from pydpop.jwk import b64u_encode

HTM = "POST"
HTU = "https://server.example.com/token"
NOW = 1_700_000_000
NONCE_WINDOW = 300


def _b64u_json(obj: dict) -> str:
    return b64u_encode(json.dumps(obj, separators=(",", ":")).encode("utf-8"))


def _decode_segment(seg: str) -> dict:
    return json.loads(base64.urlsafe_b64decode(seg + "=="))


def _resign(key, header: dict, payload: dict) -> str:
    signing_input = f"{_b64u_json(header)}.{_b64u_json(payload)}".encode("ascii")
    der_sig = key.sign(signing_input, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der_sig)
    raw_sig = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    return f"{signing_input.decode('ascii')}.{b64u_encode(raw_sig)}"


class _RecordingStore:
    """A ReplayStore that remembers exactly which jtis it recorded."""

    def __init__(self):
        self.recorded: set[str] = set()
        self.calls = 0

    def check_and_record(self, jti: str, iat: int) -> bool:
        self.calls += 1
        if jti in self.recorded:
            return False
        self.recorded.add(jti)
        return True


class _NonceServer:
    """Minimal model of a server-issued nonce: the server issues a
    nonce with an issuance time and keeps a ledger; only ledger
    entries inside the window are expected back."""

    def __init__(self, window: int = NONCE_WINDOW):
        self.window = window
        self.issued: dict[str, int] = {}
        self._counter = 0

    def issue(self, now: int) -> str:
        self._counter += 1
        nonce = f"srv-nonce-{self._counter}"
        self.issued[nonce] = now
        return nonce

    def expected(self, nonce: str, now: int) -> str | None:
        issued_at = self.issued.get(nonce)
        if issued_at is None or abs(now - issued_at) > self.window:
            return None
        return nonce


def test_invariant_valid_implies_jti_recorded():
    """Invariant 1: there is no proof with valid=True whose jti the
    store did not record. Checked over a battery of valid proofs
    (plain, ath-bound, nonce-bound) and over proofs that fail after
    the commit point would be impossible — the commit point is last,
    so a valid result always passed through check_and_record."""
    key = generate_key()
    store = _RecordingStore()
    cases = [
        generate_proof(private_key=key, htm=HTM, htu=HTU, iat=NOW,
                       jti="inv-1"),
        generate_proof(private_key=key, htm=HTM, htu=HTU, iat=NOW,
                       jti="inv-2", access_token="tok"),
        generate_proof(private_key=key, htm=HTM, htu=HTU, iat=NOW,
                       jti="inv-3", nonce="n1", access_token="tok"),
    ]
    kwargs = [
        {},
        {"access_token": "tok"},
        {"access_token": "tok", "expected_nonce": "n1"},
    ]
    for proof, kw in zip(cases, kwargs):
        result = verify_proof_result(
            proof=proof, htm=HTM, htu=HTU, now=NOW,
            replay_store=store, **kw,
        )
        assert result.valid is True
        jti = result.claims["jti"]
        assert jti in store.recorded, f"valid proof {jti} not recorded"
    assert store.calls == 3  # exactly one commit per verification

    # Negative control: a proof that fails before the commit point is
    # invalid AND unrecorded — recording is tied to acceptance.
    bad = generate_proof(
        private_key=key, htm=HTM, htu=HTU, iat=NOW, jti="inv-4",
        access_token="tok",
    )
    result = verify_proof_result(
        proof=bad, htm=HTM, htu=HTU, now=NOW,
        access_token="other", replay_store=store,
    )
    assert result.valid is False
    assert "inv-4" not in store.recorded
    assert store.calls == 3  # no commit attempt for a failed proof


def test_invariant_valid_implies_server_issued_nonce():
    """Invariant 2: with a server-issued nonce required, any
    valid=True result implies a nonce the server issued inside its
    window. A proof carrying an unissued or expired nonce is
    rejected, and the server never accepts a nonce it did not issue."""
    key = generate_key()
    server = _NonceServer()
    store = MemoryJtiStore()
    issued = server.issue(NOW)

    good = generate_proof(
        private_key=key, htm=HTM, htu=HTU, iat=NOW, nonce=issued,
    )
    result = verify_proof_result(
        proof=good, htm=HTM, htu=HTU, now=NOW,
        expected_nonce=server.expected(issued, NOW), jti_store=store,
    )
    assert result.valid is True
    assert result.claims["nonce"] == issued
    assert issued in server.issued  # the accepted nonce was issued

    # Unissued nonce: the server has no ledger entry for it.
    forged = generate_proof(
        private_key=key, htm=HTM, htu=HTU, iat=NOW, nonce="attacker-nonce",
    )
    result = verify_proof_result(
        proof=forged, htm=HTM, htu=HTU, now=NOW,
        expected_nonce=server.expected("attacker-nonce", NOW)
        or "no-such-nonce",
        jti_store=store,
    )
    assert result.reason is VerificationFailure.NONCE_MISMATCH

    # Expired nonce: issued, but outside the window when presented.
    old = server.issue(NOW - NONCE_WINDOW - 60)
    stale = generate_proof(
        private_key=key, htm=HTM, htu=HTU, iat=NOW, nonce=old,
    )
    result = verify_proof_result(
        proof=stale, htm=HTM, htu=HTU, now=NOW,
        expected_nonce=server.expected(old, NOW) or "expired-nonce",
        jti_store=store,
    )
    assert result.reason is VerificationFailure.NONCE_MISMATCH


def test_invariant_ath_and_signature_distinguishable_and_ath_free():
    """Invariant 3: ath failure and signature failure are
    distinguishable in the result object, and an ath failure does
    not consume the jti."""
    key = generate_key()
    store = MemoryJtiStore()
    original = generate_proof(
        private_key=key, htm=HTM, htu=HTU, iat=NOW,
        jti="inv-ath-1", access_token="token-A",
    )
    kwargs = {"htm": HTM, "htu": HTU, "access_token": "token-A",
              "now": NOW, "jti_store": store}

    # Bad signature (tampered payload, not re-signed).
    head_b64, payload_b64, sig = original.split(".")
    payload = _decode_segment(payload_b64)
    payload["ath"] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    tampered = f"{head_b64}.{_b64u_json(payload)}.{sig}"
    bad_sig = verify_proof_result(proof=tampered, **kwargs)
    assert bad_sig.reason is VerificationFailure.BAD_SIGNATURE

    # Valid signature, wrong ath (re-signed with the real key).
    header = _decode_segment(head_b64)
    resigned = _resign(key, header, payload)
    bad_ath = verify_proof_result(proof=resigned, **kwargs)
    assert bad_ath.reason is VerificationFailure.ATH_MISMATCH
    assert bad_sig.reason is not bad_ath.reason  # distinguishable

    # Neither failure consumed the jti: the original proof verifies.
    assert verify_proof_result(proof=original, **kwargs).valid is True
