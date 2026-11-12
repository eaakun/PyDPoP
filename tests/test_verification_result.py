"""Structured verification results for pydpop (trust-primitive memo §2).

One test per :class:`VerificationFailure` reason, plus an agreement
test proving :func:`verify_proof` and :func:`verify_proof_result`
make identical accept/reject decisions with identical reasons, and
tests for the :class:`ReplayStore` protocol.
"""
from __future__ import annotations

import base64
import dataclasses
import json

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from pydpop import (
    DPoPError,
    DPoPVerificationResult,
    MemoryJtiStore,
    MemoryReplayStore,
    ReplayStore,
    VerificationFailure,
    generate_key,
    generate_proof,
    mldsa_available,
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


def _proof_parts(key, **kwargs):
    proof = generate_proof(private_key=key, htm=HTM, htu=HTU, **kwargs)
    head, payload, sig = proof.split(".")
    return proof, _decode_segment(head), _decode_segment(payload), sig


def _check(proof, expect: VerificationFailure | None, **kwargs):
    """Assert verify_proof_result and verify_proof agree on one case."""
    result = verify_proof_result(proof=proof, htm=HTM, htu=HTU, **kwargs)
    if expect is None:
        assert result.valid is True
        assert result.reason is None
        assert result.jwk is not None and result.claims is not None
        assert result.jwk_thumbprint
        bound = verify_proof(proof=proof, htm=HTM, htu=HTU, **kwargs)
        assert bound["jwk"] == result.jwk
        assert bound["jwk_thumbprint"] == result.jwk_thumbprint
        assert bound["claims"] == result.claims
    else:
        assert result.valid is False
        assert result.reason is expect
        assert result.detail
        with pytest.raises(DPoPError) as excinfo:
            verify_proof(proof=proof, htm=HTM, htu=HTU, **kwargs)
        assert excinfo.value.reason is expect
        assert str(excinfo.value) == result.detail


# --- one test per failure reason ------------------------------------------

def test_reason_malformed_proof():
    for bad in ["", "abc", "a.b", "a.b.c.d", "..."]:
        _check(bad, VerificationFailure.MALFORMED_PROOF)
    # header/claims that decode but are not JSON objects
    bad = f"{b64u_encode(b'42')}.{b64u_encode(b'[]')}.{b64u_encode(bytes(64))}"
    _check(bad, VerificationFailure.MALFORMED_PROOF)


def test_reason_bad_typ():
    key = generate_key()
    _proof, header, payload, _ = _proof_parts(key)
    header["typ"] = "jwt"
    _check(_resign(key, header, payload), VerificationFailure.BAD_TYP)


def test_reason_unsupported_alg():
    key = generate_key()
    _proof, header, payload, _ = _proof_parts(key)
    header["alg"] = "RS256"
    _check(_resign(key, header, payload), VerificationFailure.UNSUPPORTED_ALG)


def test_reason_invalid_jwk_missing():
    key = generate_key()
    _proof, header, payload, _ = _proof_parts(key)
    del header["jwk"]
    _check(_resign(key, header, payload), VerificationFailure.INVALID_JWK)


def test_reason_invalid_jwk_missing_coordinates():
    # Fuzzer find (2026-10-11): embedded JWK without x/y used to crash
    # with KeyError; now a clean INVALID_JWK, never a crash.
    key = generate_key()
    proof = generate_proof(private_key=key, htm=HTM, htu=HTU)
    head_b64, payload_b64, sig_b64 = proof.split(".")
    header = json.loads(base64.urlsafe_b64decode(head_b64 + "=="))
    header["jwk"] = {"kty": "EC", "crv": "P-256"}
    head2 = b64u_encode(json.dumps(header).encode())
    _check(f"{head2}.{payload_b64}.{sig_b64}", VerificationFailure.INVALID_JWK)


@pytest.mark.skipif(not mldsa_available(), reason="ML-DSA unavailable")
def test_reason_invalid_jwk_composite_alg_mismatch():
    # Header checks run before signature verification, so no re-sign
    # is needed: the JWK-alg mismatch fires first.
    key = generate_key(alg="ML-DSA-44-ES256")
    proof = generate_proof(private_key=key, htm=HTM, htu=HTU)
    head_b64, payload_b64, sig_b64 = proof.split(".")
    header = _decode_segment(head_b64)
    header["jwk"]["alg"] = "ML-DSA-65-ES256"
    head2 = _b64u_json(header)
    _check(f"{head2}.{payload_b64}.{sig_b64}", VerificationFailure.INVALID_JWK)


def test_reason_bad_signature_tampered():
    key = generate_key()
    proof, _, _, sig = _proof_parts(key)
    head, payload, _ = proof.split(".")
    i = len(sig) // 2
    flipped = sig[:i] + ("A" if sig[i] != "A" else "B") + sig[i + 1:]
    assert flipped != sig
    _check(f"{head}.{payload}.{flipped}", VerificationFailure.BAD_SIGNATURE)


def test_reason_bad_signature_short():
    key = generate_key()
    proof, _, _, _ = _proof_parts(key)
    head, payload, _ = proof.split(".")
    _check(f"{head}.{payload}.AAAA", VerificationFailure.BAD_SIGNATURE)


def test_reason_htm_mismatch():
    key = generate_key()
    proof = generate_proof(private_key=key, htm=HTM, htu=HTU)
    result = verify_proof_result(proof=proof, htm="GET", htu=HTU)
    assert result.reason is VerificationFailure.HTM_MISMATCH
    with pytest.raises(DPoPError) as excinfo:
        verify_proof(proof=proof, htm="GET", htu=HTU)
    assert excinfo.value.reason is VerificationFailure.HTM_MISMATCH


def test_reason_htu_mismatch():
    key = generate_key()
    proof = generate_proof(private_key=key, htm=HTM, htu=HTU)
    result = verify_proof_result(
        proof=proof, htm=HTM, htu="https://server.example.com/other"
    )
    assert result.reason is VerificationFailure.HTU_MISMATCH
    with pytest.raises(DPoPError) as excinfo:
        verify_proof(proof=proof, htm=HTM, htu="https://server.example.com/other")
    assert excinfo.value.reason is VerificationFailure.HTU_MISMATCH


def test_reason_expired_iat():
    key = generate_key()
    stale = generate_proof(private_key=key, htm=HTM, htu=HTU, iat=NOW - 3600)
    _check(stale, VerificationFailure.EXPIRED_IAT, clock_skew=60, now=NOW)
    # non-integer iat is the same failure family
    _proof, header, payload, _ = _proof_parts(key)
    payload["iat"] = "not-a-timestamp"
    _check(
        _resign(key, header, payload),
        VerificationFailure.EXPIRED_IAT,
        clock_skew=60,
        now=NOW,
    )


def test_reason_missing_jti():
    key = generate_key()
    _proof, header, payload, _ = _proof_parts(key)
    del payload["jti"]
    _check(_resign(key, header, payload), VerificationFailure.MISSING_JTI)


def test_reason_replay_detected():
    key = generate_key()
    proof = generate_proof(private_key=key, htm=HTM, htu=HTU)
    store = MemoryJtiStore()
    first = verify_proof_result(proof=proof, htm=HTM, htu=HTU, jti_store=store)
    assert first.valid is True
    _check(proof, VerificationFailure.REPLAY_DETECTED, jti_store=store)


def test_reason_nonce_mismatch():
    key = generate_key()
    proof = generate_proof(private_key=key, htm=HTM, htu=HTU)  # no nonce claim
    _check(
        proof, VerificationFailure.NONCE_MISMATCH, expected_nonce="srv-nonce-1"
    )
    wrong = generate_proof(private_key=key, htm=HTM, htu=HTU, nonce="other")
    _check(
        wrong, VerificationFailure.NONCE_MISMATCH, expected_nonce="srv-nonce-1"
    )


def test_reason_ath_mismatch():
    key = generate_key()
    proof = generate_proof(
        private_key=key, htm=HTM, htu=HTU, access_token="token-A"
    )
    _check(proof, VerificationFailure.ATH_MISMATCH, access_token="token-B")


# --- agreement across the whole failure battery ---------------------------

def _case_builders():
    """Each builder returns a fresh (proof, kwargs) in a fixed state,
    so the two APIs can be run against identical inputs."""
    key = generate_key()

    def valid():
        return generate_proof(private_key=key, htm=HTM, htu=HTU), {}

    def valid_bound():
        proof = generate_proof(
            private_key=key, htm=HTM, htu=HTU,
            access_token="tok", nonce="n1",
        )
        return proof, {"access_token": "tok", "expected_nonce": "n1"}

    def malformed():
        return "a.b", {}

    def bad_typ():
        _, header, payload, _ = _proof_parts(key)
        header["typ"] = "dpop"
        return _resign(key, header, payload), {}

    def unsupported_alg():
        _, header, payload, _ = _proof_parts(key)
        header["alg"] = "none"
        return _resign(key, header, payload), {}

    def invalid_jwk():
        _, header, payload, _ = _proof_parts(key)
        del header["jwk"]
        return _resign(key, header, payload), {}

    def bad_sig():
        proof, _, _, sig = _proof_parts(key)
        head, payload, _ = proof.split(".")
        i = len(sig) // 2
        flipped = sig[:i] + ("A" if sig[i] != "A" else "B") + sig[i + 1:]
        return f"{head}.{payload}.{flipped}", {}

    def htm():
        return generate_proof(private_key=key, htm=HTM, htu=HTU), {"htm": "GET"}

    def htu():
        return generate_proof(private_key=key, htm=HTM, htu=HTU), {
            "htu": "https://server.example.com/other"
        }

    def iat():
        proof = generate_proof(
            private_key=key, htm=HTM, htu=HTU, iat=NOW - 3600
        )
        return proof, {"clock_skew": 60, "now": NOW}

    def no_jti():
        _, header, payload, _ = _proof_parts(key)
        del payload["jti"]
        return _resign(key, header, payload), {}

    def replay():
        proof = generate_proof(private_key=key, htm=HTM, htu=HTU)
        store = MemoryJtiStore()
        verify_proof(proof=proof, htm=HTM, htu=HTU, jti_store=store)
        return proof, {"jti_store": store}

    def nonce():
        return generate_proof(private_key=key, htm=HTM, htu=HTU), {
            "expected_nonce": "srv-nonce-1"
        }

    def ath():
        proof = generate_proof(
            private_key=key, htm=HTM, htu=HTU, access_token="token-A"
        )
        return proof, {"access_token": "token-B"}

    return {
        "valid": (valid, None),
        "valid_bound": (valid_bound, None),
        "malformed": (malformed, VerificationFailure.MALFORMED_PROOF),
        "bad_typ": (bad_typ, VerificationFailure.BAD_TYP),
        "unsupported_alg": (unsupported_alg, VerificationFailure.UNSUPPORTED_ALG),
        "invalid_jwk": (invalid_jwk, VerificationFailure.INVALID_JWK),
        "bad_sig": (bad_sig, VerificationFailure.BAD_SIGNATURE),
        "htm": (htm, VerificationFailure.HTM_MISMATCH),
        "htu": (htu, VerificationFailure.HTU_MISMATCH),
        "iat": (iat, VerificationFailure.EXPIRED_IAT),
        "no_jti": (no_jti, VerificationFailure.MISSING_JTI),
        "replay": (replay, VerificationFailure.REPLAY_DETECTED),
        "nonce": (nonce, VerificationFailure.NONCE_MISMATCH),
        "ath": (ath, VerificationFailure.ATH_MISMATCH),
    }


def test_verify_proof_and_result_agree_on_every_case():
    for name, (build, expect) in _case_builders().items():
        proof, kwargs = build()
        htm = kwargs.pop("htm", HTM)
        htu = kwargs.pop("htu", HTU)
        result = verify_proof_result(proof=proof, htm=htm, htu=htu, **kwargs)
        assert result.reason is expect, name
        assert result.valid is (expect is None), name
        if expect is None:
            bound = verify_proof(proof=proof, htm=htm, htu=htu, **kwargs)
            assert bound["claims"] == result.claims, name
        else:
            with pytest.raises(DPoPError) as excinfo:
                verify_proof(proof=proof, htm=htm, htu=htu, **kwargs)
            assert excinfo.value.reason is expect, name
            assert str(excinfo.value) == result.detail, name


# --- result object shape ---------------------------------------------------

def test_result_is_frozen_and_complete():
    key = generate_key()
    proof = generate_proof(
        private_key=key, htm=HTM, htu=HTU, access_token="tok", nonce="n1"
    )
    result = verify_proof_result(
        proof=proof, htm=HTM, htu=HTU, access_token="tok", expected_nonce="n1"
    )
    assert result.valid is True
    assert result.reason is None
    assert result.detail is None
    assert result.claims["htm"] == HTM
    with pytest.raises(dataclasses.FrozenInstanceError):
        result.valid = False  # type: ignore[misc]
    # the same failure object carries the same text both APIs surface
    bad = verify_proof_result(proof="a.b", htm=HTM, htu=HTU)
    assert bad.valid is False
    assert bad.jwk is None and bad.claims is None
    assert isinstance(bad, DPoPVerificationResult)


def test_dpop_error_without_reason_defaults_to_none():
    assert DPoPError("plain old error").reason is None


# --- ReplayStore protocol ---------------------------------------------------

def test_memory_store_implements_check_and_record():
    store = MemoryJtiStore(ttl=600)
    assert store.check_and_record("jti-1", NOW) is True
    assert store.check_and_record("jti-1", NOW) is False
    assert store.check_and_record("jti-2", NOW) is True
    # legacy seen()/add() still work on the same entries
    assert store.seen("jti-1") is True
    assert store.seen("jti-3") is False
    store.add("jti-3")
    assert store.check_and_record("jti-3", NOW) is False
    assert MemoryReplayStore is MemoryJtiStore


class _DictStore:
    """A third-party store implementing only the ReplayStore protocol."""

    def __init__(self):
        self._seen: set[str] = set()

    def check_and_record(self, jti: str, iat: int) -> bool:
        if jti in self._seen:
            return False
        self._seen.add(jti)
        return True


def test_custom_replay_store_via_replay_store_param():
    key = generate_key()
    proof = generate_proof(private_key=key, htm=HTM, htu=HTU)
    store = _DictStore()
    assert verify_proof_result(
        proof=proof, htm=HTM, htu=HTU, replay_store=store
    ).valid is True
    result = verify_proof_result(
        proof=proof, htm=HTM, htu=HTU, replay_store=store
    )
    assert result.reason is VerificationFailure.REPLAY_DETECTED


def test_replay_store_param_accepted_by_verify_proof():
    key = generate_key()
    proof = generate_proof(private_key=key, htm=HTM, htu=HTU)
    store = _DictStore()
    verify_proof(proof=proof, htm=HTM, htu=HTU, replay_store=store)
    with pytest.raises(DPoPError, match="replayed"):
        verify_proof(proof=proof, htm=HTM, htu=HTU, replay_store=store)


def test_replay_store_takes_precedence_over_jti_store():
    key = generate_key()
    proof = generate_proof(private_key=key, htm=HTM, htu=HTU)
    fresh = MemoryJtiStore()  # would accept
    seeded = _DictStore()  # already holds this jti
    seeded.check_and_record("seed", NOW)
    verify_proof(proof=proof, htm=HTM, htu=HTU, replay_store=seeded)
    result = verify_proof_result(
        proof=proof, htm=HTM, htu=HTU, jti_store=fresh, replay_store=seeded
    )
    assert result.reason is VerificationFailure.REPLAY_DETECTED


def test_check_and_record_ttl_expiry(monkeypatch):
    import pydpop.verifier as verifier_mod

    store = MemoryJtiStore(ttl=100)
    monkeypatch.setattr(verifier_mod.time, "time", lambda: float(NOW))
    assert store.check_and_record("jti-1", NOW) is True
    assert store.check_and_record("jti-1", NOW) is False
    monkeypatch.setattr(verifier_mod.time, "time", lambda: float(NOW + 200))
    assert store.check_and_record("jti-1", NOW + 200) is True


def test_protocol_is_structural():
    # Any object with check_and_record(jti, iat) -> bool satisfies
    # ReplayStore; no inheritance from pydpop is required.
    assert isinstance(_DictStore(), ReplayStore) is True
    assert isinstance(MemoryJtiStore(), ReplayStore) is True
    assert isinstance(object(), ReplayStore) is False
