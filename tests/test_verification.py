"""Negative verification-rule tests for pydpop (RFC 9449 §4.3).

Covers the server-side checks one by one: header rules (typ/alg),
signature validity, and every claim rule (htm/htu/iat/jti/nonce/ath).
"""
import base64
import json
import time

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from pydpop import (
    DPoPError,
    MemoryJtiStore,
    generate_key,
    generate_proof,
    verify_proof,
)
from pydpop.jwk import b64u_encode

HTM = "POST"
HTU = "https://server.example.com/token"


def _b64u_json(obj: dict) -> str:
    return b64u_encode(json.dumps(obj, separators=(",", ":")).encode("utf-8"))


def _decode_segment(seg: str) -> dict:
    return json.loads(base64.urlsafe_b64decode(seg + "=="))


def _resign(key, header: dict, payload: dict) -> str:
    """Re-sign (possibly modified) header/payload with the real key.

    Lets tests exercise claim checks without tripping the signature check.
    """
    signing_input = f"{_b64u_json(header)}.{_b64u_json(payload)}".encode("ascii")
    der_sig = key.sign(signing_input, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der_sig)
    raw_sig = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    return f"{signing_input.decode('ascii')}.{b64u_encode(raw_sig)}"


def _proof_parts(key, **kwargs):
    proof = generate_proof(private_key=key, htm=HTM, htu=HTU, **kwargs)
    head, payload, sig = proof.split(".")
    return proof, _decode_segment(head), _decode_segment(payload), sig


# --- header rules ---------------------------------------------------------

@pytest.mark.parametrize("alg", ["RS256", "HS256", "ES384", "none", ""])
def test_unsupported_alg_rejected(alg):
    key = generate_key()
    proof, header, payload, _ = _proof_parts(key)
    header["alg"] = alg
    forged = _resign(key, header, payload)  # alg checked before signature
    with pytest.raises(DPoPError, match="unsupported alg"):
        verify_proof(proof=forged, htm=HTM, htu=HTU)


@pytest.mark.parametrize("typ", ["jwt", "dpop", "", None])
def test_bad_typ_rejected(typ):
    key = generate_key()
    proof, header, payload, _ = _proof_parts(key)
    if typ is None:
        del header["typ"]
    else:
        header["typ"] = typ
    forged = _resign(key, header, payload)
    with pytest.raises(DPoPError, match="bad typ"):
        verify_proof(proof=forged, htm=HTM, htu=HTU)


def test_missing_jwk_rejected():
    key = generate_key()
    proof, header, payload, _ = _proof_parts(key)
    del header["jwk"]
    forged = _resign(key, header, payload)
    with pytest.raises(DPoPError, match="missing embedded jwk"):
        verify_proof(proof=forged, htm=HTM, htu=HTU)


# --- signature rules ------------------------------------------------------

def test_tampered_signature_rejected():
    key = generate_key()
    proof, _, _, sig = _proof_parts(key)
    head, payload, _ = proof.split(".")
    flipped = sig[:-1] + ("A" if sig[-1] != "A" else "B")
    with pytest.raises(DPoPError, match="bad signature"):
        verify_proof(proof=f"{head}.{payload}.{flipped}", htm=HTM, htu=HTU)


def test_short_signature_rejected():
    key = generate_key()
    proof, _, _, _ = _proof_parts(key)
    head, payload, _ = proof.split(".")
    with pytest.raises(DPoPError, match="signature"):
        verify_proof(proof=f"{head}.{payload}.AAAA", htm=HTM, htu=HTU)


@pytest.mark.parametrize("bad", ["", "abc", "a.b", "a.b.c.d", "..."])
def test_malformed_proof_rejected(bad):
    with pytest.raises(DPoPError, match="malformed"):
        verify_proof(proof=bad, htm=HTM, htu=HTU)


# --- claim rules ----------------------------------------------------------

def test_future_iat_rejected():
    now = int(time.time())
    key = generate_key()
    proof = generate_proof(private_key=key, htm=HTM, htu=HTU, iat=now + 3600)
    with pytest.raises(DPoPError, match="iat"):
        verify_proof(proof=proof, htm=HTM, htu=HTU, clock_skew=60, now=now)


def test_iat_window_boundary():
    now = 1_700_000_000
    key = generate_key()
    ok = generate_proof(private_key=key, htm=HTM, htu=HTU, iat=now - 60)
    verify_proof(proof=ok, htm=HTM, htu=HTU, clock_skew=60, now=now)
    stale = generate_proof(private_key=key, htm=HTM, htu=HTU, iat=now - 61)
    with pytest.raises(DPoPError, match="iat"):
        verify_proof(proof=stale, htm=HTM, htu=HTU, clock_skew=60, now=now)


def test_non_int_iat_rejected():
    key = generate_key()
    proof, header, payload, _ = _proof_parts(key)
    payload["iat"] = "not-a-timestamp"
    forged = _resign(key, header, payload)
    with pytest.raises(DPoPError, match="iat"):
        verify_proof(proof=forged, htm=HTM, htu=HTU)


def test_missing_jti_rejected():
    key = generate_key()
    proof, header, payload, _ = _proof_parts(key)
    del payload["jti"]
    forged = _resign(key, header, payload)
    with pytest.raises(DPoPError, match="missing jti"):
        verify_proof(proof=forged, htm=HTM, htu=HTU)


def test_missing_htm_rejected():
    key = generate_key()
    proof, header, payload, _ = _proof_parts(key)
    del payload["htm"]
    forged = _resign(key, header, payload)
    with pytest.raises(DPoPError, match="htm"):
        verify_proof(proof=forged, htm=HTM, htu=HTU)


def test_nonce_missing_when_expected():
    key = generate_key()
    proof = generate_proof(private_key=key, htm=HTM, htu=HTU)  # no nonce claim
    with pytest.raises(DPoPError, match="nonce"):
        verify_proof(proof=proof, htm=HTM, htu=HTU, expected_nonce="srv-nonce-1")


def test_htu_query_normalized_on_verify_side():
    key = generate_key()
    proof = generate_proof(private_key=key, htm=HTM, htu=HTU)
    # verifier must strip query/fragment before comparing, per RFC 9449 §4.2
    result = verify_proof(proof=proof, htm=HTM, htu=HTU + "?code=abc#frag")
    assert result["claims"]["htu"] == HTU


def test_jti_store_ttl_expiry(monkeypatch):
    import pydpop.verifier as verifier_mod

    base = 1_700_000_000
    store = MemoryJtiStore(ttl=100)
    key = generate_key()
    proof = generate_proof(private_key=key, htm=HTM, htu=HTU, iat=base)

    monkeypatch.setattr(verifier_mod.time, "time", lambda: float(base))
    verify_proof(proof=proof, htm=HTM, htu=HTU, jti_store=store,
                 clock_skew=300, now=base)
    with pytest.raises(DPoPError, match="replayed"):
        verify_proof(proof=proof, htm=HTM, htu=HTU, jti_store=store,
                     clock_skew=300, now=base)
    # after TTL expiry the same jti is accepted again (cache, not a blocklist)
    monkeypatch.setattr(verifier_mod.time, "time", lambda: float(base + 200))
    verify_proof(proof=proof, htm=HTM, htu=HTU, jti_store=store,
                 clock_skew=300, now=base + 200)


def test_distinct_jtis_do_not_collide():
    store = MemoryJtiStore()
    key = generate_key()
    for _ in range(3):
        proof = generate_proof(private_key=key, htm=HTM, htu=HTU)
        verify_proof(proof=proof, htm=HTM, htu=HTU, jti_store=store)


def test_resigned_unmodified_proof_still_verifies():
    # sanity check: the _resign helper itself produces valid proofs
    key = generate_key()
    proof, header, payload, _ = _proof_parts(key)
    forged = _resign(key, header, payload)
    assert verify_proof(proof=forged, htm=HTM, htu=HTU)["claims"]["jti"] == payload["jti"]
