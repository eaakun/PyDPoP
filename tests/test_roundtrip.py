"""Round-trip and negative tests for pydpop (RFC 9449)."""
import time

import pytest

from pydpop import (
    DPoPError,
    MemoryJtiStore,
    generate_key,
    generate_proof,
    jwk_thumbprint,
    public_jwk,
    verify_proof,
)

HTM = "POST"
HTU = "https://server.example.com/token?code=abc#frag"


def test_roundtrip_ok():
    key = generate_key()
    proof = generate_proof(private_key=key, htm=HTM, htu=HTU)
    result = verify_proof(proof=proof, htm=HTM, htu=HTU)
    assert result["claims"]["htm"] == "POST"
    # query/fragment must be stripped from htu
    assert result["claims"]["htu"] == "https://server.example.com/token"
    assert result["jwk_thumbprint"] == jwk_thumbprint(public_jwk(key))


def test_htu_with_query_still_verifies():
    key = generate_key()
    proof = generate_proof(private_key=key, htm="get", htu=HTU)
    result = verify_proof(proof=proof, htm="GET", htu="https://server.example.com/token")
    assert result["claims"]["htm"] == "GET"


def test_htm_mismatch_rejected():
    key = generate_key()
    proof = generate_proof(private_key=key, htm="POST", htu=HTU)
    with pytest.raises(DPoPError):
        verify_proof(proof=proof, htm="GET", htu=HTU)


def test_htu_mismatch_rejected():
    key = generate_key()
    proof = generate_proof(private_key=key, htm=HTM, htu=HTU)
    with pytest.raises(DPoPError):
        verify_proof(proof=proof, htm=HTM, htu="https://evil.example.com/token")


def test_tampered_payload_rejected():
    key = generate_key()
    proof = generate_proof(private_key=key, htm=HTM, htu=HTU)
    head, payload, sig = proof.split(".")
    import base64, json

    claims = json.loads(base64.urlsafe_b64decode(payload + "=="))
    claims["htm"] = "DELETE"
    forged = base64.urlsafe_b64encode(json.dumps(claims).encode()).rstrip(b"=").decode()
    with pytest.raises(DPoPError):
        verify_proof(proof=f"{head}.{forged}.{sig}", htm="DELETE", htu=HTU)


def test_stale_iat_rejected():
    key = generate_key()
    proof = generate_proof(private_key=key, htm=HTM, htu=HTU, iat=int(time.time()) - 3600)
    with pytest.raises(DPoPError, match="iat"):
        verify_proof(proof=proof, htm=HTM, htu=HTU, clock_skew=60)


def test_replay_rejected_with_jti_store():
    key = generate_key()
    store = MemoryJtiStore()
    proof = generate_proof(private_key=key, htm=HTM, htu=HTU)
    verify_proof(proof=proof, htm=HTM, htu=HTU, jti_store=store)
    with pytest.raises(DPoPError, match="replayed"):
        verify_proof(proof=proof, htm=HTM, htu=HTU, jti_store=store)


def test_ath_binding():
    key = generate_key()
    token = "access-token-123"
    proof = generate_proof(private_key=key, htm=HTM, htu=HTU, access_token=token)
    verify_proof(proof=proof, htm=HTM, htu=HTU, access_token=token)
    with pytest.raises(DPoPError, match="ath"):
        verify_proof(proof=proof, htm=HTM, htu=HTU, access_token="wrong-token")
    # proof without ath must fail when a token is presented
    bare = generate_proof(private_key=key, htm=HTM, htu=HTU)
    with pytest.raises(DPoPError, match="ath"):
        verify_proof(proof=bare, htm=HTM, htu=HTU, access_token=token)


def test_nonce_enforced_when_expected():
    key = generate_key()
    proof = generate_proof(private_key=key, htm=HTM, htu=HTU, nonce="srv-nonce-1")
    verify_proof(proof=proof, htm=HTM, htu=HTU, expected_nonce="srv-nonce-1")
    with pytest.raises(DPoPError, match="nonce"):
        verify_proof(proof=proof, htm=HTM, htu=HTU, expected_nonce="other")


def test_wrong_key_rejected():
    proof = generate_proof(private_key=generate_key(), htm=HTM, htu=HTU)
    # verifier only trusts the embedded JWK; a proof signed by key A but
    # carrying key B's JWK must fail signature verification
    head, payload, _ = proof.split(".")
    import base64, json

    evil_jwk = public_jwk(generate_key())
    header = json.loads(base64.urlsafe_b64decode(head + "=="))
    header["jwk"] = evil_jwk
    evil_head = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b"=").decode()
    with pytest.raises(DPoPError):
        verify_proof(proof=f"{evil_head}.{payload}.{'A' * 86}", htm=HTM, htu=HTU)
