"""PQ/T hybrid DPoP tests (v0.2): ML-DSA-44-ES256 and ML-DSA-65-ES256."""
import base64

import pytest

from pydpop import (
    COMPOSITE_ALGS,
    CompositeKey,
    DPoPError,
    generate_key,
    generate_proof,
    jwk_thumbprint,
    private_jwk,
    public_jwk,
    select_alg,
    verify_proof,
)

HTM = "POST"
HTU = "https://server.example.com/token"


def _b64u_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


@pytest.mark.parametrize("alg", COMPOSITE_ALGS)
def test_hybrid_roundtrip(alg):
    key = generate_key(alg=alg)
    assert isinstance(key, CompositeKey)
    assert key.variant == alg
    proof = generate_proof(private_key=key, htm=HTM, htu=HTU)
    result = verify_proof(proof=proof, htm=HTM, htu=HTU)
    assert result["claims"]["htm"] == "POST"
    assert result["jwk"]["kty"] == "AKP"
    assert result["jwk"]["alg"] == alg
    assert result["jwk_thumbprint"] == jwk_thumbprint(public_jwk(key))
    assert "priv" not in result["jwk"]


@pytest.mark.parametrize("alg", COMPOSITE_ALGS)
def test_hybrid_proof_fits_common_header_cap(alg):
    key = generate_key(alg=alg)
    proof = generate_proof(private_key=key, htm=HTM, htu=HTU)
    if alg == "ML-DSA-44-ES256":
        assert len(proof) < 8192, "44-variant must fit the 8KB header cap"


def test_hybrid_tampered_signature_rejected():
    key = generate_key(alg="ML-DSA-44-ES256")
    proof = generate_proof(private_key=key, htm=HTM, htu=HTU)
    h, p, s = proof.split(".")
    raw = bytearray(_b64u_decode(s))
    raw[100] ^= 0xFF  # inside the ML-DSA half
    bad = h + "." + p + "." + base64.urlsafe_b64encode(bytes(raw)).rstrip(b"=").decode()
    with pytest.raises(DPoPError):
        verify_proof(proof=bad, htm=HTM, htu=HTU)


def test_hybrid_broken_ecdsa_half_rejected():
    key = generate_key(alg="ML-DSA-44-ES256")
    proof = generate_proof(private_key=key, htm=HTM, htu=HTU)
    h, p, s = proof.split(".")
    raw = bytearray(_b64u_decode(s))
    raw[-1] ^= 0xFF  # inside the ECDSA half
    bad = h + "." + p + "." + base64.urlsafe_b64encode(bytes(raw)).rstrip(b"=").decode()
    with pytest.raises(DPoPError):
        verify_proof(proof=bad, htm=HTM, htu=HTU)


def test_hybrid_wrong_variant_rejected():
    """A 44-proof must not verify when the header claims 65 (and vice versa)."""
    key44 = generate_key(alg="ML-DSA-44-ES256")
    proof = generate_proof(private_key=key44, htm=HTM, htu=HTU)
    import json

    h, p, s = proof.split(".")
    header = json.loads(_b64u_decode(h))
    header["alg"] = "ML-DSA-65-ES256"
    header["jwk"] = public_jwk(generate_key(alg="ML-DSA-65-ES256"))
    h2 = base64.urlsafe_b64encode(json.dumps(header, separators=(",", ":")).encode()).rstrip(b"=").decode()
    with pytest.raises(DPoPError):
        verify_proof(proof=f"{h2}.{p}.{s}", htm=HTM, htu=HTU)


def test_hybrid_claims_still_checked():
    key = generate_key(alg="ML-DSA-44-ES256")
    proof = generate_proof(private_key=key, htm=HTM, htu=HTU, access_token="tok123")
    with pytest.raises(DPoPError):
        verify_proof(proof=proof, htm="GET", htu=HTU)
    with pytest.raises(DPoPError):
        verify_proof(proof=proof, htm=HTM, htu=HTU, access_token="wrong")


def test_hybrid_private_jwk_roundtrip():
    key = generate_key(alg="ML-DSA-44-ES256")
    priv = private_jwk(key)
    assert priv["kty"] == "AKP" and "priv" in priv
    # same key material signs verifiably
    proof = generate_proof(private_key=key, htm=HTM, htu=HTU)
    verify_proof(proof=proof, htm=HTM, htu=HTU)


def test_select_alg_prefers_pqc():
    assert select_alg({"dpop_signing_alg_values_supported": ["ES256", "ML-DSA-44-ES256"]}) == "ML-DSA-44-ES256"
    assert select_alg({"dpop_signing_alg_values_supported": ["ES256"]}) == "ES256"
    assert select_alg({}) == "ES256"
    assert select_alg({"dpop_signing_alg_values_supported": ["ES256"]}, prefer_pqc=False) == "ES256"
    with pytest.raises(DPoPError):
        select_alg({"dpop_signing_alg_values_supported": ["ES256"]}, require_pqc=True)


def test_es256_still_default():
    key = generate_key()
    proof = generate_proof(private_key=key, htm=HTM, htu=HTU)
    import json

    header = json.loads(_b64u_decode(proof.split(".")[0]))
    assert header["alg"] == "ES256"
    verify_proof(proof=proof, htm=HTM, htu=HTU)
