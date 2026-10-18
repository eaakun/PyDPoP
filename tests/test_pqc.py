"""PQ/T hybrid DPoP tests (v0.2): ML-DSA-44-ES256 and ML-DSA-65-ES256.

Component encodings follow draft-ietf-jose-pq-composite-sigs-05 §4.2:
DER Ecdsa-Sig-Value, X9.62 uncompressed public key, RFC 5915 DER ECPrivateKey.
"""
import base64
import json
import os

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
from pydpop.composite import composite_verify

HTM = "POST"
HTU = "https://server.example.com/token"
FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


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


@pytest.mark.parametrize("alg", COMPOSITE_ALGS)
def test_hybrid_pubkey_is_uncompressed_x962(alg):
    """-05 §4.2: EC component public key is 0x04 || x || y (65 bytes)."""
    key = generate_key(alg=alg)
    pub = _b64u_decode(public_jwk(key)["pub"])
    ml_pk_len = 1312 if "ML-DSA-44" in alg else 1952
    ec_part = pub[ml_pk_len:]
    assert len(ec_part) == 65 and ec_part[0] == 0x04


@pytest.mark.parametrize("alg", COMPOSITE_ALGS)
def test_hybrid_privkey_is_der_ecprivatekey(alg):
    """-05 §4.2: priv = ML-DSA seed (32 B) || RFC 5915 DER ECPrivateKey (51 B)."""
    key = generate_key(alg=alg)
    raw = _b64u_decode(private_jwk(key)["priv"])
    assert len(raw) == 32 + 51
    der = raw[32:]
    assert der[:5] == b"\x30\x31\x02\x01\x01"
    assert der[5:7] == b"\x04\x20"  # OCTET STRING, 32 bytes: the scalar
    assert der[39:] == bytes.fromhex("a00a06082a8648ce3d030107")  # [0] P-256 OID


@pytest.mark.parametrize("alg", COMPOSITE_ALGS)
def test_hybrid_signature_is_ml_dsa_plus_der(alg):
    """-05 §4.2: signature is ML-DSA sig || DER Ecdsa-Sig-Value."""
    key = generate_key(alg=alg)
    proof = generate_proof(private_key=key, htm=HTM, htu=HTU)
    raw = _b64u_decode(proof.split(".")[2])
    ml_sig_len = 2420 if "ML-DSA-44" in alg else 3309
    der = raw[ml_sig_len:]
    assert 70 <= len(der) <= 72
    assert der[0] == 0x30 and der[1] == len(der) - 2  # DER SEQUENCE
    verify_proof(proof=proof, htm=HTM, htu=HTU)


def test_draft05_official_vector_verifies():
    """IETF draft example vector passes our verify (-05 encodings).

    examples/jose/examples/ML-DSA-44-ES256.jose.json: mldsa_seed = 32×0x00,
    ecdsa_d = 1 (hex fields; jwk pub/priv are base64url per RFC 9964).
    """
    with open(os.path.join(FIXTURES, "draft05-ml-dsa-44-es256.jose.json")) as f:
        vec = json.load(f)
    assert vec["mldsa_seed"] == "00" * 32
    assert vec["ecdsa_d"] == "00" * 31 + "01"
    pub_raw = bytes.fromhex(vec["raw_composite_public_key"])
    signature = bytes.fromhex(vec["raw_composite_signature"])
    message = bytes.fromhex(vec["raw_to_be_signed"])
    assert pub_raw[1312] == 0x04  # -05 §4.2 uncompressed marker
    der = signature[2420:]
    assert 70 <= len(der) <= 72 and der[0] == 0x30  # DER Ecdsa-Sig-Value
    # must not raise
    composite_verify("ML-DSA-44-ES256", pub_raw, message, signature)


def test_draft05_official_pub_matches_ours():
    """Our key derivation reproduces the official composite public key."""
    from cryptography.hazmat.primitives.asymmetric import ec as _ec

    from pydpop.composite import composite_public_raw

    with open(os.path.join(FIXTURES, "draft05-ml-dsa-44-es256.jose.json")) as f:
        vec = json.load(f)
    pub_raw = bytes.fromhex(vec["raw_composite_public_key"])
    ec_key = _ec.derive_private_key(1, _ec.SECP256R1())
    assert composite_public_raw("ML-DSA-44-ES256", b"\x00" * 32, ec_key) == pub_raw


def test_noncanonical_der_rejected():
    """-05 §4.2: non-canonical DER Ecdsa-Sig-Value must not verify.

    cryptography's DER parser is strict (leading-zero padding is rejected at
    decode), and composite_verify additionally re-encodes and compares, so a
    non-canonical-but-valid (r, s) can never slip through.
    """
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

    from pydpop.composite import _cfg

    ml_sig_len = _cfg("ML-DSA-44-ES256")["ml_sig_len"]
    bad_proof = None
    for _ in range(64):  # need a signature whose r and s both have clear top bits
        key = generate_key(alg="ML-DSA-44-ES256")
        proof = generate_proof(private_key=key, htm=HTM, htu=HTU)
        h, p, s = proof.split(".")
        raw = bytearray(_b64u_decode(s))
        der = bytes(raw[ml_sig_len:])
        r, s_int = decode_dss_signature(der)
        r_b, s_b = r.to_bytes(32, "big"), s_int.to_bytes(32, "big")
        if r_b[0] >= 0x80 or s_b[0] >= 0x80:
            continue
        # Same (r, s), but non-canonical: unnecessary leading zeros.
        padded = b"\x30\x46\x02\x21\x00" + r_b + b"\x02\x21\x00" + s_b
        raw[ml_sig_len:] = padded
        bad_proof = h + "." + p + "." + base64.urlsafe_b64encode(bytes(raw)).rstrip(b"=").decode()
        break
    assert bad_proof is not None
    with pytest.raises(DPoPError):
        verify_proof(proof=bad_proof, htm=HTM, htu=HTU)


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
