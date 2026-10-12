"""Graceful degradation: pydpop must import and do ES256 on old cryptography.

ML-DSA needs cryptography>=48 with a working backend (47.0 added the
module but stock 47.x wheels raise UnsupportedAlgorithm on every op).
Simulate the old world by forcing the availability probe off.
"""
import pytest
from cryptography.hazmat.primitives.asymmetric import ec

import pydpop
from pydpop import composite


@pytest.fixture()
def no_mldsa(monkeypatch):
    monkeypatch.setattr(composite, "_MLDSA_IMPORT_OK", False)
    monkeypatch.setattr(composite, "_mldsa_works", False)
    yield


def test_import_never_fails_without_mldsa(no_mldsa):
    # importing the package and touching the composite module must not raise
    assert pydpop.COMPOSITE_ALGS == ("ML-DSA-44-ES256", "ML-DSA-65-ES256")
    assert composite.mldsa_available() is False


def test_es256_unaffected_without_mldsa(no_mldsa):
    key = pydpop.generate_key()
    proof = pydpop.generate_proof(private_key=key, htm="GET", htu="https://a.test/x")
    out = pydpop.verify_proof(proof=proof, htm="GET", htu="https://a.test/x")
    assert out["claims"]["htm"] == "GET"


def test_keygen_fails_fast_with_clear_error(no_mldsa):
    with pytest.raises(ValueError, match="cryptography>=48"):
        pydpop.generate_key(alg="ML-DSA-44-ES256")


def test_composite_sign_fails_with_clear_error(no_mldsa):
    key = pydpop.CompositeKey(
        "ML-DSA-44-ES256", b"\x00" * 32, ec.generate_private_key(ec.SECP256R1()))
    with pytest.raises(ValueError, match="cryptography>=48"):
        pydpop.generate_proof(private_key=key, htm="GET", htu="https://a.test/x")


def test_select_alg_skips_pqc_without_mldsa(no_mldsa):
    md = {"dpop_signing_alg_values_supported": ["ML-DSA-44-ES256", "ES256"]}
    assert pydpop.select_alg(md) == "ES256"


def test_verify_composite_proof_without_mldsa(monkeypatch):
    # real proof minted while ML-DSA worked, verified after it "broke"
    key = pydpop.generate_key(alg="ML-DSA-44-ES256")
    proof = pydpop.generate_proof(private_key=key, htm="GET", htu="https://a.test/x")
    monkeypatch.setattr(composite, "_MLDSA_IMPORT_OK", False)
    monkeypatch.setattr(composite, "_mldsa_works", False)
    with pytest.raises(pydpop.DPoPError, match="cryptography>=48"):
        pydpop.verify_proof(proof=proof, htm="GET", htu="https://a.test/x")


def test_mldsa_available_true_on_modern_cryptography():
    # this environment has cryptography>=48 with OpenSSL 3.5+
    assert composite.mldsa_available() is True
