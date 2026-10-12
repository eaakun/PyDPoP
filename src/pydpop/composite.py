"""PQ/T hybrid composite signatures for DPoP (v0.2).

Implements draft-ietf-jose-pq-composite-sigs (v03, WG document) for the two
ECDSA composite variants, on top of RFC 9964 (ML-DSA JOSE serialization):

    M'  = "CompositeAlgorithmSignatures2025" || Label || 0x00 || PH(M)
    sig = ML-DSA.Sign(M', ctx=Label) || ECDSA.Sign(M')

Keys are RFC 9964 AKP JWKs whose ``pub``/``priv`` carry the raw composite
byte strings (ML-DSA PK || EC x||y, ML-DSA seed || EC scalar). Fresh
composite keys only — the draft forbids reusing component keys.
"""
from __future__ import annotations

import hashlib
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

try:  # ML-DSA landed in cryptography 47.0; importable but unusable on
    # 47.x stock wheels (AWS-LC/BoringSSL-only) — see mldsa_available().
    from cryptography.hazmat.primitives.asymmetric.mldsa import (
        MLDSA44PrivateKey,
        MLDSA44PublicKey,
        MLDSA65PrivateKey,
        MLDSA65PublicKey,
    )
    _MLDSA_IMPORT_OK = True
except ImportError:
    _MLDSA_IMPORT_OK = False
    MLDSA44PrivateKey = MLDSA44PublicKey = None  # type: ignore[assignment]
    MLDSA65PrivateKey = MLDSA65PublicKey = None  # type: ignore[assignment]

import cryptography as _cryptography

_mldsa_works: bool | None = None


def mldsa_available() -> bool:
    """True only if ML-DSA actually works (importable *and* backed).

    cryptography 47.0 added the ``mldsa`` module but only wired it to
    AWS-LC/BoringSSL — the stock PyPI wheel (OpenSSL) raises
    ``UnsupportedAlgorithm`` on every operation until 48.0. Probe once
    and cache.
    """
    global _mldsa_works
    if _mldsa_works is None:
        if not _MLDSA_IMPORT_OK:
            _mldsa_works = False
        else:
            try:
                MLDSA44PrivateKey.generate()
                _mldsa_works = True
            except Exception:
                _mldsa_works = False
    return _mldsa_works


def _require_mldsa() -> None:
    if not mldsa_available():
        raise ValueError(
            "PQC hybrid DPoP (ML-DSA-*) needs cryptography>=48 with a working "
            f"ML-DSA backend; you have {_cryptography.__version__}. "
            "pip install -U cryptography, or use ES256."
        )
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)

PREFIX = b"CompositeAlgorithmSignatures2025"

#: Composite variants pydpop supports, in preference order.
COMPOSITE_ALGS = ("ML-DSA-44-ES256", "ML-DSA-65-ES256")

_VARIANTS: dict[str, dict[str, Any]] = {
    "ML-DSA-44-ES256": {
        "label": b"COMPSIG-MLDSA44-ECDSA-P256-SHA256",
        "prehash": hashlib.sha256,
        "ml_priv_cls": MLDSA44PrivateKey,
        "ml_pub_cls": MLDSA44PublicKey,
        "ml_sig_len": 2420,
        "ml_pk_len": 1312,
    },
    "ML-DSA-65-ES256": {
        "label": b"COMPSIG-MLDSA65-ECDSA-P256-SHA512",
        "prehash": hashlib.sha512,
        "ml_priv_cls": MLDSA65PrivateKey,
        "ml_pub_cls": MLDSA65PublicKey,
        "ml_sig_len": 3309,
        "ml_pk_len": 1952,
    },
}

_EC_SIG_LEN = 64  # raw r||s
_EC_PK_LEN = 64  # raw x||y
_SEED_LEN = 32


def _cfg(variant: str) -> dict[str, Any]:
    try:
        return _VARIANTS[variant]
    except KeyError:
        raise ValueError(f"unsupported composite alg: {variant!r}") from None


def message_repr(variant: str, message: bytes) -> bytes:
    """Draft §4 message representative: Prefix || Label || 0x00 || PH(M)."""
    cfg = _cfg(variant)
    return PREFIX + cfg["label"] + b"\x00" + cfg["prehash"](message).digest()


def composite_public_raw(variant: str, ml_seed: bytes, ec_key: ec.EllipticCurvePrivateKey) -> bytes:
    """Raw composite public key: ML-DSA PK || EC x || EC y."""
    _require_mldsa()
    cfg = _cfg(variant)
    ml_pk = cfg["ml_priv_cls"].from_seed_bytes(ml_seed).public_key().public_bytes_raw()
    nums = ec_key.public_key().public_numbers()
    return ml_pk + nums.x.to_bytes(32, "big") + nums.y.to_bytes(32, "big")


def composite_private_raw(ml_seed: bytes, ec_key: ec.EllipticCurvePrivateKey) -> bytes:
    """Raw composite private key: 32-byte ML-DSA seed || 32-byte EC scalar."""
    return ml_seed + ec_key.private_numbers().private_value.to_bytes(32, "big")


def composite_sign(variant: str, ml_seed: bytes, ec_key: ec.EllipticCurvePrivateKey, message: bytes) -> bytes:
    """Sign per the draft: both components over M', concatenated."""
    _require_mldsa()
    cfg = _cfg(variant)
    ml_sk = cfg["ml_priv_cls"].from_seed_bytes(ml_seed)
    mprime = message_repr(variant, message)
    ml_sig = ml_sk.sign(mprime, context=cfg["label"])
    der = ec_key.sign(mprime, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der)
    return ml_sig + r.to_bytes(32, "big") + s.to_bytes(32, "big")


def composite_verify(variant: str, pub_raw: bytes, message: bytes, signature: bytes) -> None:
    """Verify both components; raises on any failure."""
    _require_mldsa()
    cfg = _cfg(variant)
    if len(pub_raw) != cfg["ml_pk_len"] + _EC_PK_LEN:
        raise ValueError("bad composite public key length")
    if len(signature) != cfg["ml_sig_len"] + _EC_SIG_LEN:
        raise ValueError("bad composite signature length")
    ml_sig, es_sig = signature[: cfg["ml_sig_len"]], signature[cfg["ml_sig_len"] :]
    ml_pk = cfg["ml_pub_cls"].from_public_bytes(pub_raw[: cfg["ml_pk_len"]])
    ec_raw = pub_raw[cfg["ml_pk_len"] :]
    ec_pk = ec.EllipticCurvePublicNumbers(
        int.from_bytes(ec_raw[:32], "big"), int.from_bytes(ec_raw[32:], "big"), ec.SECP256R1()
    ).public_key()
    mprime = message_repr(variant, message)
    try:
        ml_pk.verify(ml_sig, mprime, context=cfg["label"])
    except InvalidSignature as exc:
        raise ValueError("ML-DSA component invalid") from exc
    r = int.from_bytes(es_sig[:32], "big")
    s = int.from_bytes(es_sig[32:], "big")
    try:
        ec_pk.verify(encode_dss_signature(r, s), mprime, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature as exc:
        raise ValueError("ECDSA component invalid") from exc
