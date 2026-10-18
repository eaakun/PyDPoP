"""PQ/T hybrid composite signatures for DPoP (v0.2).

Implements draft-ietf-jose-pq-composite-sigs (v05, WG document) for the two
ECDSA composite variants, on top of RFC 9964 (ML-DSA JOSE serialization):

    M'  = "CompositeAlgorithmSignatures2025" || Label || 0x00 || PH(M)
    sig = ML-DSA.Sign(M', ctx=Label) || DER(ECDSA.Sign(M'))

Per -05 §4.2 the component encodings are: ML-DSA as in -03 (unchanged);
the ECDSA signature as DER ``Ecdsa-Sig-Value`` (non-canonical DER rejected);
the ECDSA public key as X9.62 uncompressed (``0x04 || x || y``, 65 bytes);
the ECDSA private key as RFC 5915 DER ``ECPrivateKey`` (51 bytes for P-256).

Keys are RFC 9964 AKP JWKs whose ``pub``/``priv`` carry the raw composite
byte strings (ML-DSA PK || 0x04||x||y, ML-DSA seed || DER ECPrivateKey).
Fresh composite keys only — the draft forbids reusing component keys.
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

_EC_SIG_DER_MIN = 70  # DER Ecdsa-Sig-Value for P-256: 70..72 bytes
_EC_SIG_DER_MAX = 72
_EC_PK_LEN = 65  # X9.62 uncompressed: 0x04 || x || y
_EC_DER_PRIV_LEN = 51  # RFC 5915 DER ECPrivateKey for P-256
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


def _ec_pub_uncompressed(ec_key: ec.EllipticCurvePrivateKey) -> bytes:
    """X9.62 uncompressed point: 0x04 || x || y (65 bytes)."""
    nums = ec_key.public_key().public_numbers()
    return b"\x04" + nums.x.to_bytes(32, "big") + nums.y.to_bytes(32, "big")


def _ec_priv_der(ec_key: ec.EllipticCurvePrivateKey) -> bytes:
    """RFC 5915 DER ECPrivateKey for P-256 (51 bytes, named-curve form)."""
    d = ec_key.private_numbers().private_value.to_bytes(32, "big")
    return b"\x30\x31\x02\x01\x01\x04\x20" + d + b"\xA0\x0A\x06\x08\x2A\x86\x48\xCE\x3D\x03\x01\x07"


def ec_priv_from_der(der: bytes) -> ec.EllipticCurvePrivateKey:
    """Rebuild a P-256 private key from RFC 5915 DER ECPrivateKey (-05 §4.2)."""
    from cryptography.hazmat.primitives.serialization import load_der_private_key

    if len(der) != _EC_DER_PRIV_LEN:
        raise ValueError("bad ECDSA private key encoding")
    key = load_der_private_key(der, password=None)
    if not isinstance(key, ec.EllipticCurvePrivateKey) or not isinstance(key.curve, ec.SECP256R1):
        raise TypeError("bad ECDSA private key encoding")
    return key


def composite_public_raw(variant: str, ml_seed: bytes, ec_key: ec.EllipticCurvePrivateKey) -> bytes:
    """Raw composite public key: ML-DSA PK || 0x04 || EC x || EC y (-05 §4.2)."""
    _require_mldsa()
    cfg = _cfg(variant)
    ml_pk = cfg["ml_priv_cls"].from_seed_bytes(ml_seed).public_key().public_bytes_raw()
    return ml_pk + _ec_pub_uncompressed(ec_key)


def composite_private_raw(ml_seed: bytes, ec_key: ec.EllipticCurvePrivateKey) -> bytes:
    """Raw composite private key: 32-byte ML-DSA seed || DER ECPrivateKey (-05 §4.2)."""
    return ml_seed + _ec_priv_der(ec_key)


def composite_sign(variant: str, ml_seed: bytes, ec_key: ec.EllipticCurvePrivateKey, message: bytes) -> bytes:
    """Sign per the draft: both components over M', concatenated.

    The ECDSA half is DER ``Ecdsa-Sig-Value`` (-05 §4.2), used verbatim.
    """
    _require_mldsa()
    cfg = _cfg(variant)
    ml_sk = cfg["ml_priv_cls"].from_seed_bytes(ml_seed)
    mprime = message_repr(variant, message)
    ml_sig = ml_sk.sign(mprime, context=cfg["label"])
    der = ec_key.sign(mprime, ec.ECDSA(hashes.SHA256()))
    return ml_sig + der


def _parse_ec_pub(ec_raw: bytes) -> ec.EllipticCurvePublicKey:
    """Rebuild the ECDSA public key from X9.62 uncompressed form."""
    if len(ec_raw) != _EC_PK_LEN or ec_raw[0] != 0x04:
        raise ValueError("bad ECDSA public key encoding (want 0x04||x||y)")
    return ec.EllipticCurvePublicNumbers(
        int.from_bytes(ec_raw[1:33], "big"), int.from_bytes(ec_raw[33:65], "big"), ec.SECP256R1()
    ).public_key()


def composite_verify(variant: str, pub_raw: bytes, message: bytes, signature: bytes) -> None:
    """Verify both components; raises on any failure.

    The ECDSA half must be DER ``Ecdsa-Sig-Value``; non-canonical DER is
    rejected outright (-05 §4.2).
    """
    _require_mldsa()
    cfg = _cfg(variant)
    if len(pub_raw) != cfg["ml_pk_len"] + _EC_PK_LEN:
        raise ValueError("bad composite public key length")
    if not (cfg["ml_sig_len"] + _EC_SIG_DER_MIN <= len(signature) <= cfg["ml_sig_len"] + _EC_SIG_DER_MAX):
        raise ValueError("bad composite signature length")
    ml_sig, es_sig = signature[: cfg["ml_sig_len"]], signature[cfg["ml_sig_len"] :]
    ml_pk = cfg["ml_pub_cls"].from_public_bytes(pub_raw[: cfg["ml_pk_len"]])
    ec_pk = _parse_ec_pub(pub_raw[cfg["ml_pk_len"] :])
    mprime = message_repr(variant, message)
    try:
        ml_pk.verify(ml_sig, mprime, context=cfg["label"])
    except InvalidSignature as exc:
        raise ValueError("ML-DSA component invalid") from exc
    try:
        r, s = decode_dss_signature(es_sig)
    except ValueError as exc:
        raise ValueError("ECDSA component invalid") from exc
    if encode_dss_signature(r, s) != es_sig:
        raise ValueError("ECDSA component invalid (non-canonical DER)")
    try:
        ec_pk.verify(es_sig, mprime, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature as exc:
        raise ValueError("ECDSA component invalid") from exc
