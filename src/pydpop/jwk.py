"""Key helpers: EC (v0.1) and PQ/T hybrid composite keys (v0.2).

EC keys are ``cryptography`` objects; composite keys are :class:`CompositeKey`.
Both flow through the same helpers: :func:`generate_key`, :func:`public_jwk`,
:func:`jwk_thumbprint`, :func:`public_key_from_jwk` (server side rebuilds the
verifier inputs from the embedded JWK).
"""
from __future__ import annotations

import base64
import hashlib
import json
import secrets

from cryptography.hazmat.primitives.asymmetric import ec

from .composite import (
    COMPOSITE_ALGS,
    composite_private_raw,
    composite_public_raw,
)


def b64u_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64u_decode(data: str) -> bytes:
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


def generate_key(alg: str = "ES256"):
    """Generate a fresh DPoP key.

    - ``"ES256"`` (default): returns a P-256 ``EllipticCurvePrivateKey``.
    - ``"ML-DSA-44-ES256"`` / ``"ML-DSA-65-ES256"``: returns a
      :class:`CompositeKey` (fresh ML-DSA + P-256 pair; the draft forbids
      reusing component keys across contexts).
    """
    if alg == "ES256":
        return ec.generate_private_key(ec.SECP256R1())
    return CompositeKey.generate(alg)


class CompositeKey:
    """A PQ/T hybrid keypair: fresh ML-DSA seed + fresh P-256 key.

    The two components are generated together and never separated —
    ``variant`` selects the ML-DSA parameter set (``ML-DSA-44-ES256`` is the
    default: proofs fit the common 8 KB HTTP header cap).
    """

    def __init__(self, variant: str, ml_seed: bytes, ec_key: ec.EllipticCurvePrivateKey):
        if variant not in COMPOSITE_ALGS:
            raise ValueError(f"unsupported composite alg: {variant!r}")
        if len(ml_seed) != 32:
            raise ValueError("ML-DSA seed must be 32 bytes")
        self.variant = variant
        self._ml_seed = ml_seed
        self._ec_key = ec_key

    @classmethod
    def generate(cls, variant: str = "ML-DSA-44-ES256") -> CompositeKey:
        return cls(variant, secrets.token_bytes(32), ec.generate_private_key(ec.SECP256R1()))

    @property
    def ml_seed(self) -> bytes:
        return self._ml_seed

    @property
    def ec_key(self) -> ec.EllipticCurvePrivateKey:
        return self._ec_key

    def __repr__(self) -> str:  # never leak key material
        return f"CompositeKey({self.variant})"


def public_jwk(private_key) -> dict:
    """Export the public half of a key as a JWK (no private material).

    EC keys → ``{"kty": "EC", ...}``; composite keys → RFC 9964
    ``{"kty": "AKP", "alg": <variant>, "pub": ...}``.
    """
    if isinstance(private_key, CompositeKey):
        return {
            "kty": "AKP",
            "alg": private_key.variant,
            "pub": b64u_encode(
                composite_public_raw(private_key.variant, private_key.ml_seed, private_key.ec_key)
            ),
        }
    numbers = private_key.public_key().public_numbers()
    if not isinstance(numbers.curve, ec.SECP256R1):
        raise ValueError("pydpop only supports P-256 / ES256 for EC keys")
    return {
        "kty": "EC",
        "crv": "P-256",
        "x": b64u_encode(numbers.x.to_bytes(32, "big")),
        "y": b64u_encode(numbers.y.to_bytes(32, "big")),
    }


def private_jwk(private_key) -> dict:
    """Export a key including private material (client-side storage only).

    Never embed this in a proof — proofs carry :func:`public_jwk`.
    """
    if isinstance(private_key, CompositeKey):
        return {
            "kty": "AKP",
            "alg": private_key.variant,
            "pub": b64u_encode(
                composite_public_raw(private_key.variant, private_key.ml_seed, private_key.ec_key)
            ),
            "priv": b64u_encode(composite_private_raw(private_key.ml_seed, private_key.ec_key)),
        }
    numbers = private_key.private_numbers()
    if not isinstance(numbers.public_numbers.curve, ec.SECP256R1):
        raise ValueError("pydpop only supports P-256 / ES256 for EC keys")
    pub = numbers.public_numbers
    return {
        "kty": "EC",
        "crv": "P-256",
        "x": b64u_encode(pub.x.to_bytes(32, "big")),
        "y": b64u_encode(pub.y.to_bytes(32, "big")),
        "d": b64u_encode(numbers.private_value.to_bytes(32, "big")),
    }


def jwk_thumbprint(jwk: dict) -> str:
    """RFC 7638 JWK SHA-256 thumbprint — used for ``cnf.jkt`` key binding.

    EC keys use ``crv/kty/x/y``; AKP (composite) keys use ``alg/kty/pub``
    per RFC 9964.
    """
    if jwk.get("kty") == "AKP":
        required = {"alg": jwk["alg"], "kty": jwk["kty"], "pub": jwk["pub"]}
    else:
        required = {"crv": jwk["crv"], "kty": jwk["kty"], "x": jwk["x"], "y": jwk["y"]}
    canonical = json.dumps(required, separators=(",", ":"), sort_keys=True)
    return b64u_encode(hashlib.sha256(canonical.encode("utf-8")).digest())


def public_key_from_jwk(jwk: dict):
    """Rebuild an EC public key object from a JWK (server side)."""
    if jwk.get("kty") != "EC" or jwk.get("crv") != "P-256":
        raise ValueError("pydpop only supports EC P-256 JWKs here; use composite_key_from_jwk for AKP")
    if "d" in jwk:
        raise ValueError("DPoP proof JWK must not contain private material")
    if not isinstance(jwk.get("x"), str) or not isinstance(jwk.get("y"), str):
        raise ValueError("EC JWK must carry string 'x' and 'y' coordinates")
    numbers = ec.EllipticCurvePublicNumbers(
        x=int.from_bytes(b64u_decode(jwk["x"]), "big"),
        y=int.from_bytes(b64u_decode(jwk["y"]), "big"),
        curve=ec.SECP256R1(),
    )
    return numbers.public_key()


def composite_key_from_jwk(jwk: dict) -> tuple[str, bytes]:
    """Extract ``(variant, raw_composite_public)`` from an AKP JWK (server side)."""
    if jwk.get("kty") != "AKP":
        raise ValueError("not an AKP JWK")
    variant = jwk.get("alg")
    if variant not in COMPOSITE_ALGS:
        raise ValueError(f"unsupported composite alg: {variant!r}")
    if "priv" in jwk:
        raise ValueError("DPoP proof JWK must not contain private material")
    pub = jwk.get("pub")
    if not isinstance(pub, str):
        raise ValueError("AKP JWK must carry a string 'pub'")
    return variant, b64u_decode(pub)


def private_key_from_jwk(jwk: dict):
    """Rebuild a private key from a :func:`private_jwk` dict (client-side key storage).

    Round-trips both EC and composite keys. Keep the input secret.
    """
    if jwk.get("kty") == "AKP":
        variant = jwk.get("alg")
        if variant not in COMPOSITE_ALGS:
            raise ValueError(f"unsupported composite alg: {variant!r}")
        priv = jwk.get("priv")
        if not isinstance(priv, str):
            raise ValueError("AKP private JWK must carry a string 'priv'")
        raw = b64u_decode(priv)
        if len(raw) != 64:
            raise ValueError("bad composite private key length")
        ec_key = ec.derive_private_key(int.from_bytes(raw[32:], "big"), ec.SECP256R1())
        return CompositeKey(variant, raw[:32], ec_key)
    if jwk.get("kty") == "EC" and jwk.get("crv") == "P-256":
        d = jwk.get("d")
        if not isinstance(d, str):
            raise ValueError("EC private JWK must carry a string 'd'")
        return ec.derive_private_key(int.from_bytes(b64u_decode(d), "big"), ec.SECP256R1())
    raise ValueError(f"unsupported private JWK: kty={jwk.get('kty')!r}")
