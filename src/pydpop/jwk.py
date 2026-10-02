"""EC key helpers: generation, public JWK export, RFC 7638 thumbprints."""
from __future__ import annotations

import base64
import hashlib
import json

from cryptography.hazmat.primitives.asymmetric import ec


def b64u_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64u_decode(data: str) -> bytes:
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


def generate_key() -> ec.EllipticCurvePrivateKey:
    """Generate a fresh P-256 private key for DPoP."""
    return ec.generate_private_key(ec.SECP256R1())


def public_jwk(private_key: ec.EllipticCurvePrivateKey) -> dict:
    """Export the public half of an EC key as a JWK (no private material)."""
    numbers = private_key.public_key().public_numbers()
    if not isinstance(numbers.curve, ec.SECP256R1):
        raise ValueError("pydpop v0.1 only supports P-256 / ES256")
    return {
        "kty": "EC",
        "crv": "P-256",
        "x": b64u_encode(numbers.x.to_bytes(32, "big")),
        "y": b64u_encode(numbers.y.to_bytes(32, "big")),
    }


def jwk_thumbprint(jwk: dict) -> str:
    """RFC 7638 JWK SHA-256 thumbprint — used for `cnf.jkt` key binding."""
    required = {"crv": jwk["crv"], "kty": jwk["kty"], "x": jwk["x"], "y": jwk["y"]}
    canonical = json.dumps(required, separators=(",", ":"), sort_keys=True)
    return b64u_encode(hashlib.sha256(canonical.encode("utf-8")).digest())


def public_key_from_jwk(jwk: dict):
    """Rebuild an EC public key object from a JWK (server side)."""
    if jwk.get("kty") != "EC" or jwk.get("crv") != "P-256":
        raise ValueError("pydpop v0.1 only supports EC P-256 JWKs")
    if "d" in jwk:
        raise ValueError("DPoP proof JWK must not contain private material")
    numbers = ec.EllipticCurvePublicNumbers(
        x=int.from_bytes(b64u_decode(jwk["x"]), "big"),
        y=int.from_bytes(b64u_decode(jwk["y"]), "big"),
        curve=ec.SECP256R1(),
    )
    return numbers.public_key()
