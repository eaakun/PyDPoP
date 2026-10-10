"""Server-side DPoP proof verification (RFC 9449, Section 4.3)."""
from __future__ import annotations

import hashlib
import hmac
import json
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from .jwk import b64u_decode, b64u_encode, jwk_thumbprint, public_key_from_jwk
from .proof import _raw_to_der


def _norm_for_compare(uri: str) -> str:
    """Compare-form of a URI: no query/fragment (RFC 9449 §4.3) plus
    case-folded scheme/host (RFC 3986 §6.2.2.1, which §4.3 SHOULD-applies).
    Used only for comparison — proof contents are untouched."""
    from urllib.parse import urlsplit, urlunsplit

    parts = urlsplit(uri)
    return urlunsplit(
        (parts.scheme.lower(), parts.netloc.lower(), parts.path, "", "")
    )


class DPoPError(Exception):
    """Raised when a DPoP proof fails verification."""


class MemoryJtiStore:
    """Minimal in-memory replay cache. Plug in Redis/DB for production."""

    def __init__(self, ttl: int = 600):
        self._seen: dict[str, float] = {}
        self.ttl = ttl

    def seen(self, jti: str) -> bool:
        now = time.time()
        # opportunistic expiry sweep
        for k in [k for k, exp in self._seen.items() if exp < now]:
            del self._seen[k]
        return jti in self._seen

    def add(self, jti: str) -> None:
        self._seen[jti] = time.time() + self.ttl


def verify_proof(
    *,
    proof: str,
    htm: str,
    htu: str,
    access_token: str | None = None,
    expected_nonce: str | None = None,
    clock_skew: int = 60,
    jti_store: MemoryJtiStore | None = None,
    now: int | None = None,
) -> dict:
    """Verify a DPoP proof JWT against the incoming request.

    Returns ``{"jwk": ..., "jwk_thumbprint": ..., "claims": ...}`` on success,
    raises :class:`DPoPError` otherwise.
    """
    now = now if now is not None else int(time.time())

    try:
        head_b64, payload_b64, sig_b64 = proof.split(".")
        header = json.loads(b64u_decode(head_b64))
        claims = json.loads(b64u_decode(payload_b64))
        signature = b64u_decode(sig_b64)
    except Exception as exc:
        raise DPoPError(f"malformed DPoP JWT: {exc}") from exc
    if not isinstance(header, dict) or not isinstance(claims, dict):
        raise DPoPError("malformed DPoP JWT: header/claims must be JSON objects")

    # 1. header checks
    if header.get("typ") != "dpop+jwt":
        raise DPoPError("bad typ header (must be 'dpop+jwt')")
    if header.get("alg") != "ES256":
        raise DPoPError(f"unsupported alg: {header.get('alg')!r}")
    jwk = header.get("jwk")
    if not isinstance(jwk, dict):
        raise DPoPError("missing embedded jwk")

    # 2. signature over the ASCII signing input
    try:
        public_key = public_key_from_jwk(jwk)
        signing_input = f"{head_b64}.{payload_b64}".encode("ascii")
        if len(signature) != 64:
            raise DPoPError("bad signature length")
        public_key.verify(_raw_to_der(signature), signing_input, ec.ECDSA(hashes.SHA256()))
    except DPoPError:
        raise
    except (InvalidSignature, ValueError) as exc:
        raise DPoPError(f"bad signature: {exc}") from exc

    # 3. claims checks
    if claims.get("htm") != htm.upper():
        raise DPoPError("htm mismatch")
    claim_htu = claims.get("htu")
    if not isinstance(claim_htu, str) or _norm_for_compare(claim_htu) != _norm_for_compare(htu):
        raise DPoPError("htu mismatch")
    iat = claims.get("iat")
    if not isinstance(iat, int) or abs(now - iat) > clock_skew:
        raise DPoPError("iat outside acceptable window")
    jti = claims.get("jti")
    if not jti:
        raise DPoPError("missing jti")
    if jti_store is not None:
        if jti_store.seen(jti):
            raise DPoPError("replayed jti")
        jti_store.add(jti)
    if expected_nonce is not None and claims.get("nonce") != expected_nonce:
        raise DPoPError("nonce mismatch")
    if access_token is not None:
        expected_ath = b64u_encode(hashlib.sha256(access_token.encode("utf-8")).digest())
        ath = claims.get("ath")
        if not isinstance(ath, str) or not hmac.compare_digest(ath, expected_ath):
            raise DPoPError("ath mismatch")

    return {"jwk": jwk, "jwk_thumbprint": jwk_thumbprint(jwk), "claims": claims}
