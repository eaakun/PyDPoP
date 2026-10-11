"""DPoP proof JWT generation (RFC 9449, Section 4; PQC in v0.2)."""
from __future__ import annotations

import hashlib
import json
import secrets
import time
from urllib.parse import urlsplit, urlunsplit

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)

from .composite import composite_sign
from .jwk import CompositeKey, b64u_encode, public_jwk


def normalize_htu(htu: str) -> str:
    """Strip query and fragment per RFC 9449 §4.2 (`htu` has no query/fragment)."""
    parts = urlsplit(htu)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))


def _b64u_json(obj: dict) -> str:
    return b64u_encode(json.dumps(obj, separators=(",", ":")).encode("utf-8"))


def generate_proof(
    *,
    private_key,
    htm: str,
    htu: str,
    iat: int | None = None,
    jti: str | None = None,
    access_token: str | None = None,
    nonce: str | None = None,
) -> str:
    """Create a DPoP proof JWT for one HTTP request.

    - ``private_key``: a P-256 key from :func:`generate_key` (ES256 proof) or
      a :class:`CompositeKey` (hybrid ``ML-DSA-*-ES256`` proof)
    - ``htm``: HTTP method, e.g. "POST"
    - ``htu``: full request URI (query/fragment are stripped automatically)
    - ``access_token``: if the request carries one, its ``ath`` claim is bound
    - ``nonce``: server-provided DPoP-Nonce, when the server demands one
    """
    alg = private_key.variant if isinstance(private_key, CompositeKey) else "ES256"
    header = {"typ": "dpop+jwt", "alg": alg, "jwk": public_jwk(private_key)}
    payload: dict = {
        "jti": jti or secrets.token_urlsafe(32),
        "htm": htm.upper(),
        "htu": normalize_htu(htu),
        "iat": iat if iat is not None else int(time.time()),
    }
    if access_token is not None:
        payload["ath"] = b64u_encode(hashlib.sha256(access_token.encode("utf-8")).digest())
    if nonce is not None:
        payload["nonce"] = nonce

    signing_input = f"{_b64u_json(header)}.{_b64u_json(payload)}".encode("ascii")
    if isinstance(private_key, CompositeKey):
        raw_sig = composite_sign(private_key.variant, private_key.ml_seed, private_key.ec_key, signing_input)
    else:
        der_sig = private_key.sign(signing_input, ec.ECDSA(hashes.SHA256()))
        r, s = decode_dss_signature(der_sig)
        raw_sig = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    return f"{signing_input.decode('ascii')}.{b64u_encode(raw_sig)}"


def _raw_to_der(raw_sig: bytes) -> bytes:
    if len(raw_sig) != 64:
        raise ValueError("bad ES256 signature length")
    r = int.from_bytes(raw_sig[:32], "big")
    s = int.from_bytes(raw_sig[32:], "big")
    return encode_dss_signature(r, s)


def select_alg(server_metadata: dict, *, prefer_pqc: bool = True, require_pqc: bool = False) -> str:
    """Choose a DPoP signing alg from the AS's ``dpop_signing_alg_values_supported``
    (RFC 9449 §8.2).

    - If the AS advertises a composite alg pydpop supports and ``prefer_pqc``
      is true → that composite alg (``ML-DSA-44-ES256`` first: proofs fit the
      common 8 KB header cap).
    - Otherwise → ``"ES256"``.
    - ``require_pqc=True`` with no advertised composite alg → raises
      :class:`DPoPError` instead of silently downgrading.

    Pass the result to :func:`pydpop.generate_key` ``(alg=...)``.
    """
    from .verifier import DPoPError

    from .composite import COMPOSITE_ALGS

    advertised = server_metadata.get("dpop_signing_alg_values_supported") or ["ES256"]
    if prefer_pqc:
        for alg in COMPOSITE_ALGS:
            if alg in advertised:
                return alg
    if require_pqc:
        raise DPoPError("server does not advertise a PQC DPoP alg; refusing to downgrade")
    return "ES256"
