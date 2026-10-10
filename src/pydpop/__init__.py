"""pydpop — RFC 9449 DPoP (Demonstrating Proof of Possession) for Python.

v0.1 scope: ES256 proof generation + server-side verification.
ML-DSA hybrid signatures are on the roadmap (v0.2), not in this release.
"""

from .jwk import generate_key, jwk_thumbprint, public_jwk
from .proof import generate_proof
from .verifier import DPoPError, MemoryJtiStore, verify_proof

__all__ = [
    "DPoPError",
    "MemoryJtiStore",
    "generate_key",
    "generate_proof",
    "jwk_thumbprint",
    "public_jwk",
    "verify_proof",
]

__version__ = "0.1.0"
