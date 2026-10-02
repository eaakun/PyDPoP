"""pydpop — RFC 9449 DPoP (Demonstrating Proof of Possession) for Python.

v0.1 scope: ES256 proof generation + server-side verification.
ML-DSA hybrid signatures are on the roadmap (v0.2), not in this release.
"""

from .jwk import generate_key, public_jwk, jwk_thumbprint
from .proof import generate_proof
from .verifier import verify_proof, DPoPError, MemoryJtiStore

__all__ = [
    "generate_key",
    "public_jwk",
    "jwk_thumbprint",
    "generate_proof",
    "verify_proof",
    "DPoPError",
    "MemoryJtiStore",
]

__version__ = "0.1.0"
