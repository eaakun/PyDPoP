"""pydpop — RFC 9449 DPoP (Demonstrating Proof of Possession) for Python.

v0.2: ES256 plus PQ/T hybrid composite proofs (``ML-DSA-44-ES256``,
``ML-DSA-65-ES256``) per draft-ietf-jose-pq-composite-sigs and RFC 9964.
Single dependency: ``cryptography``.
"""

from .composite import COMPOSITE_ALGS
from .jwk import CompositeKey, composite_key_from_jwk, generate_key, jwk_thumbprint, private_jwk, public_jwk
from .proof import generate_proof, select_alg
from .verifier import DPoPError, MemoryJtiStore, verify_proof

__all__ = [
    "COMPOSITE_ALGS",
    "CompositeKey",
    "DPoPError",
    "MemoryJtiStore",
    "composite_key_from_jwk",
    "generate_key",
    "generate_proof",
    "jwk_thumbprint",
    "private_jwk",
    "public_jwk",
    "select_alg",
    "verify_proof",
]

__version__ = "0.2.0"
