"""DPoP for FastAPI: server-side proof verification as a Dependency.

No standalone PyPI package offers this — everyone hand-rolls it. Wire it
once and every endpoint gets RFC 9449 verification, replay protection,
and `ath` binding:

.. code-block:: python

    from fastapi import Depends, FastAPI
    from pydpop.integrations.fastapi import DPoPVerifier

    app = FastAPI()
    verify_dpop = DPoPVerifier()  # shared replay cache

    @app.get("/data")
    def read_data(bound=Depends(verify_dpop)):
        # bound == {"jwk", "jwk_thumbprint", "claims"}; compare
        # bound["jwk_thumbprint"] against the access token's cnf.jkt
        ...

Failures raise 401 with ``WWW-Authenticate: DPoP`` (fail closed).
Requires the ``fastapi`` extra: ``pip install pydpop[fastapi]``.
"""
from __future__ import annotations

from typing import Optional

try:
    from fastapi import HTTPException, Request, status
except ImportError as exc:  # pragma: no cover
    raise ImportError("pydpop[fastapi] is required: pip install pydpop[fastapi]") from exc

from ..verifier import DPoPError, MemoryJtiStore, verify_proof


def _unauthorized(detail: str = "invalid DPoP proof", nonce: Optional[str] = None) -> HTTPException:
    headers = {"WWW-Authenticate": f'DPoP error="invalid_dpop_proof", error_description="{detail}"'}
    if nonce:
        headers["DPoP-Nonce"] = nonce
    return HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, headers=headers)


class DPoPVerifier:
    """FastAPI Dependency verifying DPoP proofs on incoming requests.

    - Extracts the ``DPoP`` header and the ``Authorization: DPoP <token>``
      access token (for ``ath`` binding).
    - Verifies signature, ``htm``/``htu``, ``iat`` window, ``nonce``,
      ``ath``, and ``jti`` replay via the shared store.
    - Returns the :func:`verify_proof` result dict
      (``{"jwk", "jwk_thumbprint", "claims"}``) for the endpoint to
      compare ``jwk_thumbprint`` against the token's ``cnf.jkt``.
    - Any failure → 401 ``WWW-Authenticate: DPoP`` (fail closed).

    Share one instance across endpoints so the replay cache is shared.
    """

    def __init__(
        self,
        *,
        jti_store: Optional[MemoryJtiStore] = None,
        clock_skew: int = 60,
        expected_nonce: Optional[str] = None,
        challenge_nonce: Optional[str] = None,
    ):
        self._store = jti_store or MemoryJtiStore()
        self._clock_skew = clock_skew
        self._expected_nonce = expected_nonce
        self._challenge_nonce = challenge_nonce

    async def __call__(self, request: Request) -> dict:
        proof = request.headers.get("DPoP")
        if not proof:
            raise _unauthorized("missing DPoP header", self._challenge_nonce)
        auth = request.headers.get("Authorization", "")
        access_token = auth[5:] if auth.startswith("DPoP ") else None
        try:
            return verify_proof(
                proof=proof,
                htm=request.method,
                htu=str(request.url),
                access_token=access_token,
                expected_nonce=self._expected_nonce,
                clock_skew=self._clock_skew,
                jti_store=self._store,
            )
        except DPoPError as exc:
            raise _unauthorized(str(exc), self._challenge_nonce) from exc
