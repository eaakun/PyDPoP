"""DPoP for Starlette: server-side proof verification as ASGI middleware.

Works for any Starlette app (and any ASGI framework):

.. code-block:: python

    from starlette.applications import Starlette
    from pydpop.integrations.starlette import DPoPMiddleware

    app = Starlette()
    app.add_middleware(DPoPMiddleware)  # or DPoPMiddleware(app, ...)

On success the endpoint sees ``scope["dpop"] == {"jwk", "jwk_thumbprint",
"claims"}`` — compare ``scope["dpop"]["jwk_thumbprint"]`` against the
access token's ``cnf.jkt``. Any failure → ``401 WWW-Authenticate: DPoP``
(fail closed). Non-HTTP scopes pass through untouched.

Requires the ``starlette`` extra: ``pip install pydpop[starlette]``.
"""
from __future__ import annotations

from typing import Optional

try:
    from starlette.responses import JSONResponse
    from starlette.types import ASGIApp, Message, Receive, Scope, Send
except ImportError as exc:  # pragma: no cover
    raise ImportError("pydpop[starlette] is required: pip install pydpop[starlette]") from exc

from ..verifier import DPoPError, MemoryJtiStore, verify_proof


def _unauthorized(detail: str, nonce: Optional[str] = None) -> JSONResponse:
    headers = {"WWW-Authenticate": f'DPoP error="invalid_dpop_proof", error_description="{detail}"'}
    if nonce:
        headers["DPoP-Nonce"] = nonce
    return JSONResponse(
        {"error": "invalid_dpop_proof", "error_description": detail},
        status_code=401,
        headers=headers,
    )


class DPoPMiddleware:
    """ASGI middleware verifying DPoP proofs (fail closed)."""

    def __init__(
        self,
        app: ASGIApp,
        *,
        jti_store: Optional[MemoryJtiStore] = None,
        clock_skew: int = 60,
        expected_nonce: Optional[str] = None,
        challenge_nonce: Optional[str] = None,
    ):
        self.app = app
        self._store = jti_store or MemoryJtiStore()
        self._clock_skew = clock_skew
        self._expected_nonce = expected_nonce
        self._challenge_nonce = challenge_nonce

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        headers = {k.decode().lower(): v.decode() for k, v in scope["headers"]}
        proof = headers.get("dpop")
        if not proof:
            resp = _unauthorized("missing DPoP header", self._challenge_nonce)
            await resp(scope, receive, send)
            return
        auth = headers.get("authorization", "")
        access_token = auth[5:] if auth.startswith("DPoP ") else None
        scheme = scope.get("scheme", "http")
        server = scope.get("server") or ("testserver", 80)
        host = headers.get("host", server[0])
        htu = f"{scheme}://{host}{scope.get('path', '/')}"
        try:
            scope["dpop"] = verify_proof(
                proof=proof,
                htm=scope["method"],
                htu=htu,
                access_token=access_token,
                expected_nonce=self._expected_nonce,
                clock_skew=self._clock_skew,
                jti_store=self._store,
            )
        except DPoPError as exc:
            resp = _unauthorized(str(exc), self._challenge_nonce)
            await resp(scope, receive, send)
            return
        await self.app(scope, receive, send)
