"""DPoP for httpx: sign every request, handle ``DPoP-Nonce`` retries.

Once this is wired into your client, DPoP is no longer a per-request chore —
it rides along with every call, including the ``use_dpop_nonce`` retry dance
from RFC 9449 §4.3.

.. code-block:: python

    import httpx
    from pydpop import generate_key
    from pydpop.integrations.httpx import DPoPAuth

    key = generate_key(alg="ML-DSA-44-ES256")  # or default ES256
    client = httpx.Client(auth=DPoPAuth(key))
    r = client.post("https://auth.example.com/token", data={"grant_type": "client_credentials"})

Requires the ``httpx`` extra: ``pip install pydpop[httpx]``.
"""
from __future__ import annotations

from typing import Iterator, Optional

try:
    import httpx
except ImportError as exc:  # pragma: no cover
    raise ImportError("pydpop[httpx] is required: pip install pydpop[httpx]") from exc

from ..proof import generate_proof

#: Statuses on which a DPoP-Nonce challenge may arrive (RFC 9449 §4.3).
_NONCE_STATUSES = frozenset({400, 401})


class DPoPAuth(httpx.Auth):
    """``httpx.Auth`` that attaches a fresh DPoP proof to every request.

    - Each request gets its own proof (fresh ``jti``/``iat``).
    - A ``DPoP-Nonce`` response header is cached and sent on subsequent
      requests; a 400/401 carrying one triggers a single automatic retry
      with the nonce (RFC 9449 §4.3) — the caller never sees the dance.
    - ``access_token`` binds the ``ath`` claim when calling a resource
      server with a DPoP-bound token.
    """

    def __init__(self, private_key, *, access_token: Optional[str] = None):
        self._key = private_key
        self._access_token = access_token
        self._nonce: Optional[str] = None

    @property
    def nonce(self) -> Optional[str]:
        """Last server-provided DPoP nonce, if any."""
        return self._nonce

    def _proof_for(self, request: httpx.Request, nonce: Optional[str] = None) -> str:
        return generate_proof(
            private_key=self._key,
            htm=request.method,
            htu=str(request.url),
            access_token=self._access_token,
            nonce=nonce,
        )

    def _send_with_proof(self, request: httpx.Request, nonce: Optional[str]):
        request.headers["DPoP"] = self._proof_for(request, nonce)
        return request

    def auth_flow(self, request: httpx.Request) -> Iterator[httpx.Request]:
        response = yield self._send_with_proof(request, self._nonce)
        new_nonce = response.headers.get("DPoP-Nonce")
        if new_nonce and new_nonce != self._nonce and response.status_code in _NONCE_STATUSES:
            # One automatic retry with the fresh nonce; never loops.
            self._nonce = new_nonce
            yield self._send_with_proof(request, new_nonce)
