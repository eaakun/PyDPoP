"""DPoP for aiohttp: an async client session that signs every request.

.. code-block:: python

    from pydpop import generate_key
    from pydpop.integrations.aiohttp import DPoPClientSession

    key = generate_key()

    async with DPoPClientSession(key) as sess:
        async with sess.post(token_url, data={...}) as resp: ...  # proof auto-attached
        # with an access token: ath binding is automatic
        async with DPoPClientSession(key, access_token=tok) as api:
            async with api.get(pds_url) as resp: ...

Every request gets a fresh proof; ``DPoP-Nonce`` is cached and a single
automatic retry happens on ``use_dpop_nonce`` (400/401). Mirrors
``pydpop.integrations.httpx.DPoPAuth`` for the aiohttp world.

Requires the ``aiohttp`` extra: ``pip install pydpop[aiohttp]``.
"""
from __future__ import annotations

from typing import Any, Optional

try:
    import aiohttp
    from yarl import URL
except ImportError as exc:  # pragma: no cover
    raise ImportError("pydpop[aiohttp] is required: pip install pydpop[aiohttp]") from exc

from ..jwk import public_jwk
from ..proof import generate_proof


def _is_nonce_challenge(resp: "aiohttp.ClientResponse") -> bool:
    if resp.status not in (400, 401):
        return False
    www_auth = resp.headers.get("WWW-Authenticate", "")
    if 'use_dpop_nonce' in www_auth:
        return True
    return False


class DPoPClientSession(aiohttp.ClientSession):
    """``aiohttp.ClientSession`` that attaches a fresh DPoP proof per request."""

    def __init__(self, private_key, *, access_token: Optional[str] = None, **kwargs: Any):
        super().__init__(**kwargs)
        self._dpop_key = private_key
        self._access_token = access_token
        self._nonce: Optional[str] = None

    async def _request(self, method: str, str_or_url, **kwargs: Any):
        url = URL(str_or_url)
        # strip auth from headers if caller passed a stale DPoP proof
        headers = dict(kwargs.pop("headers", None) or {})
        if self._access_token and "Authorization" not in headers:
            headers["Authorization"] = f"DPoP {self._access_token}"

        def sign(nonce: Optional[str]):
            proof = generate_proof(
                private_key=self._dpop_key,
                htm=method.upper(),
                htu=str(url.with_query(None).with_fragment(None)),
                access_token=self._access_token,
                nonce=nonce,
            )
            return {**headers, "DPoP": proof}

        resp = await super()._request(method, str_or_url, headers=sign(self._nonce), **kwargs)
        if _is_nonce_challenge(resp):
            new_nonce = resp.headers.get("DPoP-Nonce")
            if new_nonce and new_nonce != self._nonce:
                self._nonce = new_nonce
                resp.release()
                resp = await super()._request(method, str_or_url, headers=sign(new_nonce), **kwargs)
        elif "DPoP-Nonce" in resp.headers:
            self._nonce = resp.headers["DPoP-Nonce"]
        return resp

    @property
    def dpop_jwk_thumbprint(self) -> str:
        from ..jwk import jwk_thumbprint

        return jwk_thumbprint(public_jwk(self._dpop_key))
