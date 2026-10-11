"""DPoP for requests: sign every request, handle ``DPoP-Nonce`` retries.

.. code-block:: python

    import requests
    from pydpop import generate_key
    from pydpop.integrations.requests import DPoPAuth

    key = generate_key()  # or generate_key(alg="ML-DSA-44-ES256")
    s = requests.Session()
    s.auth = DPoPAuth(key)
    s.post("https://auth.example.com/token", data={"grant_type": "client_credentials"})

Requires the ``requests`` extra: ``pip install pydpop[requests]``.
"""
from __future__ import annotations

from typing import Optional

try:
    import requests
    from requests.auth import AuthBase
except ImportError as exc:  # pragma: no cover
    raise ImportError("pydpop[requests] is required: pip install pydpop[requests]") from exc

from ..proof import generate_proof

_NONCE_STATUSES = frozenset({400, 401})


class DPoPAuth(AuthBase):
    """``requests`` auth that attaches a fresh DPoP proof to every request.

    - Each request gets its own proof (fresh ``jti``/``iat``).
    - A ``DPoP-Nonce`` response header is cached and sent on subsequent
      requests; a 400/401 carrying one triggers a single automatic retry
      with the nonce (RFC 9449 §4.3).
    - ``access_token`` binds the ``ath`` claim for resource-server calls.
    """

    def __init__(self, private_key, *, access_token: Optional[str] = None):
        self._key = private_key
        self._access_token = access_token
        self._nonce: Optional[str] = None

    @property
    def nonce(self) -> Optional[str]:
        return self._nonce

    def _proof(self, method: str, url: str, nonce: Optional[str] = None) -> str:
        return generate_proof(
            private_key=self._key,
            htm=method,
            htu=url,
            access_token=self._access_token,
            nonce=nonce,
        )

    def __call__(self, r: requests.PreparedRequest) -> requests.PreparedRequest:
        r.headers["DPoP"] = self._proof(r.method or "GET", r.url or "", self._nonce)

        def _retry_with_nonce(response: requests.Response, **kwargs):
            new_nonce = response.headers.get("DPoP-Nonce")
            if (
                new_nonce
                and new_nonce != self._nonce
                and response.status_code in _NONCE_STATUSES
                and not getattr(response, "_dpop_retried", False)
            ):
                self._nonce = new_nonce
                response._dpop_retried = True
                new_req = response.request.copy()
                new_req.headers["DPoP"] = self._proof(
                    new_req.method or "GET", new_req.url or "", new_nonce
                )
                new_resp = response.connection.send(new_req, **kwargs)
                new_resp._dpop_retried = True
                new_resp.history = [response, *response.history]
                return new_resp
            return response

        r.register_hook("response", _retry_with_nonce)
        return r
