"""DPoP for Django: server-side proof verification as middleware.

Add to ``MIDDLEWARE`` and every request gets RFC 9449 verification,
replay protection, and ``ath`` binding:

.. code-block:: python

    # settings.py
    MIDDLEWARE = [
        ...,
        "pydpop.integrations.django.DPoPMiddleware",
    ]
    # optional
    PYDPOP_DPOP = {"clock_skew": 60, "challenge_nonce": None}

On success the view sees ``request.dpop == {"jwk", "jwk_thumbprint",
"claims"}`` — compare ``request.dpop["jwk_thumbprint"]`` against the
access token's ``cnf.jkt``. Any failure → ``401 WWW-Authenticate: DPoP``
(fail closed). Exempt views (health checks, public pages) with
``@dpop_exempt``.

Requires the ``django`` extra: ``pip install pydpop[django]``.
"""
from __future__ import annotations

from functools import wraps
from typing import Optional

try:
    from django.conf import settings
    from django.http import JsonResponse
except ImportError as exc:  # pragma: no cover
    raise ImportError("pydpop[django] is required: pip install pydpop[django]") from exc

from ..verifier import DPoPError, MemoryJtiStore, verify_proof


def dpop_exempt(view_func):
    """Mark a view as exempt from DPoP verification (e.g. health checks)."""
    @wraps(view_func)
    def wrapper(*args, **kwargs):
        return view_func(*args, **kwargs)
    wrapper.dpop_exempt = True
    return wrapper


def _unauthorized(detail: str, nonce: Optional[str] = None) -> JsonResponse:
    resp = JsonResponse({"error": "invalid_dpop_proof", "error_description": detail}, status=401)
    resp["WWW-Authenticate"] = f'DPoP error="invalid_dpop_proof", error_description="{detail}"'
    if nonce:
        resp["DPoP-Nonce"] = nonce
    return resp


class DPoPMiddleware:
    """Verify DPoP proofs on incoming requests (fail closed).

    Shares one ``jti`` replay store across requests. Configure via the
    ``PYDPOP_DPOP`` settings dict: ``clock_skew`` (seconds, default 60),
    ``expected_nonce``, ``challenge_nonce``, or a custom ``jti_store``.
    """

    def __init__(self, get_response):
        self.get_response = get_response
        cfg = getattr(settings, "PYDPOP_DPOP", {}) or {}
        self._store = cfg.get("jti_store") or MemoryJtiStore()
        self._clock_skew = cfg.get("clock_skew", 60)
        self._expected_nonce = cfg.get("expected_nonce")
        self._challenge_nonce = cfg.get("challenge_nonce")

    def __call__(self, request):
        return self.get_response(request)

    def process_view(self, request, view_func, view_args, view_kwargs):
        """Runs after URL resolution, so @dpop_exempt is visible here."""
        if getattr(view_func, "dpop_exempt", False):
            return None
        proof = request.headers.get("DPoP")
        if not proof:
            return _unauthorized("missing DPoP header", self._challenge_nonce)
        auth = request.headers.get("Authorization", "")
        access_token = auth[5:] if auth.startswith("DPoP ") else None
        try:
            request.dpop = verify_proof(
                proof=proof,
                htm=request.method,
                htu=request.build_absolute_uri(),
                access_token=access_token,
                expected_nonce=self._expected_nonce,
                clock_skew=self._clock_skew,
                jti_store=self._store,
            )
        except DPoPError as exc:
            return _unauthorized(str(exc), self._challenge_nonce)
        return None
