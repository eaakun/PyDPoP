"""DPoP for Flask: server-side proof verification as a before-request hook.

.. code-block:: python

    from flask import Flask, g
    from pydpop.integrations.flask import DPoPVerifier, dpop_exempt

    app = Flask(__name__)
    DPoPVerifier(app)  # or: verifier = DPoPVerifier(); verifier.init_app(app)

    @app.get("/data")
    def data():
        # g.dpop == {"jwk", "jwk_thumbprint", "claims"}
        # compare g.dpop["jwk_thumbprint"] to the token's cnf.jkt
        ...

    @app.get("/health")
    @dpop_exempt
    def health():
        return {"ok": True}

Any failure → ``401 WWW-Authenticate: DPoP`` (fail closed).
Requires the ``flask`` extra: ``pip install pydpop[flask]``.
"""
from __future__ import annotations

from functools import wraps
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:  # pragma: no cover
    from flask import Flask

try:
    from flask import current_app, g, jsonify, request
except ImportError as exc:  # pragma: no cover
    raise ImportError("pydpop[flask] is required: pip install pydpop[flask]") from exc

from ..verifier import DPoPError, MemoryJtiStore, verify_proof


def dpop_exempt(view_func):
    """Mark a view as exempt from DPoP verification (e.g. health checks)."""
    @wraps(view_func)
    def wrapper(*args, **kwargs):
        return view_func(*args, **kwargs)
    wrapper.dpop_exempt = True
    return wrapper


class DPoPVerifier:
    """Flask-native DPoP verification, registered as a before-request hook.

    Shares one ``jti`` replay store across requests. ``g.dpop`` carries the
    :func:`verify_proof` result dict on success.
    """

    def __init__(
        self,
        app: "Optional[Flask]" = None,
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
        if app is not None:
            self.init_app(app)

    def init_app(self, app: "Flask") -> None:
        app.before_request(self._check)

    def _unauthorized(self, detail: str):
        resp = jsonify(error="invalid_dpop_proof", error_description=detail)
        resp.status_code = 401
        resp.headers["WWW-Authenticate"] = (
            f'DPoP error="invalid_dpop_proof", error_description="{detail}"'
        )
        if self._challenge_nonce:
            resp.headers["DPoP-Nonce"] = self._challenge_nonce
        return resp

    def _check(self):
        # request.url_rule is already matched before before_request handlers run
        rule = request.url_rule
        if rule is not None:
            view = current_app.view_functions.get(rule.endpoint)
            if getattr(view, "dpop_exempt", False):
                return None
        proof = request.headers.get("DPoP")
        if not proof:
            return self._unauthorized("missing DPoP header")
        auth = request.headers.get("Authorization", "")
        access_token = auth[5:] if auth.startswith("DPoP ") else None
        try:
            g.dpop = verify_proof(
                proof=proof,
                htm=request.method,
                htu=request.url,
                access_token=access_token,
                expected_nonce=self._expected_nonce,
                clock_skew=self._clock_skew,
                jti_store=self._store,
            )
        except DPoPError as exc:
            return self._unauthorized(str(exc))
        return None
