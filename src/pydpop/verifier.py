"""Server-side DPoP proof verification (RFC 9449, Section 4.3; PQC in v0.2)."""
from __future__ import annotations

import hashlib
import hmac
import json
import time
from dataclasses import dataclass
from enum import Enum
from typing import Protocol, runtime_checkable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from .composite import COMPOSITE_ALGS, composite_verify
from .jwk import (
    b64u_decode,
    b64u_encode,
    composite_key_from_jwk,
    jwk_thumbprint,
    public_key_from_jwk,
)
from .proof import _raw_to_der


def _norm_for_compare(uri: str) -> str:
    """Compare-form of a URI: no query/fragment (RFC 9449 §4.3) plus
    case-folded scheme/host (RFC 3986 §6.2.2.1, which §4.3 SHOULD-applies).
    Used only for comparison — proof contents are untouched."""
    from urllib.parse import urlsplit, urlunsplit

    parts = urlsplit(uri)
    return urlunsplit(
        (parts.scheme.lower(), parts.netloc.lower(), parts.path, "", "")
    )


class VerificationFailure(str, Enum):
    """Machine-readable reason a DPoP proof failed verification.

    Every rejection maps to exactly one member. The same member is
    carried on :class:`DPoPError` (``exc.reason``) and on
    :class:`DPoPVerificationResult` (``result.reason``), so a gateway
    can branch on it — e.g. ``NONCE_MISMATCH`` → 401 with a fresh
    ``DPoP-Nonce``, ``BAD_SIGNATURE`` → 400 — instead of treating
    every failure as one opaque "invalid".
    """

    MALFORMED_PROOF = "malformed_proof"
    BAD_TYP = "bad_typ"
    UNSUPPORTED_ALG = "unsupported_alg"
    INVALID_JWK = "invalid_jwk"
    BAD_SIGNATURE = "bad_signature"
    HTM_MISMATCH = "htm_mismatch"
    HTU_MISMATCH = "htu_mismatch"
    EXPIRED_IAT = "expired_iat"
    MISSING_JTI = "missing_jti"
    REPLAY_DETECTED = "replay_detected"
    NONCE_MISMATCH = "nonce_mismatch"
    ATH_MISMATCH = "ath_mismatch"


class DPoPError(Exception):
    """Raised when a DPoP proof fails verification.

    ``reason`` is the machine-readable :class:`VerificationFailure`
    (``None`` only for errors constructed without one, e.g. by older
    call sites); ``str(exc)`` keeps the human-readable detail, which
    never contains key material.
    """

    def __init__(
        self, message: str, reason: VerificationFailure | None = None
    ) -> None:
        super().__init__(message)
        self.reason = reason


@dataclass(frozen=True)
class DPoPVerificationResult:
    """Structured outcome of DPoP proof verification.

    ``valid`` is True only when every RFC 9449 §4.3 check passed; then
    ``jwk`` / ``jwk_thumbprint`` / ``claims`` carry the success payload
    and ``reason`` is None. Otherwise ``valid`` is False, ``reason``
    names the first failing check, and ``detail`` is the human-readable
    message (the same text :func:`verify_proof` raises in
    :class:`DPoPError`). Use this instead of ``verify_proof`` when the
    caller needs to distinguish failure modes.
    """

    valid: bool
    reason: VerificationFailure | None = None
    jwk: dict | None = None
    jwk_thumbprint: str | None = None
    claims: dict | None = None
    detail: str | None = None


@runtime_checkable
class ReplayStore(Protocol):
    """Replay cache for DPoP ``jti`` values.

    CONTRACT — not a suggestion, not a best-effort guideline. The
    verifier calls :meth:`check_and_record` exactly once per
    verification, and only after every other check has passed: it is
    the verification commit point (see the fixed verification order
    in docs/python-dpop-profile.md). The call must be atomic: the
    ``jti`` is recorded if and only if it was not already present,
    so two concurrent verifications of the same proof resolve
    one-win-one-loss — exactly one returns True. A store that
    records a ``jti`` before the proof is fully accepted, or that
    lets two concurrent calls both succeed, violates the contract
    and voids the replay guarantee: a failed proof would burn a
    legitimate ``jti`` (denial of service against the real client),
    or a replayed proof would slip through.

    ``iat`` is the proof's issued-at time (already validated by the
    time the verifier calls); a store may use it to bound retention
    (e.g. refuse to retain entries older than the token lifetime).
    Return ``False`` when the ``jti`` was already seen.
    """

    def check_and_record(self, jti: str, iat: int) -> bool:
        """Record ``jti`` iff unseen; return False if already seen."""
        ...


class MemoryJtiStore:
    """Minimal in-memory replay cache. Plug in Redis/DB for production.

    Implements :class:`ReplayStore`: :meth:`check_and_record` sweeps
    expired entries, then records the ``jti`` iff unseen. Retention is
    keyed off receipt time (``iat`` is accepted for protocol
    conformance); use a persistent store in multi-instance deployments
    — process memory does not survive restarts or share across workers
    (see the three failure modes in docs/python-dpop-profile.md).
    Single-process atomicity holds because the check-and-set is one
    dict operation under the GIL; multi-process deployments need a
    store with a real atomic primitive (e.g. Redis SETNX).
    """

    def __init__(self, ttl: int = 600):
        self._seen: dict[str, float] = {}
        self.ttl = ttl

    def _sweep(self, now: float) -> None:
        for k in [k for k, exp in self._seen.items() if exp < now]:
            del self._seen[k]

    def seen(self, jti: str) -> bool:
        self._sweep(time.time())
        return jti in self._seen

    def add(self, jti: str) -> None:
        self._seen[jti] = time.time() + self.ttl

    def check_and_record(self, jti: str, iat: int) -> bool:
        now = time.time()
        self._sweep(now)
        if jti in self._seen:
            return False
        self._seen[jti] = now + self.ttl
        return True


# The memo's name for the default store; same object, kept importable
# under the historical name as well.
MemoryReplayStore = MemoryJtiStore


def _verify_or_raise(
    *,
    proof: str,
    htm: str,
    htu: str,
    access_token: str | None,
    expected_nonce: str | None,
    clock_skew: int,
    jti_store: MemoryJtiStore | None,
    replay_store: ReplayStore | None,
    now: int,
) -> DPoPVerificationResult:
    """Run every RFC 9449 §4.3 check in order; return the success
    result or raise :class:`DPoPError` (with ``reason``) at the first
    failing check. Accept/reject decisions are identical to the
    pre-structured-result verifier — only the failure channel changed.

    Fixed verification order (auditable contract, see
    docs/python-dpop-profile.md §3): parse → header structure
    (typ/alg/jwk) → signature → htm/htu → iat window → jti presence
    → nonce → ath → check_and_record (commit point) → return.
    ``check_and_record`` is the LAST possibly-failing step: after it
    returns True there is no fallible path before ``valid=True``, so
    "jti consumed" ⇔ "proof accepted". A proof that fails any
    earlier check never consumes its ``jti``.
    """
    try:
        head_b64, payload_b64, sig_b64 = proof.split(".")
        header = json.loads(b64u_decode(head_b64))
        claims = json.loads(b64u_decode(payload_b64))
        signature = b64u_decode(sig_b64)
    except Exception as exc:
        raise DPoPError(
            f"malformed DPoP JWT: {exc}", VerificationFailure.MALFORMED_PROOF
        ) from exc
    if not isinstance(header, dict) or not isinstance(claims, dict):
        raise DPoPError(
            "malformed DPoP JWT: header/claims must be JSON objects",
            VerificationFailure.MALFORMED_PROOF,
        )

    # 1. header checks
    if header.get("typ") != "dpop+jwt":
        raise DPoPError(
            "bad typ header (must be 'dpop+jwt')", VerificationFailure.BAD_TYP
        )
    alg = header.get("alg")
    if alg != "ES256" and alg not in COMPOSITE_ALGS:
        raise DPoPError(
            f"unsupported alg: {alg!r}", VerificationFailure.UNSUPPORTED_ALG
        )
    jwk = header.get("jwk")
    if not isinstance(jwk, dict):
        raise DPoPError("missing embedded jwk", VerificationFailure.INVALID_JWK)
    if alg in COMPOSITE_ALGS and jwk.get("alg") != alg:
        raise DPoPError(
            "embedded JWK alg does not match proof alg",
            VerificationFailure.INVALID_JWK,
        )

    # 2. signature over the ASCII signing input
    signing_input = f"{head_b64}.{payload_b64}".encode("ascii")
    if alg in COMPOSITE_ALGS:
        try:
            variant, pub_raw = composite_key_from_jwk(jwk)
        except ValueError as exc:
            raise DPoPError(
                f"invalid embedded JWK: {exc}", VerificationFailure.INVALID_JWK
            ) from exc
        try:
            composite_verify(variant, pub_raw, signing_input, signature)
        except ValueError as exc:
            raise DPoPError(
                f"bad composite signature: {exc}",
                VerificationFailure.BAD_SIGNATURE,
            ) from exc
    else:
        try:
            public_key = public_key_from_jwk(jwk)
        except ValueError as exc:
            raise DPoPError(
                f"invalid embedded JWK: {exc}", VerificationFailure.INVALID_JWK
            ) from exc
        if len(signature) != 64:
            raise DPoPError(
                "bad signature length", VerificationFailure.BAD_SIGNATURE
            )
        try:
            public_key.verify(
                _raw_to_der(signature), signing_input, ec.ECDSA(hashes.SHA256())
            )
        except (InvalidSignature, ValueError) as exc:
            raise DPoPError(
                f"bad signature: {exc}", VerificationFailure.BAD_SIGNATURE
            ) from exc

    # 3. claims checks
    if claims.get("htm") != htm.upper():
        raise DPoPError("htm mismatch", VerificationFailure.HTM_MISMATCH)
    claim_htu = claims.get("htu")
    if not isinstance(claim_htu, str) or _norm_for_compare(claim_htu) != _norm_for_compare(htu):
        raise DPoPError("htu mismatch", VerificationFailure.HTU_MISMATCH)
    iat = claims.get("iat")
    if not isinstance(iat, int) or abs(now - iat) > clock_skew:
        raise DPoPError(
            "iat outside acceptable window", VerificationFailure.EXPIRED_IAT
        )
    jti = claims.get("jti")
    if not jti:
        raise DPoPError("missing jti", VerificationFailure.MISSING_JTI)
    if expected_nonce is not None and claims.get("nonce") != expected_nonce:
        raise DPoPError("nonce mismatch", VerificationFailure.NONCE_MISMATCH)
    if access_token is not None:
        expected_ath = b64u_encode(hashlib.sha256(access_token.encode("utf-8")).digest())
        ath = claims.get("ath")
        if not isinstance(ath, str) or not hmac.compare_digest(ath, expected_ath):
            raise DPoPError("ath mismatch", VerificationFailure.ATH_MISMATCH)

    # Commit point (LAST possibly-failing step): the jti is consumed
    # only now that every other check has passed. A proof that failed
    # above never burns its jti, so the legitimate holder can retry
    # with the same jti — and an attacker who tampers with ath on an
    # intercepted proof cannot deny the real client its jti.
    store = replay_store if replay_store is not None else jti_store
    if store is not None:
        if hasattr(store, "check_and_record"):
            if not store.check_and_record(jti, iat):
                raise DPoPError(
                    "replayed jti", VerificationFailure.REPLAY_DETECTED
                )
        else:  # duck-typed legacy store with seen()/add() only
            # No atomicity contract for the legacy interface (seen()
            # then add() cannot be one atomic step); it is kept for
            # backward compatibility only.
            if store.seen(jti):
                raise DPoPError(
                    "replayed jti", VerificationFailure.REPLAY_DETECTED
                )
            store.add(jti)

    return DPoPVerificationResult(
        valid=True,
        jwk=jwk,
        jwk_thumbprint=jwk_thumbprint(jwk),
        claims=claims,
    )


def verify_proof_result(
    *,
    proof: str,
    htm: str,
    htu: str,
    access_token: str | None = None,
    expected_nonce: str | None = None,
    clock_skew: int = 60,
    jti_store: MemoryJtiStore | None = None,
    replay_store: ReplayStore | None = None,
    now: int | None = None,
) -> DPoPVerificationResult:
    """Verify a DPoP proof JWT against the incoming request, returning
    a structured :class:`DPoPVerificationResult` instead of raising.

    Same checks, same order, same accept/reject decisions as
    :func:`verify_proof` — the only difference is the failure channel.
    ``replay_store`` (a :class:`ReplayStore`) takes precedence over the
    legacy ``jti_store`` when both are given; a ``MemoryJtiStore``
    passed as either satisfies both. ``now`` overrides the wall clock
    (tests / deterministic replay).
    """
    now = now if now is not None else int(time.time())
    try:
        return _verify_or_raise(
            proof=proof,
            htm=htm,
            htu=htu,
            access_token=access_token,
            expected_nonce=expected_nonce,
            clock_skew=clock_skew,
            jti_store=jti_store,
            replay_store=replay_store,
            now=now,
        )
    except DPoPError as exc:
        return DPoPVerificationResult(
            valid=False, reason=exc.reason, detail=str(exc)
        )


def verify_proof(
    *,
    proof: str,
    htm: str,
    htu: str,
    access_token: str | None = None,
    expected_nonce: str | None = None,
    clock_skew: int = 60,
    jti_store: MemoryJtiStore | None = None,
    replay_store: ReplayStore | None = None,
    now: int | None = None,
) -> dict:
    """Verify a DPoP proof JWT against the incoming request.

    Returns ``{"jwk": ..., "jwk_thumbprint": ..., "claims": ...}`` on success,
    raises :class:`DPoPError` otherwise (``exc.reason`` names the failing
    check as a :class:`VerificationFailure`). For a non-raising API use
    :func:`verify_proof_result`.
    """
    result = verify_proof_result(
        proof=proof,
        htm=htm,
        htu=htu,
        access_token=access_token,
        expected_nonce=expected_nonce,
        clock_skew=clock_skew,
        jti_store=jti_store,
        replay_store=replay_store,
        now=now,
    )
    if result.valid:
        return {
            "jwk": result.jwk,
            "jwk_thumbprint": result.jwk_thumbprint,
            "claims": result.claims,
        }
    raise DPoPError(
        result.detail or str(result.reason), result.reason
    )
