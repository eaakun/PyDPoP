#!/usr/bin/env python3
"""Generate the static DPoP conformance fixture vectors.

Builds ``conformance/vectors/vectors.json`` from the corpus in
``cases.py``: one entry per case, each carrying the actual proof JWT
strings, the verifier inputs, and the expected outcome — so another
implementation can run the same 28 cases without pydpop installed.

Design notes (read before regenerating):

- Fixed key, fixed time. All ES256 proofs are signed with one
  committed test key (``keys.es256`` in the output) and evaluated at
  a fixed reference time (2026-11-06T00:00:00Z, epoch 1793923200),
  so ``iat`` edges (±300 s accept, ±301 s reject) are exact and do
  not drift with the wall clock. The key is TEST ONLY and is labelled
  as such in the output.
- The committed vectors are the artifact. ECDSA signatures use a
  random nonce, so re-running this generator produces *equivalent*
  vectors (identical claims, keys, and expected outcomes) with
  different signature bytes — it is not byte-identical. Do not
  expect ``diff`` to be empty across regenerations; the check that
  matters is ``python conformance/run.py --vectors`` (28/28).
- Regeneration reuses the committed key (loaded from the existing
  vectors.json), so the key — and therefore the ``cnf.jkt`` in T01 —
  is stable across runs.
- Hybrid cases (G05, A06) use a fresh ML-DSA-44-ES256 composite key
  per generation; the proof is self-contained (embedded JWK), so no
  hybrid key is committed.
- Multi-step cases (R07 replay, N01 nonce retry) share one fresh
  jti store across their steps; that is part of the case semantics
  and is recorded in the output's ``evaluation`` block.
"""

import hashlib
import hmac as hmac_mod
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
sys.path.insert(0, os.path.dirname(__file__))

from cases import (
    HTM,
    HTU,
    _b64u_json,
    _build_proof,
    _decode_claims,
    _ec_sign_raw,
)

from pydpop.composite import mldsa_available
from pydpop.jwk import (
    CompositeKey,
    b64u_encode,
    generate_key,
    jwk_thumbprint,
    private_jwk,
    private_key_from_jwk,
    public_jwk,
)
from pydpop.proof import generate_proof

REF = 1793923200  # 2026-11-06T00:00:00Z — the fixed "now" for evaluation
OUT = os.path.join(os.path.dirname(__file__), "vectors", "vectors.json")
TOKEN = "test-access-token-123"
NONCE = "server-nonce-1"

# reason_contains substring -> VerificationFailure member. Every reject
# step carries both: the human-readable substring (for any language)
# and the machine-readable enum member (for pydpop and for the
# compliance matrix). R15 has no reason_contains (its rejection is
# "invalid embedded JWK" via key rebuild) and sets expect_reason
# explicitly instead.
REASON_MAP = {
    "bad signature": "BAD_SIGNATURE",
    "htm mismatch": "HTM_MISMATCH",
    "htu mismatch": "HTU_MISMATCH",
    "iat outside acceptable window": "EXPIRED_IAT",
    "missing jti": "MISSING_JTI",
    "replayed jti": "REPLAY_DETECTED",
    "ath mismatch": "ATH_MISMATCH",
    "nonce mismatch": "NONCE_MISMATCH",
    "unsupported alg": "UNSUPPORTED_ALG",
    "missing embedded jwk": "INVALID_JWK",
    "bad typ": "BAD_TYP",
    "malformed": "MALFORMED_PROOF",
}


def _step(proof, expect, **kw):
    d = {"proof": proof, "htm": HTM, "htu": HTU, "clock_skew": 300,
         "expect": expect}
    d.update(kw)
    if expect == "reject" and "expect_reason" not in d:
        d["expect_reason"] = REASON_MAP[d["reason_contains"]]
    return d


def _valid(key, cid, jti=None, **kw):
    kw.setdefault("iat", REF)
    kw.setdefault("htm", HTM)
    kw.setdefault("htu", HTU)
    return generate_proof(
        private_key=key, jti=jti or f"{cid}-1", **kw
    )


def _signed(key, header, payload):
    # Adds iat only; callers pass jti explicitly (R06 deliberately has none).
    payload = dict(payload)
    payload.setdefault("iat", REF)
    signing_input = f"{_b64u_json(header)}.{_b64u_json(payload)}".encode()
    sig = _ec_sign_raw(key, signing_input)
    return f"{signing_input.decode()}.{b64u_encode(sig)}"


def _case(cid, title, spec, category, steps, expected=None):
    return {
        "id": cid,
        "title": title,
        "spec": spec,
        "category": category,
        "expected": expected or ("reject" if category == "reject" else "accept"),
        "steps": steps,
    }


def _hybrid_key():
    if not mldsa_available():
        raise RuntimeError("ML-DSA backend unavailable — cannot build G05/A06")
    return CompositeKey.generate("ML-DSA-44-ES256")


def build_cases(key):
    cases = []

    # ------------------------------------------------------------ generation
    proof = _valid(key, "G01")
    cases.append(_case("G01", "proof carries typ dpop+jwt, alg ES256, EC P-256 jwk",
                       "RFC 9449 §4.2", "generation",
                       [_step(proof, "structure",
                              expect_header={"typ": "dpop+jwt", "alg": "ES256",
                                             "jwk": {"kty": "EC", "crv": "P-256"}},
                              expect_claims={"htm": HTM, "htu": HTU, "iat": REF,
                                             "jti": "G01-1"})],
                       expected="structure"))

    proof = _valid(key, "G02", access_token=TOKEN)
    cases.append(_case("G02", "ath equals base64url(SHA-256(access token))",
                       "RFC 9449 §4.3", "generation",
                       [_step(proof, "structure",
                              expect_claims={"ath": b64u_encode(
                                  hashlib.sha256(TOKEN.encode()).digest())})],
                       expected="structure"))

    proof = _valid(key, "G03", nonce=NONCE)
    cases.append(_case("G03", "nonce claim present when server nonce supplied",
                       "RFC 9449 §4.3", "generation",
                       [_step(proof, "structure",
                              expect_claims={"nonce": NONCE})],
                       expected="structure"))

    proof = _valid(key, "G04", htu="https://mcp.example.com/token?code=abc#frag")
    cases.append(_case("G04", "htu strips query and fragment",
                       "RFC 9449 §4.3", "generation",
                       [_step(proof, "structure",
                              expect_claims={"htu": HTU})],
                       expected="structure"))

    proof = _valid(_hybrid_key(), "G05")
    cases.append(_case("G05", "hybrid proof carries ML-DSA alg in header and jwk",
                       "draft-ietf-jose-pq-composite-sigs-05", "generation",
                       [_step(proof, "structure",
                              expect_header={"alg": "ML-DSA-44-ES256",
                                             "jwk": {"alg": "ML-DSA-44-ES256"}})],
                       expected="structure"))

    # ---------------------------------------------------------------- accept
    cases.append(_case("A01", "valid proof verifies", "RFC 9449 §4.3", "accept",
                       [_step(_valid(key, "A01"), "accept")]))
    cases.append(_case("A02", "proof with matching ath verifies", "RFC 9449 §4.3",
                       "accept",
                       [_step(_valid(key, "A02", access_token=TOKEN), "accept",
                              access_token=TOKEN)]))
    cases.append(_case("A03", "proof with matching nonce verifies", "RFC 9449 §8/§9",
                       "accept",
                       [_step(_valid(key, "A03", nonce=NONCE), "accept",
                              expected_nonce=NONCE)]))
    cases.append(_case("A04", "iat at -300s accepts under SEP window",
                       "SEP-1932 § Stateless Replay", "accept",
                       [_step(_valid(key, "A04", iat=REF - 300), "accept")]))
    cases.append(_case("A05", "iat at +300s accepts under SEP window",
                       "SEP-1932 § Stateless Replay", "accept",
                       [_step(_valid(key, "A05", iat=REF + 300), "accept")]))
    cases.append(_case("A06", "hybrid proof verifies",
                       "draft-ietf-jose-pq-composite-sigs-05", "accept",
                       [_step(_valid(_hybrid_key(), "A06"), "accept")]))

    # ---------------------------------------------------------------- reject
    proof = _valid(key, "R01")
    head_b64, _, sig_b64 = proof.split(".")
    claims = _decode_claims(proof)
    claims["htm"] = "GET"  # tamper without re-signing
    forged = f"{head_b64}.{_b64u_json(claims)}.{sig_b64}"
    cases.append(_case("R01", "tampered payload rejected (bad signature)",
                       "RFC 9449 §4.3", "reject",
                       [_step(forged, "reject", htm="GET",
                              reason_contains="bad signature")]))

    cases.append(_case("R02", "wrong htm rejected", "RFC 9449 §4.3", "reject",
                       [_step(_valid(key, "R02", htm="POST"), "reject", htm="GET",
                              reason_contains="htm mismatch")]))
    cases.append(_case("R03", "wrong htu rejected", "RFC 9449 §4.3", "reject",
                       [_step(_valid(key, "R03"), "reject",
                              htu="https://mcp.example.com/other",
                              reason_contains="htu mismatch")]))
    cases.append(_case("R04", "iat at -301s rejected under SEP window",
                       "SEP-1932 § Stateless Replay", "reject",
                       [_step(_valid(key, "R04", iat=REF - 301), "reject",
                              reason_contains="iat outside acceptable window")]))
    cases.append(_case("R05", "iat at +301s rejected under SEP window",
                       "SEP-1932 § Stateless Replay", "reject",
                       [_step(_valid(key, "R05", iat=REF + 301), "reject",
                              reason_contains="iat outside acceptable window")]))

    header = {"typ": "dpop+jwt", "alg": "ES256", "jwk": public_jwk(key)}
    payload = {"htm": HTM, "htu": HTU}  # no jti
    cases.append(_case("R06", "missing jti rejected", "RFC 9449 §4.3", "reject",
                       [_step(_signed(key, header, payload), "reject",
                              reason_contains="missing jti")]))

    proof = _valid(key, "R07")
    cases.append(_case("R07", "replayed jti rejected by stateful store",
                       "RFC 9449 §11.1", "reject",
                       [_step(proof, "accept"),
                        _step(proof, "reject", reason_contains="replayed jti")]))

    cases.append(_case("R08", "ath mismatch rejected", "RFC 9449 §4.3", "reject",
                       [_step(_valid(key, "R08", access_token="token-A"), "reject",
                              access_token="token-B",
                              reason_contains="ath mismatch")]))
    cases.append(_case("R09", "nonce mismatch rejected", "RFC 9449 §8/§9", "reject",
                       [_step(_valid(key, "R09", nonce="nonce-A"), "reject",
                              expected_nonce="nonce-B",
                              reason_contains="nonce mismatch")]))

    header = {"typ": "dpop+jwt", "alg": "none", "jwk": public_jwk(key)}
    payload = {"htm": HTM, "htu": HTU, "iat": REF, "jti": "R10-1"}
    cases.append(_case("R10", "alg none rejected", "RFC 9449 §4.2", "reject",
                       [_step(_build_proof(header, payload, b""), "reject",
                              reason_contains="unsupported alg")]))

    header = {"typ": "dpop+jwt", "alg": "HS256", "jwk": public_jwk(key)}
    payload = {"htm": HTM, "htu": HTU, "iat": REF, "jti": "R11-1"}
    sig = hmac_mod.new(b"secret", b"whatever", hashlib.sha256).digest()
    cases.append(_case("R11", "alg HS256 rejected", "RFC 9449 §4.2", "reject",
                       [_step(_build_proof(header, payload, sig), "reject",
                              reason_contains="unsupported alg")]))

    header = {"typ": "dpop+jwt", "alg": "ES256"}  # no jwk
    payload = {"htm": HTM, "htu": HTU, "jti": "R12-1"}
    cases.append(_case("R12", "missing embedded jwk rejected", "RFC 9449 §4.2",
                       "reject",
                       [_step(_signed(key, header, payload), "reject",
                              reason_contains="missing embedded jwk")]))

    header = {"typ": "JWT", "alg": "ES256", "jwk": public_jwk(key)}
    payload = {"htm": HTM, "htu": HTU, "jti": "R13-1"}
    cases.append(_case("R13", "typ other than dpop+jwt rejected", "RFC 9449 §4.2",
                       "reject",
                       [_step(_signed(key, header, payload), "reject",
                              reason_contains="bad typ")]))

    cases.append(_case("R14", "malformed JWT rejected", "RFC 9449 §4.3", "reject",
                       [_step("not.a.jwt", "reject", reason_contains="malformed")]))

    jwk = dict(public_jwk(key))
    jwk["kty"] = "oct"  # not an EC key; key rebuild must fail
    header = {"typ": "dpop+jwt", "alg": "ES256", "jwk": jwk}
    payload = {"htm": HTM, "htu": HTU, "iat": REF, "jti": "R15-1"}
    cases.append(_case("R15", "non-EC jwk rejected", "RFC 9449 §4.2", "reject",
                       [_step(_build_proof(header, payload, b"\x00" * 64), "reject",
                              expect_reason="INVALID_JWK")]))

    # ------------------------------------------------------- signaling + nonce
    proof = _valid(key, "T01")
    jkt = jwk_thumbprint(public_jwk(key))
    cases.append(_case("T01", "token response cnf.jkt matches proof key thumbprint",
                       "SEP-1932 § Obtaining / RFC 9449 §6", "signaling",
                       [_step(proof, "accept", expect_cnf_jkt=jkt)]))

    first = _valid(key, "N01")
    retry = _valid(key, "N01", nonce="srv-1", jti="N01-2")
    # Distinct jtis per step: the retry is a *new* proof carrying the
    # nonce (same jti would trip the shared per-case jti store as a
    # replay). R07 is the opposite: one proof, two steps, same jti.
    cases.append(_case("N01", "use_dpop_nonce retry flow: reject then accept with nonce",
                       "SEP-1932 § Server-Provided Nonces", "nonce",
                       [_step(first, "reject", expected_nonce="srv-1",
                              reason_contains="nonce mismatch"),
                        _step(retry, "accept", expected_nonce="srv-1")],
                       expected="flow"))
    return cases


def main():
    existing = None
    if os.path.exists(OUT):
        with open(OUT, encoding="utf-8") as f:
            existing = json.load(f)
    if existing and existing.get("keys", {}).get("es256"):
        key_jwk = existing["keys"]["es256"]
        key = private_key_from_jwk({k: v for k, v in key_jwk.items()
                                    if k != "note"})
        print("reusing committed test key")
    else:
        key = generate_key("ES256")
        print("generated fresh test key (first build)")

    key_jwk = dict(private_jwk(key))
    key_jwk["note"] = ("TEST KEY ONLY — generated for this fixture set, "
                       "never use in production")

    doc = {
        "format": "pydpop-conformance-vectors/1",
        "corpus": "RFC 9449 + SEP-1932 (DPoP Profile for MCP)",
        "reference_time": REF,
        "reference_time_iso": "2026-11-06T00:00:00Z",
        "evaluation": {
            "now": "verify every step with now = reference_time",
            "clock_skew": "use the step's clock_skew (300 unless stated)",
            "jti_store": "one fresh store per case, shared across its steps",
            "structure": "decode the proof; compare header/claims against "
                         "expect_header/expect_claims (nested dicts match "
                         "by subset)",
            "signaling": "expect_cnf_jkt must equal the RFC 7638 "
                         "thumbprint of the proof's embedded jwk",
            "expect_reason": "for reject steps, the VerificationFailure "
                             "member the verifier must return "
                             "(reason_contains is the human-readable "
                             "substring of the same failure)",
        },
        "keys": {"es256": key_jwk},
        "cases": build_cases(key),
    }
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=2, ensure_ascii=False)
        f.write("\n")
    print(f"wrote {OUT}: {len(doc['cases'])} cases")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
