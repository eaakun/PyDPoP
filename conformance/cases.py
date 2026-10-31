"""DPoP conformance corpus: RFC 9449 core + SEP-1932 (DPoP Profile for MCP).

Each case is a small dict:

    id:       stable id, e.g. "R05"
    title:    what it checks
    spec:     normative reference, e.g. "SEP-1932 § Stateless Replay" or
              "RFC 9449 §4.3"
    category: "generation" | "accept" | "reject" | "signaling" | "nonce"
    run:      callable(ctx) -> None; raises AssertionError on failure.
              A case that must be rejected passes only if verify_proof
              raises DPoPError. Cases that cannot run in this environment
              (e.g. ML-DSA unavailable) raise SkipCase.

The corpus is deliberately implementation-agnostic in shape: cases.json
(see run.py --dump-corpus) exports id/title/spec/category/expected so
another implementation can implement the same runner interface and
compare results case by case. That export is the point of this
directory: pydpop is not just asserting about itself, it is publishing
the yardstick.
"""

import base64
import hashlib
import hmac as hmac_mod
import json
import time

from pydpop.composite import mldsa_available
from pydpop.jwk import (
    CompositeKey,
    b64u_decode,
    b64u_encode,
    generate_key,
    jwk_thumbprint,
    public_jwk,
)
from pydpop.proof import generate_proof, normalize_htu
from pydpop.verifier import DPoPError, MemoryJtiStore, verify_proof


class SkipCase(Exception):
    """Raised when a case cannot run in this environment."""


NOW = int(time.time())
HTM = "POST"
HTU = "https://mcp.example.com/token"


def _b64u_json(obj):
    return b64u_encode(json.dumps(obj, separators=(",", ":")).encode())


def _ec_sign_raw(private_key, signing_input):
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import (
        decode_dss_signature,
    )

    der = private_key.sign(signing_input, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der)
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def _build_proof(header, payload, raw_sig=b""):
    signing_input = f"{_b64u_json(header)}.{_b64u_json(payload)}"
    return f"{signing_input}.{b64u_encode(raw_sig)}"


def _valid_proof(key, **kw):
    kw.setdefault("htm", HTM)
    kw.setdefault("htu", HTU)
    kw.setdefault("iat", NOW)
    return generate_proof(private_key=key, **kw)


def _expect_reject(fn, match=None):
    try:
        fn()
    except DPoPError as exc:
        if match is not None and match not in str(exc):
            raise AssertionError(f"rejected, but wrong reason: {exc}")
        return
    raise AssertionError("expected DPoPError, proof was accepted")


def _decode_claims(proof):
    _, payload_b64, _ = proof.split(".")
    return json.loads(b64u_decode(payload_b64))


def _decode_header(proof):
    head_b64, _, _ = proof.split(".")
    return json.loads(b64u_decode(head_b64))


# ---------------------------------------------------------------- generation
def g01_proof_structure(ctx):
    proof = _valid_proof(ctx["key"])
    head = _decode_header(proof)
    claims = _decode_claims(proof)
    assert head["typ"] == "dpop+jwt", head
    assert head["alg"] == "ES256", head
    jwk = head["jwk"]
    assert jwk["kty"] == "EC" and jwk["crv"] == "P-256", jwk
    assert claims["htm"] == "POST", claims
    assert claims["htu"] == HTU, claims
    assert isinstance(claims["iat"], int) and claims["jti"], claims


def g02_ath_claim(ctx):
    token = "test-access-token-123"
    proof = _valid_proof(ctx["key"], access_token=token)
    claims = _decode_claims(proof)
    expected = b64u_encode(hashlib.sha256(token.encode()).digest())
    assert claims["ath"] == expected, claims


def g03_nonce_claim(ctx):
    proof = _valid_proof(ctx["key"], nonce="server-nonce-1")
    assert _decode_claims(proof)["nonce"] == "server-nonce-1"


def g04_htu_normalized(ctx):
    proof = _valid_proof(
        ctx["key"], htu="https://mcp.example.com/token?code=abc#frag"
    )
    assert _decode_claims(proof)["htu"] == "https://mcp.example.com/token"
    assert normalize_htu("https://mcp.example.com/token?code=abc#frag") == (
        "https://mcp.example.com/token"
    )


def g05_hybrid_structure(ctx):
    if not mldsa_available():
        raise SkipCase("ML-DSA backend unavailable")
    key = CompositeKey.generate("ML-DSA-44-ES256")
    proof = _valid_proof(key)
    head = _decode_header(proof)
    assert head["alg"] == "ML-DSA-44-ES256", head
    assert head["jwk"]["alg"] == "ML-DSA-44-ES256", head


# -------------------------------------------------------------------- accept
def a01_valid_proof_accepts(ctx):
    out = verify_proof(
        proof=_valid_proof(ctx["key"]), htm=HTM, htu=HTU, now=NOW
    )
    assert out["jwk_thumbprint"], out


def a02_matching_ath_accepts(ctx):
    token = "test-access-token-123"
    verify_proof(
        proof=_valid_proof(ctx["key"], access_token=token),
        htm=HTM,
        htu=HTU,
        access_token=token,
        now=NOW,
    )


def a03_matching_nonce_accepts(ctx):
    verify_proof(
        proof=_valid_proof(ctx["key"], nonce="server-nonce-1"),
        htm=HTM,
        htu=HTU,
        expected_nonce="server-nonce-1",
        now=NOW,
    )


def a04_iat_minus_300_accepts(ctx):
    # SEP-1932: servers MUST reject iat outside ±5 minutes; the edge
    # itself is inside the window.
    verify_proof(
        proof=_valid_proof(ctx["key"], iat=NOW - 300),
        htm=HTM,
        htu=HTU,
        clock_skew=300,
        now=NOW,
    )


def a05_iat_plus_300_accepts(ctx):
    verify_proof(
        proof=_valid_proof(ctx["key"], iat=NOW + 300),
        htm=HTM,
        htu=HTU,
        clock_skew=300,
        now=NOW,
    )


def a06_hybrid_proof_accepts(ctx):
    if not mldsa_available():
        raise SkipCase("ML-DSA backend unavailable")
    key = CompositeKey.generate("ML-DSA-44-ES256")
    verify_proof(proof=_valid_proof(key), htm=HTM, htu=HTU, now=NOW)


# -------------------------------------------------------------------- reject
def r01_tampered_payload_rejects(ctx):
    proof = _valid_proof(ctx["key"])
    head_b64, _, sig_b64 = proof.split(".")
    claims = _decode_claims(proof)
    claims["htm"] = "GET"  # tamper without re-signing
    forged = f"{head_b64}.{_b64u_json(claims)}.{sig_b64}"
    _expect_reject(
        lambda: verify_proof(proof=forged, htm="GET", htu=HTU, now=NOW),
        match="bad signature",
    )


def r02_wrong_htm_rejects(ctx):
    proof = _valid_proof(ctx["key"], htm="POST")
    _expect_reject(
        lambda: verify_proof(proof=proof, htm="GET", htu=HTU, now=NOW),
        match="htm mismatch",
    )


def r03_wrong_htu_rejects(ctx):
    proof = _valid_proof(ctx["key"], htu="https://mcp.example.com/token")
    _expect_reject(
        lambda: verify_proof(
            proof=proof, htm=HTM, htu="https://mcp.example.com/other",
            now=NOW,
        ),
        match="htu mismatch",
    )


def r04_iat_minus_301_rejects(ctx):
    _expect_reject(
        lambda: verify_proof(
            proof=_valid_proof(ctx["key"], iat=NOW - 301),
            htm=HTM, htu=HTU, clock_skew=300, now=NOW,
        ),
        match="iat outside acceptable window",
    )


def r05_iat_plus_301_rejects(ctx):
    _expect_reject(
        lambda: verify_proof(
            proof=_valid_proof(ctx["key"], iat=NOW + 301),
            htm=HTM, htu=HTU, clock_skew=300, now=NOW,
        ),
        match="iat outside acceptable window",
    )


def r06_missing_jti_rejects(ctx):
    key = ctx["key"]
    header = {"typ": "dpop+jwt", "alg": "ES256", "jwk": public_jwk(key)}
    payload = {"htm": HTM, "htu": HTU, "iat": NOW}  # no jti
    signing_input = f"{_b64u_json(header)}.{_b64u_json(payload)}".encode()
    proof = f"{signing_input.decode()}.{b64u_encode(_ec_sign_raw(key, signing_input))}"
    _expect_reject(
        lambda: verify_proof(proof=proof, htm=HTM, htu=HTU, now=NOW),
        match="missing jti",
    )


def r07_replayed_jti_rejects(ctx):
    store = MemoryJtiStore()
    proof = _valid_proof(ctx["key"])
    verify_proof(proof=proof, htm=HTM, htu=HTU, jti_store=store, now=NOW)
    _expect_reject(
        lambda: verify_proof(
            proof=proof, htm=HTM, htu=HTU, jti_store=store, now=NOW
        ),
        match="replayed jti",
    )


def r08_ath_mismatch_rejects(ctx):
    proof = _valid_proof(ctx["key"], access_token="token-A")
    _expect_reject(
        lambda: verify_proof(
            proof=proof, htm=HTM, htu=HTU, access_token="token-B",
            now=NOW,
        ),
        match="ath mismatch",
    )


def r09_nonce_mismatch_rejects(ctx):
    proof = _valid_proof(ctx["key"], nonce="nonce-A")
    _expect_reject(
        lambda: verify_proof(
            proof=proof, htm=HTM, htu=HTU, expected_nonce="nonce-B",
            now=NOW,
        ),
        match="nonce mismatch",
    )


def r10_alg_none_rejects(ctx):
    key = ctx["key"]
    header = {"typ": "dpop+jwt", "alg": "none", "jwk": public_jwk(key)}
    payload = {"htm": HTM, "htu": HTU, "iat": NOW, "jti": "x"}
    proof = _build_proof(header, payload, b"")
    _expect_reject(
        lambda: verify_proof(proof=proof, htm=HTM, htu=HTU, now=NOW),
        match="unsupported alg",
    )


def r11_alg_hs256_rejects(ctx):
    key = ctx["key"]
    header = {"typ": "dpop+jwt", "alg": "HS256", "jwk": public_jwk(key)}
    payload = {"htm": HTM, "htu": HTU, "iat": NOW, "jti": "x"}
    sig = hmac_mod.new(b"secret", b"whatever", hashlib.sha256).digest()
    proof = _build_proof(header, payload, sig)
    _expect_reject(
        lambda: verify_proof(proof=proof, htm=HTM, htu=HTU, now=NOW),
        match="unsupported alg",
    )


def r12_missing_jwk_rejects(ctx):
    key = ctx["key"]
    header = {"typ": "dpop+jwt", "alg": "ES256"}  # no jwk
    payload = {"htm": HTM, "htu": HTU, "iat": NOW, "jti": "x"}
    signing_input = f"{_b64u_json(header)}.{_b64u_json(payload)}".encode()
    proof = f"{signing_input.decode()}.{b64u_encode(_ec_sign_raw(key, signing_input))}"
    _expect_reject(
        lambda: verify_proof(proof=proof, htm=HTM, htu=HTU, now=NOW),
        match="missing embedded jwk",
    )


def r13_wrong_typ_rejects(ctx):
    key = ctx["key"]
    header = {"typ": "JWT", "alg": "ES256", "jwk": public_jwk(key)}
    payload = {"htm": HTM, "htu": HTU, "iat": NOW, "jti": "x"}
    signing_input = f"{_b64u_json(header)}.{_b64u_json(payload)}".encode()
    proof = f"{signing_input.decode()}.{b64u_encode(_ec_sign_raw(key, signing_input))}"
    _expect_reject(
        lambda: verify_proof(proof=proof, htm=HTM, htu=HTU, now=NOW),
        match="bad typ",
    )


def r14_malformed_jwt_rejects(ctx):
    _expect_reject(
        lambda: verify_proof(proof="not.a.jwt", htm=HTM, htu=HTU, now=NOW),
        match="malformed",
    )


def r15_wrong_kty_rejects(ctx):
    key = ctx["key"]
    jwk = dict(public_jwk(key))
    jwk["kty"] = "oct"  # not an EC key; key rebuild must fail
    header = {"typ": "dpop+jwt", "alg": "ES256", "jwk": jwk}
    payload = {"htm": HTM, "htu": HTU, "iat": NOW, "jti": "x"}
    proof = _build_proof(header, payload, b"\x00" * 64)
    _expect_reject(lambda: verify_proof(proof=proof, htm=HTM, htu=HTU, now=NOW))


# ------------------------------------------------------- signaling + nonce
def t01_cnf_jkt_binding(ctx):
    # SEP-1932 § Obtaining: token_type DPoP + cnf.jkt bound to the
    # proof key. The binding is checkable without a live AS: the jkt
    # in a token response must equal the thumbprint of the key in the
    # proof header.
    key = ctx["key"]
    proof = _valid_proof(key)
    head = _decode_header(proof)
    token_response = {
        "token_type": "DPoP",
        "cnf": {"jkt": jwk_thumbprint(head["jwk"])},
    }
    assert token_response["token_type"] == "DPoP"
    assert token_response["cnf"]["jkt"] == jwk_thumbprint(public_jwk(key))
    out = verify_proof(proof=proof, htm=HTM, htu=HTU, now=NOW)
    assert out["jwk_thumbprint"] == token_response["cnf"]["jkt"]


def n01_nonce_retry_flow(ctx):
    # SEP-1932 § Server-Provided Nonces: on use_dpop_nonce the client
    # MUST retry with the supplied nonce. Modelled at proof level: a
    # proof without the demanded nonce is rejected; the retried proof
    # carrying it verifies.
    first = _valid_proof(ctx["key"])
    _expect_reject(
        lambda: verify_proof(
            proof=first, htm=HTM, htu=HTU, expected_nonce="srv-1",
            now=NOW,
        ),
        match="nonce mismatch",
    )
    retry = _valid_proof(ctx["key"], nonce="srv-1")
    verify_proof(
        proof=retry, htm=HTM, htu=HTU, expected_nonce="srv-1", now=NOW
    )


CASES = [
    ("G01", "proof carries typ dpop+jwt, alg ES256, EC P-256 jwk",
     "RFC 9449 §4.2", "generation", g01_proof_structure),
    ("G02", "ath equals base64url(SHA-256(access token))",
     "RFC 9449 §4.3", "generation", g02_ath_claim),
    ("G03", "nonce claim present when server nonce supplied",
     "RFC 9449 §4.3", "generation", g03_nonce_claim),
    ("G04", "htu strips query and fragment",
     "RFC 9449 §4.3", "generation", g04_htu_normalized),
    ("G05", "hybrid proof carries ML-DSA alg in header and jwk",
     "draft-ietf-jose-pq-composite-sigs-05", "generation", g05_hybrid_structure),
    ("A01", "valid proof verifies", "RFC 9449 §4.3", "accept", a01_valid_proof_accepts),
    ("A02", "proof with matching ath verifies", "RFC 9449 §4.3", "accept", a02_matching_ath_accepts),
    ("A03", "proof with matching nonce verifies", "RFC 9449 §8/§9", "accept", a03_matching_nonce_accepts),
    ("A04", "iat at -300s accepts under SEP window", "SEP-1932 § Stateless Replay", "accept", a04_iat_minus_300_accepts),
    ("A05", "iat at +300s accepts under SEP window", "SEP-1932 § Stateless Replay", "accept", a05_iat_plus_300_accepts),
    ("A06", "hybrid proof verifies", "draft-ietf-jose-pq-composite-sigs-05", "accept", a06_hybrid_proof_accepts),
    ("R01", "tampered payload rejected (bad signature)", "RFC 9449 §4.3", "reject", r01_tampered_payload_rejects),
    ("R02", "wrong htm rejected", "RFC 9449 §4.3", "reject", r02_wrong_htm_rejects),
    ("R03", "wrong htu rejected", "RFC 9449 §4.3", "reject", r03_wrong_htu_rejects),
    ("R04", "iat at -301s rejected under SEP window", "SEP-1932 § Stateless Replay", "reject", r04_iat_minus_301_rejects),
    ("R05", "iat at +301s rejected under SEP window", "SEP-1932 § Stateless Replay", "reject", r05_iat_plus_301_rejects),
    ("R06", "missing jti rejected", "RFC 9449 §4.3", "reject", r06_missing_jti_rejects),
    ("R07", "replayed jti rejected by stateful store", "RFC 9449 §11.1", "reject", r07_replayed_jti_rejects),
    ("R08", "ath mismatch rejected", "RFC 9449 §4.3", "reject", r08_ath_mismatch_rejects),
    ("R09", "nonce mismatch rejected", "RFC 9449 §8/§9", "reject", r09_nonce_mismatch_rejects),
    ("R10", "alg none rejected", "RFC 9449 §4.2", "reject", r10_alg_none_rejects),
    ("R11", "alg HS256 rejected", "RFC 9449 §4.2", "reject", r11_alg_hs256_rejects),
    ("R12", "missing embedded jwk rejected", "RFC 9449 §4.2", "reject", r12_missing_jwk_rejects),
    ("R13", "typ other than dpop+jwt rejected", "RFC 9449 §4.2", "reject", r13_wrong_typ_rejects),
    ("R14", "malformed JWT rejected", "RFC 9449 §4.3", "reject", r14_malformed_jwt_rejects),
    ("R15", "non-EC jwk rejected", "RFC 9449 §4.2", "reject", r15_wrong_kty_rejects),
    ("T01", "token response cnf.jkt matches proof key thumbprint",
     "SEP-1932 § Obtaining / RFC 9449 §6", "signaling", t01_cnf_jkt_binding),
    ("N01", "use_dpop_nonce retry flow: reject then accept with nonce",
     "SEP-1932 § Server-Provided Nonces", "nonce", n01_nonce_retry_flow),
]


def make_ctx():
    return {"key": generate_key("ES256")}
