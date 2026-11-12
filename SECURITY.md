# Security Policy

pydpop is security-sensitive software: it mints and verifies the proofs that
keep OAuth access tokens sender-constrained. We take reports seriously.

## Reporting a vulnerability

**Do not open a public issue.** Email the maintainer directly:

- eaakun@gmail.com — please include "pydpop security" in the subject.

Include: pydpop version, a minimal reproduction, and the impact you see.
We aim to acknowledge within 48 hours and to ship a fix promptly; reporters
are credited in the release notes unless they prefer otherwise.

## Scope

- `src/pydpop/`: proof generation/verification, composite (PQC) signatures,
  JWK handling, integrations.
- Out of scope: the demo Hugging Face Space (report HF abuse via their own
  channels), vulnerabilities in `cryptography` itself (report upstream).

## Threat model

What pydpop defends against — and what it does not. Read this before
relying on DPoP in production; a security library that over-promises
is worse than one that says plainly where its protection ends.

### Defends

- **Stolen bearer tokens replayed from elsewhere** (the core RFC 9449
  property): a proof is bound to a key the attacker does not hold, so a
  token lifted off the wire or out of a log is useless without its
  holder's private key.
- **Forged proofs**: signature verification must pass — ES256, or both
  components of a hybrid proof — before any claim is trusted.
- **Replayed proofs**: `jti` replay detection via a `ReplayStore`
  (`MemoryJtiStore` in-process by default; plug in Redis/DB for
  multi-instance deployments).
- **Token substitution**: the `ath` claim binds the proof to the exact
  access token presented.
- **Stale or future-dated proofs**: the `iat` window check (default
  ±60 s, configurable via `clock_skew`).
- **Algorithm confusion**: the verifier accepts only `ES256` and the
  two ML-DSA hybrid algs; `HS256` / `none` / RSA are rejected outright,
  and an embedded JWK carrying private material (`d` / `priv`) is
  rejected.

### Does NOT defend

- **Key leakage**: if the client's private key is stolen, the attacker
  can mint valid proofs. Protect keys (OS keychain, HSM, file
  permissions). pydpop never transmits private material, but it cannot
  protect a key you leak.
- **Severe clock skew**: the `iat` window tolerates small drift only. A
  clock off by minutes breaks verification (fail-closed); raising
  `clock_skew` to compensate widens the replay window.
- **Missing TLS**: DPoP makes a stolen token useless, but it does not
  encrypt traffic. Metadata, non-DPoP credentials, and everything else
  on the wire still need TLS.
- **Token issuance policy**: DPoP constrains how a token is
  *presented*, not who the authorization server issues tokens *to*.
  If the AS mints a token for the attacker, sender binding changes
  nothing — the proof key travels with him.
- **Server-side authorization**: a valid proof says "this request
  comes from the key holder", not "this key holder is allowed to do
  this". Authorization is the application's job.
- **Replay-store availability**: the default `MemoryJtiStore` is
  process-local — it does not survive restarts and does not share
  across workers. In multi-instance deployments use a shared store,
  or accept a replay window after a restart.

Failure modes are auditable, not silent: `verify_proof()` raises
`DPoPError` with a machine-readable `reason`
(`VerificationFailure`); `verify_proof_result()` returns the same
information as a frozen `DPoPVerificationResult` without raising,
so a gateway can answer `NONCE_MISMATCH` with 401 + a fresh nonce
and `BAD_SIGNATURE` with 400 instead of collapsing every failure
into one opaque "invalid".

## Hardening already in place

- Fuzzing in CI (malformed JWT/JWK inputs must raise `DPoPError`, never crash).
- Constant-time `ath` comparison; `htu` normalization per RFC 3986.
- Hybrid proofs require **both** component signatures (draft-ietf-jose-pq-composite-sigs);
  a broken classical component alone cannot forge.
- No private key material ever leaves the client: embedded proof JWKs are
  rejected server-side if they contain `d`/`priv`.
