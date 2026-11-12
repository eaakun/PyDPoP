# Python DPoP Interoperability Profile (pydpop-profile/1)

Status: **v1 — published by pydpop as the deployment contract for
Python DPoP**. This document adopts RFC 9449 unmodified and tightens
only the deployment choices RFC 9449 leaves open. When Python
projects do DPoP, they should cite this profile instead of each
re-interpreting the RFC: the profile is the auditable contract a
deployment can be checked against.

Related: [SEP-1932](https://github.com/modelcontextprotocol/modelcontextprotocol/pull/1932)
(the DPoP Profile for MCP) tightens the same RFC for MCP servers
(iat ±5 min, nonce retry as MUST). This profile is the Python-side
companion: same RFC, same tightening philosophy, scoped to how a
Python resource server or client deploys DPoP with pydpop.

Normative language (MUST / SHOULD / MAY) follows RFC 2119. A
deployment that claims conformance to this profile MUST satisfy
every MUST in §3–§5.

## 1. Scope

This profile covers:

- stateless resource servers (no shared replay store) — §2;
- stateful deployments (a `ReplayStore` backs verification) — §4;
- the verification order every pydpop verifier implements — §3;
- interaction with RFC 8693 token exchange — §5;
- the failure modes of the in-memory replay store — §6.

Out of scope: key management for signing keys, token issuance
policy, authorization decisions, and any non-Python deployment.

## 2. Stateless resource-server minimum baseline

A resource server with **no** replay store cannot detect a replayed
proof. The profile therefore treats stateless operation as a
degraded mode with an explicit residual risk, not as an equivalent
alternative:

- `jti` tracking MAY be degraded to optional (no store configured),
  but the deployment MUST document that it runs without replay
  protection.
- The residual replay window equals the `iat` window. Without a
  store, a stolen proof is replayable for the whole window, so the
  window MUST be narrowed to the smallest value operations
  tolerate. pydpop's default `clock_skew` is 60 s; stateless
  deployments SHOULD use at most 60 s, and 30 s where clock sync
  (NTP) is reliable. The chosen window MUST be recorded in the
  deployment's configuration, not left implicit.
- The server SHOULD issue a nonce on first contact
  (`use_dpop_nonce`) so that a stolen proof cannot be replayed
  against a fresh challenge even inside the window.

### 2.1 Nonce as encrypted timestamp (specified, not yet implemented)

A stateless server can carry its state inside the nonce itself
instead of storing it. This construction is **specified here; it is
not implemented in pydpop yet** (no AEAD nonce code ships in this
release). An implementation of it MUST follow this construction:

- Nonce format: `v1.<base64url(nonce_bytes)>`, where
  `nonce_bytes = AES-256-GCM(key, iv, plaintext, aad)` with a fresh
  random 96-bit `iv` per nonce; `plaintext = issue_time_unix (8-byte
  big-endian) || server_id (UTF-8, length-prefixed)`; `aad =
  "pydpop-stateless-nonce-v1" || resource-server identifier`.
- Verification: decrypt (failure → `NONCE_MISMATCH`); check
  `|now - issue_time| ≤ nonce window` (recommended 300 s, matching
  SEP-1932's nonce lifetime); check `server_id` equals the server's
  own identifier. A nonce that decrypts but is outside the window
  or for another server is rejected.
- Key management: one 256-bit secret per deployment, stored like
  any other server secret (never committed, never shared across
  deployments). Rotation MUST keep the previous key valid for one
  nonce window so in-flight nonces keep verifying.

## 3. Fixed verification order (auditable contract)

Every pydpop verifier executes the checks in exactly this order.
The order is part of the profile: an auditor can read it off the
implementation and off this document and they must agree.

```
parse (malformed JWT)
  → header structure: typ == "dpop+jwt", alg supported, embedded jwk present
  → signature over the ASCII signing input
  → htm == request method, htu == request URI (normalized)
  → iat inside the acceptance window (|now - iat| ≤ clock_skew)
  → jti present
  → nonce (when expected_nonce is set)
  → ath == base64url(SHA-256(access token)) (when a token is bound)
  → check_and_record(jti, iat)   ← COMMIT POINT (last possibly-failing step)
  → return valid=True
```

### 3.1 jti consumption is a tightening

`check_and_record` runs last, so a `jti` is consumed **only when
full verification passes**: "jti consumed" ⇔ "proof accepted".
This is a tightening relative to the earlier pre-check order, not a
relaxation, for two reasons:

- **Precise semantics.** Under the old order, "jti consumed" did
  not imply "proof was accepted" — a proof could burn its `jti`
  and still be rejected. The new order makes the store's contents
  an exact record of accepted proofs.
- **No tampered-ath denial of service.** An attacker who intercepts
  a legitimate proof and tampers with `ath` cannot burn the
  victim's `jti`: the tampered proof fails signature (or `ath`)
  before the commit point, and the legitimate proof is still
  accepted afterwards. The attacker has no private key, so
  "failure does not consume" opens no replay window — a fresh
  forgery still fails the signature check.

Three preconditions hold simultaneously; if any is dropped, the
change becomes a relaxation:

1. **Commit point is last.** After `check_and_record` returns
   True there is no fallible path before `valid=True`. The code
   after the call is a straight return of the success result.
2. **Atomicity is a contract.** `ReplayStore.check_and_record`
   MUST be atomic: two concurrent verifications of the same proof
   resolve one-win-one-loss. This is a contract on the store
   implementer, not a suggestion (see §4).
3. **Nonce sits before the commit point.** A nonce failure does
   not consume the `jti`: nonce expiry is an expected retry path
   under RFC 9449, and burning the `jti` would force the client
   to mint a new proof for a retry the protocol explicitly allows.

## 4. Stateful deployment contract

### 4.1 ReplayStore atomicity (contract)

`ReplayStore.check_and_record(jti, iat) -> bool` MUST be atomic:
the `jti` is recorded if and only if it was not already present,
in a single indivisible step. Two concurrent verifications of the
same proof MUST resolve one-win-one-loss — exactly one returns
True. A store that records before the proof is fully accepted, or
that lets two concurrent calls both succeed, violates the contract
and voids the replay guarantee. `MemoryJtiStore` satisfies this
within one process (the check-and-set is one dict operation under
the GIL); multi-process or multi-instance deployments MUST use a
store with a real atomic primitive (e.g. Redis `SETNX`, a SQL
unique constraint with insert-if-absent).

### 4.2 TTL vs iat-window arithmetic

A `jti` entry MUST be retained at least until no proof carrying
that `iat` can still be accepted. A proof with issued-at `iat` is
acceptable while `now ≤ iat + clock_skew`, so retention MUST cover
the whole window after receipt:

```
TTL ≥ clock_skew + max clock drift between client and server
```

The profile recommends `TTL ≥ 2 × clock_skew` as the safe margin
(pydpop's defaults — TTL 600 s, `clock_skew` 60 s — satisfy this
with room). A store that evicts entries early re-opens the replay
window for exactly the evicted interval; a store that never evicts
grows without bound (see §6).

### 4.3 Fail-closed behavior

If the replay store is unavailable or returns an error,
verification MUST fail closed: the proof is rejected, never
accepted without recording. pydpop surfaces store errors to the
caller rather than converting them into acceptance — integrations
MUST treat any exception from the store as a rejection (HTTP 500
with no token honoured is fail-closed; a fallback that accepts
without a store is not).

## 5. RFC 8693 token-exchange boundary

When a DPoP-bound access token is presented as the subject token
of an RFC 8693 exchange, the sender constraint must survive the
exchange. The following rules bind the exchange endpoint and any
verifier of the exchanged token:

- The exchange endpoint MUST require a DPoP proof bound to the
  same key as the subject token's `cnf.jkt`. A request that
  presents a DPoP-bound subject token with a proof under a
  different key, or with no proof at all, MUST be rejected.
- The issued token MUST carry the same `cnf` (same `jkt`) as the
  subject token: the binding is preserved, not re-keyed. An
  exchanged token whose `cnf` is absent or differs from the
  subject token's `cnf` MUST be rejected by verifiers.
- A verifier of the exchanged token computes `ath` over the new
  (exchanged) token value, as usual; the `ath` check is what ties
  the presented proof to the exchanged token, and it MUST NOT be
  skipped on the grounds that the token was "already verified at
  exchange time".
- The exchange response SHOULD signal the preserved `cnf.jkt` so
  the client can confirm the binding carried over.

## 6. Memory replay-store failure modes (accurate)

The in-memory store (`MemoryJtiStore`) has exactly three failure
modes. None of them is a throughput cliff: there is no request-rate
threshold at which replay protection silently stops working. (An
earlier draft of this work cited a "17 req/s" figure; it is
withdrawn — no such threshold exists and it must not be cited.)

- **Multi-instance inconsistency.** Each instance holds its own
  store; the same `jti` can pass once per instance. This is a
  distributed-consistency problem and exists at any request rate.
  Multi-instance deployments MUST use a shared store (§4.1).
- **Unbounded memory growth.** `jti` records grow with the number
  of requests inside the retention window; without TTL hygiene the
  store grows until the process runs out of memory. `MemoryJtiStore`
  sweeps expired entries on every call and MUST be configured with
  a TTL (§4.2); operators MUST monitor its size.
- **Process-restart loss.** Recorded `jti`s vanish with the
  process, so replays inside the restart window are unprotected.
  Deployments that need continuity across restarts MUST use a
  persistent store.

## 7. Invariants harness (auditor entry point)

The security properties in §3 are executable, not aspirational.
Run them with:

```
python -m pytest tests/test_invariants.py -v
```

The harness checks, against `verify_proof_result` and a recording
`ReplayStore`:

1. No proof returns `valid=True` while its `jti` was not recorded
   by the store.
2. With a server-issued nonce required, any `valid=True` result
   implies a nonce the server issued inside its window.
3. `ath` failure and signature failure are distinguishable in the
   result object, and an `ath` failure does not consume the `jti`.

The full suite (`python -m pytest -q`) additionally runs the
agreement battery proving `verify_proof` and `verify_proof_result`
make identical decisions, and the 28-case conformance vectors
(`python conformance/run.py --vectors`, 28/28) against the same
verifier.

## 8. Compliance matrix

`conformance/compliance-matrix.json` is the machine-readable export
of the conformance corpus: per case, its RFC/SEP reference,
category, expected outcome, and (for rejections) the
`VerificationFailure` the verifier must return. Regenerate it with:

```
python conformance/run.py --vectors --matrix conformance/compliance-matrix.json
```

Other-language implementations can calibrate against
`conformance/vectors/vectors.json` (format
`pydpop-conformance-vectors/1`) and check their results against
the matrix.
