# CACHED_BINDING — UNREVIEWED PROPOSAL — NOT FOR PRODUCTION

> **Status: unreviewed proposal. Not on the roadmap, not a default,
> not a recommended path.** This document exists so the idea is
> recorded with its risks attached, not so it can be built from.
> No code in pydpop implements it. It must not be implemented until
> the threat analysis in §3 is written and passes review.

## 1. The idea (as proposed)

A `VerificationPolicy` option under which, after a (`jkt`, `ath`,
`htm`, `htu`) binding is fully verified once, the binding's
validity is cached for a short window and subsequent requests skip
the full JWT verification, presenting only a reference to the cached
binding.

## 2. Why it is demoted

Skipping full JWT verification is a security-boundary change, not a
performance feature. A poisoned cache entry discards the whole
defence: a cached "valid" binding would be honoured without ever
re-checking the signature. Presenting it as a policy enum value
would let a caller believe they had made a security decision by
picking an option, when in fact they would have delegated the
decision to a cache. The correct shape for this idea is a threat
analysis first, a decision second, code last — and the analysis
does not exist yet.

## 3. Threat analysis required before any reconsideration

The analysis must answer all four questions below, in writing,
with a named reviewer. A partial answer is not an answer.

### 3.1 Cache-key integrity

Is (`jkt`, `ath`, `htm`, `htu`) enough to uniquely identify an
already-verified binding? The entry MUST be bound to the proof's
cryptographic digest, not to declared fields alone: two different
proofs can declare the same (`jkt`, `ath`, `htm`, `htu`) while
differing in signature validity, `iat`, `nonce`, or `jti`, and a
key built from declarations alone could let a second, unverified
proof ride on the first proof's cache entry. The analysis must show
the exact key construction and prove that no two distinct proofs
can collide on it — or concede that the cache must be keyed by the
proof digest itself, which largely defeats the purpose.

### 3.2 Write entry

Is the cache in-process or shared? If shared, can one compromised
node pollute the cache for other nodes? If the answer is yes, the
feature can only ever be a single-instance optimization, and the
documentation must say so. The analysis must also state who may
write (only the verifier, after a full verification — never the
request path) and what happens on a write race.

### 3.3 Invalidation semantics

Each of the following MUST invalidate an entry; the entry must
carry enough freshness proof to enforce that, not rely on TTL
guesswork:

- `iat` window expiry (the underlying proof's acceptance window
  closes);
- nonce rotation (a new server nonce voids bindings verified under
  the old one);
- token revocation (if the deployment has a revocation mechanism,
  a revoked token voids its bindings immediately);
- key rotation (the bound key is rotated or revoked).

An entry that outlives any of these is a live bypass.

### 3.4 Conservative boundary

Even if built, the cache may hold **only** "cryptographic binding
validity" — never an authorization decision. A cache hit MUST still
re-check token revocation status (if the deployment has a
revocation mechanism); only the signature verification and the `ath`
recomputation may be skipped. Any design that caches "this request
is authorized" is out of scope and must be rejected.

## 4. Decision log

- 2026-11-12: demoted from "VerificationPolicy option" to
  "unreviewed proposal" by the project owner. Rationale: every
  optimization must first prove it does not lower worst-case
  guarantees; this one had not.
