# DPoP Conformance Corpus (RFC 9449 + SEP-1932)

This directory is pydpop's bid to become the yardstick, not just a
library: a machine-readable corpus of conformance cases for DPoP
(RFC 9449) as profiled for MCP by SEP-1932, plus a runner that
executes the corpus against the local checkout.

## What it covers

- **Generation**: proof structure (`typ`, `alg`, embedded JWK), `ath`
  computation, `nonce` claim, `htu` normalization.
- **Accept**: valid proofs, matching `ath`/`nonce`, and the SEP-1932
  `iat` window edges (±300 s).
- **Reject**: tampered payloads, wrong `htm`/`htu`, `iat` outside the
  SEP window (±301 s), missing `jti`, replayed `jti`, `ath`/`nonce`
  mismatch, `alg: none`, `alg: HS256`, missing JWK, wrong `typ`,
  malformed JWTs, non-EC keys.
- **Signaling**: token-response `cnf.jkt` bound to the proof key
  (SEP-1932 § Obtaining, RFC 9449 §6).
- **Nonce flow**: `use_dpop_nonce` rejection then retry-with-nonce
  acceptance (SEP-1932 tightens RFC 9449's "expected" retry to MUST).

## Run it

From the repo root, with the dev venv:

```
python conformance/run.py
```

It prints a per-case table and writes
`conformance/conformance-report.json`. Exit code is 0 only when every
runnable case passes; cases that cannot run here (e.g. ML-DSA
unavailable) report SKIP, not FAIL.

## For other implementations

The canonical export is `vectors/vectors.json` — the full fixture
set, not just case metadata. One file, 28 cases, each carrying the
actual proof JWT strings, the verifier inputs, and the expected
outcome. Run it against your own implementation and compare case by
case; that shared yardstick is the point.

File layout:

- `format`: `pydpop-conformance-vectors/1`.
- `reference_time` / `reference_time_iso`: the fixed "now" every
  step is evaluated at (2026-11-06T00:00:00Z). `iat` edges are exact
  against it: ±300 s accepts, ±301 s rejects.
- `keys.es256`: the single P-256 test key all ES256 proofs are
  signed with (private part included, labelled TEST KEY ONLY).
  Hybrid proofs (G05, A06) are self-contained via their embedded
  JWK and use a fresh composite key per generation.
- `cases[]`: `id`, `title`, `spec`, `category`, `expected`, and
  `steps[]`. Every step is self-contained: `proof`, `htm`, `htu`,
  `clock_skew`, `expect` (`accept` / `reject` / `structure`), plus
  `access_token` / `expected_nonce` / `reason_contains` /
  `expect_header` / `expect_claims` / `expect_cnf_jkt` where the
  case needs them.

Evaluation rules (also recorded in the file's `evaluation` block):

- Verify every step with `now = reference_time` and the step's
  `clock_skew`.
- One fresh `jti` store per case, shared across its steps. R07
  (replay) and N01 (nonce retry) depend on this: R07 is one proof
  verified twice (accept, then reject as replayed); N01 is reject
  without the nonce, then accept with it.
- `structure` steps: decode the proof and compare header/claims
  against `expect_header` / `expect_claims` (nested dicts match by
  subset).
- `signaling` (T01): `expect_cnf_jkt` must equal the RFC 7638
  thumbprint of the proof's embedded JWK.
- `reason_contains` is the substring of the verifier's rejection
  reason (e.g. `bad signature`, `iat outside acceptable window`).

Regenerate the file with `python conformance/generate_vectors.py`
(it reuses the committed test key). ECDSA signatures use a random
nonce, so regeneration produces equivalent vectors — identical
claims, keys, and expected outcomes — with different signature
bytes; the check that matters is `python conformance/run.py
--vectors` (28/28 against pydpop's own verifier). Results for
pydpop itself live in `docs/conformance.md`.

The older metadata-only export is still available:
`python conformance/run.py --dump-corpus` prints id/title/spec/
category/expected per case.
