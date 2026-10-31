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

`python conformance/run.py --dump-corpus` prints the corpus as JSON
(id, title, spec, category, expected accept/reject). Implement the
same runner interface against your own verifier and compare case by
case — that shared corpus is the point. Results for pydpop itself live
in `docs/conformance.md`.
