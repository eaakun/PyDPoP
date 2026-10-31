# DPoP Conformance Results (RFC 9449 + SEP-1932)

pydpop's conformance corpus lives in `conformance/` (see
`conformance/README.md` for the runner and the corpus export other
implementations can adopt). This page records pydpop's own results
against that corpus, and maps the corpus to the SEP-1932 text it
implements.

## Results (2026-10-31, pydpop 0.2.1, branch `conformance-harness`)

**28 passed, 0 skipped, 0 failed out of 28 cases.**
Full per-case report: `conformance/conformance-report.json`.

| Family | Cases | Result |
| --- | --- | --- |
| Generation (proof structure, `ath`, `nonce`, `htu`) | G01–G05 | 5/5 |
| Accept (valid proofs, SEP `iat` window edges ±300 s) | A01–A06 | 6/6 |
| Reject (tampering, wrong claims, `iat` ±301 s, replay, bad algs) | R01–R15 | 15/15 |
| Token-endpoint signaling (`cnf.jkt` binding) | T01 | 1/1 |
| Nonce retry flow (`use_dpop_nonce` → retry with nonce) | N01 | 1/1 |

## SEP-1932 mapping

SEP-1932 (DPoP Profile for MCP, modelcontextprotocol#1932, draft)
adopts RFC 9449 without MCP-specific extensions, and tightens two
points into testable MUSTs. The corpus covers them directly:

- **§ Obtaining DPoP-Bound Access Tokens** — token requests carry a
  `DPoP` proof (RFC 9449 §5); binding and signaling via `cnf`/`jkt`
  and `token_type: DPoP` (§6). Covered by T01 plus the generation
  family.
- **§ Stateless DPoP Proof Replay Protection** — servers MUST reject
  proofs whose `iat` falls outside ±5 minutes. Covered by A04/A05
  (edges accept) and R04/R05 (one second past the edge rejects).
  Stateful replay via `jti` tracking is covered by R07.
- **§ Server-Provided Nonces** — on `use_dpop_nonce` the client MUST
  retry with the supplied nonce (tightened from RFC 9449's
  non-normative "expected"). Covered by N01.
- **Testing Plan items 1–6** (proof formatting, content digest,
  validation steps, 401 error handling, `iat` boundaries, algorithm
  support) map to the generation, accept, and reject families; the
  hybrid `ML-DSA-*-ES256` cases (G05, A06) cover algorithm support
  beyond ES256.

## What this is for

SEP-1932's own "Reference Implementation" section says links will be
added when implementations are available, and its Testing Plan says
test vectors will be provided in the reference implementation. This
corpus is that deliverable in pydpop's shape: a shared, versioned set
of cases any DPoP implementation for MCP can run, with pydpop's own
results published beside it. Other implementations can export the
corpus (`python conformance/run.py --dump-corpus`) and report
case-by-case compatibility against the same yardstick.
