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

## Hardening already in place

- Fuzzing in CI (malformed JWT/JWK inputs must raise `DPoPError`, never crash).
- Constant-time `ath` comparison; `htu` normalization per RFC 3986.
- Hybrid proofs require **both** component signatures (draft-ietf-jose-pq-composite-sigs);
  a broken classical component alone cannot forge.
- No private key material ever leaves the client: embedded proof JWKs are
  rejected server-side if they contain `d`/`priv`.
