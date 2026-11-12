# Changelog

All notable changes to pydpop. Format follows [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

### Security

- [security] `verify_proof()` failures now carry a machine-readable
  reason: `DPoPError.reason` is a `VerificationFailure` enum
  (`MALFORMED_PROOF`, `BAD_TYP`, `UNSUPPORTED_ALG`, `INVALID_JWK`,
  `BAD_SIGNATURE`, `HTM_MISMATCH`, `HTU_MISMATCH`, `EXPIRED_IAT`,
  `MISSING_JTI`, `REPLAY_DETECTED`, `NONCE_MISMATCH`, `ATH_MISMATCH`).
  Accept/reject decisions are unchanged. New non-raising
  `verify_proof_result()` returns a frozen `DPoPVerificationResult`
  with the same reason, so a gateway can answer `NONCE_MISMATCH`
  with 401 + a fresh nonce instead of collapsing every failure into
  one opaque "invalid".
- [security] `ReplayStore` protocol (`check_and_record(jti, iat) ->
  bool`, atomic) formalizes the replay-cache contract;
  `MemoryJtiStore` implements it (also importable as
  `MemoryReplayStore`). The legacy `jti_store` parameter and
  `seen()`/`add()` keep working.
- [security] `SECURITY.md` now states an explicit threat model: what
  pydpop defends (stolen/replayed bearer tokens, forged proofs, token
  substitution, stale proofs, algorithm confusion) and what it does
  not (key leakage, severe clock skew, missing TLS, issuance policy,
  authorization, process-local replay cache).
- [security] `jti` is now consumed only at the verification commit
  point: `check_and_record` runs last, after signature, `htm`/`htu`,
  `iat` window, nonce and `ath` — a proof that fails any earlier
  check never burns its `jti`. This is a tightening: "jti consumed"
  now means exactly "proof accepted", and an attacker who tampers
  with `ath` on an intercepted proof can no longer deny the
  legitimate client its `jti`. Accept/reject decisions are
  otherwise unchanged (the 28-case conformance vectors pass
  unmodified). `ReplayStore.check_and_record` atomicity is now a
  documented contract, not a suggestion
  (see `docs/python-dpop-profile.md` §3–§4).

### Changed

- Composite signatures now follow draft-ietf-jose-pq-composite-sigs-05 §4.2
  component encodings: ECDSA half is DER `Ecdsa-Sig-Value` (non-canonical DER
  rejected at verify), public key is X9.62 uncompressed `0x04||x||y` (65 B),
  private key is RFC 5915 DER `ECPrivateKey`. `M′` construction, labels and
  component order are unchanged. Composite proofs grow by ~11 base64 chars;
  the 8 KB header conclusion for `ML-DSA-44-ES256` is unaffected.

### Added

- `pydpop.integrations.flask.DPoPVerifier`: Flask-native DPoP verification
  (`pip install pydpop[flask]`) — before-request hook, `g.dpop`, `@dpop_exempt`.
- `pydpop.integrations.starlette.DPoPMiddleware`: pure-ASGI DPoP middleware
  (`pip install pydpop[starlette]`) — `scope["dpop"]`, works for any ASGI app.
- `pydpop.integrations.aiohttp.DPoPClientSession`: async DPoP client
  (`pip install pydpop[aiohttp]`) — fresh proof per request, nonce auto-retry.
- `pydpop.integrations.django.DPoPMiddleware`: Django-native DPoP verification
  (`pip install pydpop[django]`) — fail-closed 401s, shared `jti` replay cache,
  `ath` binding, `@dpop_exempt` for public views.
- `pydpop.integrations.fastapi.DPoPVerifier`: FastAPI-native DPoP verification
  as a Dependency (`pip install pydpop[fastapi]`) — 401 fail-closed, shared
  `jti` replay cache, `ath` binding from `Authorization: DPoP`.
- `docs/atproto.md`: DPoP recipe for ATProto/Bluesky (DPoP is mandatory there;
  the ecosystem hand-rolls it — this is the drop-in layer).
- `pydpop.integrations.requests.DPoPAuth`: DPoP for `requests`
  (`pip install pydpop[requests]`) — mirrors the httpx integration.
- `dpop` CLI (`keygen`/`mint`/`verify`/`thumbprint`) for debugging flows
  without writing a script.
- `private_key_from_jwk()` / `private_jwk()`: client-side key persistence
  round-trip (save to disk, load back).
- `docs/python-dpop-profile.md`: the Python DPoP Interoperability
  Profile (pydpop-profile/1) — stateless/stateful deployment
  contracts, the fixed verification order as an auditable contract,
  the RFC 8693 token-exchange boundary, the AEAD-nonce construction
  (specified, not implemented), and the accurate memory-store
  failure modes (multi-instance inconsistency, unbounded growth,
  restart loss — no request-rate threshold).
- `tests/test_invariants.py`: executable invariants harness
  (`pytest tests/test_invariants.py -v`) — no valid proof without a
  recorded `jti`, server-issued nonce required for validity, `ath`
  vs signature failures distinguishable and `ath` failure never
  consumes the `jti`.
- Cross-language conformance oracle: the 28-case vectors from the
  conformance corpus now live in `conformance/` on main-line
  branches, reject steps carry a machine-readable `expect_reason`
  (`VerificationFailure` member), `python conformance/run.py
  --vectors --matrix conformance/compliance-matrix.json` exports the
  machine-readable compliance matrix, and `dpop serve --conformance`
  exposes `/health`, `/vectors`, `/matrix` and `/verify` over HTTP
  for other languages' interop tests.
- `docs/proposals/cached-binding.md`: CACHED_BINDING demoted to an
  unreviewed proposal (NOT FOR PRODUCTION) — the four threat-analysis
  questions it must answer before any reconsideration are spelled out
  there. It is not implemented and not on the roadmap.
- Supply chain (UNTESTED until the next release):
  `.github/workflows/supply-chain.yml` produces SLSA L3 provenance,
  Sigstore keyless signatures and a CycloneDX SBOM on each published
  release; `dpop audit-release` consistency-checks a release
  directory (tag vs pyproject version, provenance subjects vs files,
  provenance builder/commit, SBOM coverage of pyproject deps).
  The DPoP-style release proof was withdrawn — no custom artifact
  binding is built anywhere; see `docs/supply-chain.md`.
- `SECURITY.md`: vulnerability reporting policy.
- README and `docs/integrations.md` now lead with the two 5-minute
  paths (FastAPI resource server, httpx client) before RFC clause
  detail.

## [0.2.1] — 2026-10-11

### Added

- `pydpop.integrations.httpx.DPoPAuth`: drop-in DPoP for httpx (`pip install pydpop[httpx]`).
  Signs every request with a fresh proof, caches `DPoP-Nonce`, single automatic
  retry on `use_dpop_nonce` (RFC 9449 §4.3). Works with sync and async clients.
- `docs/integrations.md`, `llms.txt` (AI-assistant-readable package summary).

### Changed

- PyPI description/keywords and README FAQ tuned for search (GEO/SEO): PQC terms
  now visible where developers look.

## [0.2.0] — 2026-10-11

### Added

- PQ/T hybrid DPoP proofs: `ML-DSA-44-ES256` (default hybrid — proofs fit the
  common 8 KB HTTP header cap) and `ML-DSA-65-ES256` (opt-in), per
  draft-ietf-jose-pq-composite-sigs-03 and RFC 9964. First PQC-ready Python
  DPoP library.
- `generate_key(alg=...)`, `CompositeKey`, RFC 9964 `AKP` JWKs,
  `private_jwk()`, `composite_key_from_jwk()`.
- `select_alg(server_metadata, require_pqc=...)`: negotiate via the AS's
  `dpop_signing_alg_values_supported` (RFC 9449 §8.2), fail-closed option.
- `docs/pqc.md`.

### Changed

- `generate_proof` / `verify_proof` dispatch on the proof's `alg` header.
  ES256 behavior is unchanged.

## [0.1.1] — 2026-10-11

### Fixed

- Two fuzzer-found crashes: non-dict JWT header/claims and JWKs missing
  `x`/`y` now raise `DPoPError` instead of `AttributeError`/`KeyError`.
- `htu` scheme/host case-normalization per RFC 3986; constant-time `ath`
  comparison.

## [0.1.0] — 2026-10-03

### Added

- Initial release: RFC 9449 DPoP proof generation (`generate_proof`) and
  server-side verification (`verify_proof`) with ES256, `jti` replay cache,
  `nonce`/`ath` support, RFC 7638 JWK thumbprints. Single dependency:
  `cryptography`.
