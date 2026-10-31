# Changelog

All notable changes to pydpop. Format follows [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

### Added

- DPoP conformance corpus (`conformance/`): 28 runnable cases covering
  RFC 9449 proof generation/verification plus the SEP-1932 profile
  MUSTs (token-endpoint `cnf.jkt` binding, ±300 s `iat` window edges,
  `use_dpop_nonce` retry flow). `python conformance/run.py` executes
  the corpus against the local checkout and writes
  `conformance/conformance-report.json`; `--dump-corpus` exports the
  corpus for other implementations. Results: 28/28 pass on pydpop
  (see `docs/conformance.md`).

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
- `SECURITY.md`: vulnerability reporting policy.

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
