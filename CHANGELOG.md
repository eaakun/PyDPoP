# Changelog

All notable changes to pydpop. Format follows [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

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
