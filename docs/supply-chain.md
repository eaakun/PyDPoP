# Supply chain (SLSA + Sigstore + SBOM)

## Status: UNTESTED

`.github/workflows/supply-chain.yml` has never run. It triggers on
the next published release; verify its output on that release
(provenance, Sigstore bundles, SBOM) before relying on it. This
document describes the intent, not a verified pipeline.

## Ruling

Per the project owner's 2026-11-12 ruling, the "DPoP-style release
proof" mechanism is **withdrawn**: pydpop does not invent a binding
format for its own artifacts. The release chain uses only standard,
independently verifiable artifacts, because those have ecosystem
tooling, independent verifiers, and audit conventions. What pydpop
adds is a consistency checker (`dpop audit-release`), not a new
cryptographic binding layer. (A one-line doc analogy to DPoP is the
most the idea gets.)

## What the workflow produces

On each published release (`.github/workflows/supply-chain.yml`):

- **SLSA Build Level 3 provenance** via the official generator
  (`slsa-framework/slsa-github-generator`, generic workflow): the
  build job hashes the wheel/sdist and the provenance job attests
  them.
- **Sigstore keyless signatures** of the wheel and sdist
  (`sigstore/gh-action-sigstore-python`), so anyone can verify the
  artifacts came from this repository's release workflow.
- **CycloneDX SBOM** (`anchore/sbom-action`), published alongside
  the distributions.

## Verifying a release (downstream)

```console
$ sigstore verify dist/pydpop-0.2.2-py3-none-any.whl \
    --certificate-identity https://github.com/eaakun/PyDPoP/.github/workflows/supply-chain.yml@refs/tags/v0.2.2 \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com
$ dpop audit-release --tag v0.2.2 --artifacts dist/ --commit <source-commit-sha>
```

`dpop audit-release` is a **consistency check**, not a signature
verification. It checks, with no network access:

1. the tag matches the version in `pyproject.toml`;
2. distribution files are present;
3. a SLSA provenance file (`.intoto.jsonl`) is present, parses,
   names the SLSA generator as builder, and (when `--commit` is
   given) its `configSource` digest matches the commit;
4. every provenance subject digest matches the file on disk;
5. a CycloneDX SBOM is present, covers every runtime dependency in
   `pyproject.toml`, and lists `cryptography` at a version
   satisfying `cryptography>=41`.

It exits 0 only when every check passes. It does **not** verify
Sigstore signatures — do that separately with `sigstore verify`
above. Use `--json` for a machine-readable report.

## What `audit-release` does not do

- It does not verify that the provenance was produced by the
  workflow it claims (that is what Sigstore verification is for).
- It does not check dependency versions beyond `cryptography`'s
  minimum — the SBOM coverage check is presence-only for other
  deps.
- It does not compare the SBOM against a lockfile: pydpop has no
  lockfile; the comparison is against `pyproject.toml`'s declared
  runtime dependencies.
