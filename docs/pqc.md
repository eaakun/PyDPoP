# Post-Quantum DPoP (v0.2)

pydpop v0.2 adds PQ/T hybrid composite DPoP proofs alongside the v0.1 ES256
path — no new dependencies (`cryptography` already ships ML-DSA), no
breaking changes to existing callers.

## Which algorithm?

| `alg` | proof size | notes |
|---|---|---|
| `ES256` (default) | ~0.6 KB | RFC 9449, unchanged from v0.1 |
| `ML-DSA-44-ES256` | ~6.0 KB | **recommended hybrid**: fits the common 8 KB HTTP header cap |
| `ML-DSA-65-ES256` | ~8.3 KB | opt-in; needs raised header limits on your servers |

Both hybrids follow draft-ietf-jose-pq-composite-sigs (WG, v03) exactly —
domain-separated `M' = Prefix || Label || 0x00 || PH(M)`, ML-DSA signed with
`ctx=Label` — and use RFC 9964 `AKP` JWKs. Verification requires *both*
component signatures to pass.

## Usage

```python
from pydpop import generate_key, generate_proof, verify_proof, select_alg

# 1. negotiate with the authorization server (RFC 9449 §8.2 metadata)
alg = select_alg(as_metadata)  # -> "ML-DSA-44-ES256", or "ES256" as fallback
# alg = select_alg(as_metadata, require_pqc=True)  # fail closed, no downgrade

# 2. client side — same calls, hybrid key
key = generate_key(alg=alg)
proof = generate_proof(private_key=key, htm="POST", htu="https://auth.example.com/token")

# 3. server side — unchanged; dispatch is by proof header alg
bound = verify_proof(proof=proof, htm="POST", htu="https://auth.example.com/token")
print(bound["jwk_thumbprint"])  # RFC 7638 over the composite JWK, for cnf.jkt
```

Notes:

- Hybrid keys are fresh ML-DSA + P-256 pairs generated together; the draft
  forbids reusing a standalone P-256 key as the classical component.
- `jwk_thumbprint` works for both EC and AKP JWKs (RFC 9964 member set for AKP).
- A `DPoP-Nonce` retry reuses the same algorithm — negotiation happens once,
  never per-retry, so a nonce challenge can't become a downgrade vector.

## Standards tracking

- RFC 9964 (ML-DSA in JOSE/COSE, May 2026) — implemented, stable.
- draft-ietf-jose-pq-composite-sigs-03 — implemented; the draft is still WG
  work-in-progress, so pydpop pins the revision it was built against and
  re-checks on every update. Wire-format changes upstream will be tracked
  as patch releases.

## Interop

ES256 interop with Node.js `jose` is verified bidirectionally
(`docs/interop.md`). For the composite algs there is no second Python
implementation yet; the nearest cross-check target is jwx-go/compsig (Go).
Interop reports welcome.
