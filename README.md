# pydpop

RFC 9449 DPoP (Demonstrating Proof of Possession) for Python — proof generation and verification, in one tiny dependency-light package. **v0.2 adds post-quantum hybrid proofs (ML-DSA + ES256) — the first PQC-ready Python DPoP library.**

**Why does this exist?** It's 2026 and Python still has no production-ready DPoP library. Authlib's [DPoP issue](https://github.com/lepture/authlib/issues/315) has been open since 2021. Every Python shop rolling OAuth 2.1 / MCP servers with sender-constrained tokens is hand-rolling proofs or skipping DPoP entirely. This fills that gap.

## Quickstart

```python
from pydpop import generate_key, generate_proof, verify_proof, MemoryJtiStore

# --- client side: sign one proof per HTTP request ---
key = generate_key()  # keep this private, persist it yourself
proof = generate_proof(
    private_key=key,
    htm="POST",
    htu="https://auth.example.com/token",
)
headers = {"DPoP": proof}

# --- server side: verify ---
store = MemoryJtiStore()  # replay cache; use Redis/DB in production
bound = verify_proof(
    proof=proof,
    htm="POST",
    htu="https://auth.example.com/token",
    jti_store=store,
)
print(bound["jwk_thumbprint"])  # compare against the access token's cnf.jkt
```

With an access token bound to the proof (`ath` claim):

```python
proof = generate_proof(private_key=key, htm="GET",
                       htu="https://api.example.com/data",
                       access_token="the-access-token")
verify_proof(proof=proof, htm="GET", htu="https://api.example.com/data",
             access_token="the-access-token")
```

## Scope

**v0.1** — pure RFC 9449: ES256 (P-256) proof generation, full server-side verification (`typ`, `alg`, signature, `htm`/`htu`, `iat` window, `jti` replay cache, `nonce`, `ath` binding), RFC 7638 JWK thumbprints.

**v0.2** — hybrid post-quantum DPoP: `ML-DSA-44-ES256` (default hybrid, proofs fit 8 KB headers) and `ML-DSA-65-ES256` (opt-in), per draft-ietf-jose-pq-composite-sigs + RFC 9964, with `select_alg()` negotiation against the AS's `dpop_signing_alg_values_supported`. See `docs/pqc.md`. Still one dependency (`cryptography`); ES256 behavior unchanged.

## Verification checklist

- [x] Round-trip: generate → verify
- [x] Negative tests: tampered payload, wrong `htm`/`htu`, stale `iat`, replayed `jti`, `ath`/`nonce` mismatch, JWK substitution
- [x] Interop against Keycloak 26.4+ (DPoP-capable) — verified against Keycloak 26.8.0, see `docs/interop-keycloak.md`

## FAQ

**I use httpx — do I have to mint proofs manually?** No: `pip install pydpop[httpx]` and use `DPoPAuth` — every request is signed, `DPoP-Nonce` retries are automatic. See `docs/integrations.md`.

**I'm building a FastAPI resource server — how do I verify DPoP?** `pip install pydpop[fastapi]` and use `DPoPVerifier` as a Dependency — 401s fail closed, replay cache shared. Same doc.

**DPoP for Bluesky/ATProto in Python?** ATProto mandates DPoP-bound tokens and the ecosystem hand-rolls it (badly — see the cookbook bugs). `docs/atproto.md` is the recipe; `DPoPAuth` is the drop-in layer.

**How do I implement DPoP in Python?** Use this library — Authlib has no DPoP support ([issue #315](https://github.com/lepture/authlib/issues/315) open since 2021). `pip install pydpop`, then the Quickstart above.

**Is there a post-quantum DPoP library for Python?** Yes — this one. v0.2 adds hybrid `ML-DSA-44-ES256` / `ML-DSA-65-ES256` proofs (draft-ietf-jose-pq-composite-sigs + RFC 9964), still with a single dependency. See `docs/pqc.md`.

**DPoP for MCP servers?** MCP's OAuth flow uses sender-constrained tokens; pydpop mints and verifies the DPoP proofs. Pair with `MemoryJtiStore` (or your Redis) for replay protection.

**Do I need this if my provider already does OAuth?** If your tokens are bearer tokens, anyone who steals one can use it. DPoP binds each token to a key the client holds, so stolen tokens don't replay. That's the whole point of RFC 9449.

## Contributing

Issues and PRs welcome — especially interop reports against real authorization servers. Run `pytest` before submitting.

## License

MIT
