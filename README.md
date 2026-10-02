# pydpop

RFC 9449 DPoP (Demonstrating Proof of Possession) for Python — proof generation and verification, in one tiny dependency-light package.

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

**v0.2 (roadmap)** — hybrid post-quantum signatures (ML-DSA-65 + classical), making this the first PQC-ready Python DPoP library. Algorithm agility by configuration, not by rewriting your code.

## Verification checklist

- [x] Round-trip: generate → verify
- [x] Negative tests: tampered payload, wrong `htm`/`htu`, stale `iat`, replayed `jti`, `ath`/`nonce` mismatch, JWK substitution
- [ ] Interop against Keycloak 26.4+ (DPoP-capable) — stretch goal, tracked in issues

## Contributing

Issues and PRs welcome — especially interop reports against real authorization servers. Run `pytest` before submitting.

## License

MIT
