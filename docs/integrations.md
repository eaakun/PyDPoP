# HTTP client integrations

`pip install pydpop[httpx]` — DPoP stops being a per-request chore.

## httpx: `DPoPAuth`

```python
import httpx
from pydpop import generate_key
from pydpop.integrations.httpx import DPoPAuth

key = generate_key(alg="ML-DSA-44-ES256")  # or default ES256

# Every request gets a fresh proof; DPoP-Nonce challenges are retried once,
# automatically, with the server nonce (RFC 9449 §4.3).
client = httpx.Client(auth=DPoPAuth(key))
token = client.post("https://auth.example.com/token", data={
    "grant_type": "client_credentials",
}).json()

# Resource server with a DPoP-bound access token: ath is bound for you.
api = httpx.Client(auth=DPoPAuth(key, access_token=token["access_token"]))
api.get("https://api.example.com/data")
```

Works with `httpx.AsyncClient` as well. The core `pip install pydpop` stays
a single dependency (`cryptography`); the httpx integration is opt-in.

## Why this matters

Proof-per-request bookkeeping — fresh `jti`, `iat`, nonce caching, the
`use_dpop_nonce` retry — is where hand-rolled DPoP integrations go wrong.
`DPoPAuth` owns that dance, so your code never touches a proof directly.
