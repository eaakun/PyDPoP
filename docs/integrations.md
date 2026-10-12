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

## FastAPI: `DPoPVerifier`

```python
from fastapi import Depends, FastAPI
from pydpop.integrations.fastapi import DPoPVerifier

app = FastAPI()
verify_dpop = DPoPVerifier()  # share one instance: shared replay cache

@app.get("/data")
def read_data(bound=Depends(verify_dpop)):
    # bound == {"jwk", "jwk_thumbprint", "claims"}
    # compare bound["jwk_thumbprint"] to the access token's cnf.jkt
    ...
```

Any failure → `401 WWW-Authenticate: DPoP` (fail closed). Requires
`pip install pydpop[fastapi]`.

## Django: `DPoPMiddleware`

```python
# settings.py
MIDDLEWARE = [
    ...,
    "pydpop.integrations.django.DPoPMiddleware",
]

# views.py
def my_view(request):
    # request.dpop == {"jwk", "jwk_thumbprint", "claims"}
    # compare request.dpop["jwk_thumbprint"] to the token's cnf.jkt
    ...

@dpop_exempt
def health_check(request): ...  # skips verification
```

Fail-closed 401s, shared replay cache, `ath` binding — same guarantees as
the FastAPI verifier, plus `@dpop_exempt` for public views. Requires
`pip install pydpop[django]`.

## Flask: `DPoPVerifier`

```python
from flask import Flask, g
from pydpop.integrations.flask import DPoPVerifier, dpop_exempt

app = Flask(__name__)
DPoPVerifier(app)  # registers a before-request hook

@app.get("/data")
def data():
    return {"jkt": g.dpop["jwk_thumbprint"]}  # compare to cnf.jkt
```

401s fail closed; `@dpop_exempt` for public views. Requires
`pip install pydpop[flask]`.

## Starlette: `DPoPMiddleware`

Pure ASGI middleware — works for any Starlette app (and any ASGI framework):

```python
from starlette.applications import Starlette
from pydpop.integrations.starlette import DPoPMiddleware

app = Starlette()
app.add_middleware(DPoPMiddleware)
# endpoint: scope["dpop"]["jwk_thumbprint"]
```

Requires `pip install pydpop[starlette]`.

## aiohttp client: `DPoPClientSession`

```python
from pydpop.integrations.aiohttp import DPoPClientSession

async with DPoPClientSession(key, access_token=tok) as sess:
    async with sess.get(url) as resp: ...
```

Fresh proof per request, `DPoP-Nonce` caching, single auto-retry on
`use_dpop_nonce` — the aiohttp mirror of the httpx integration. Requires
`pip install pydpop[aiohttp]`.
