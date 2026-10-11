# DPoP for ATProto (Bluesky) in Python

ATProto's OAuth **mandates** DPoP-bound access tokens: client metadata must
set `dpop_bound_access_tokens: true`, every request needs a fresh DPoP proof
JWT in the `DPoP` header with `Authorization: DPoP {access_token}`, nonces
are tracked per AS/PDS, and the `ath` claim is required on PDS requests.

The Python ecosystem hand-rolls this today — the official cookbook builds
proofs on authlib's generic JWT (which has no DPoP support; real bugs have
shipped from this pattern, e.g. `htu` leaking query params). pydpop is the
drop-in replacement for that hand-rolled layer.

```python
import httpx
from pydpop import generate_key, private_jwk, private_key_from_jwk
from pydpop.integrations.httpx import DPoPAuth

# ATProto advertises ES256 — the classical path is what you need here.
key = generate_key()  # persist private_jwk(key) yourself, reload with private_key_from_jwk

# Token requests AND PDS calls go through the same client: every request
# gets a fresh proof, use_dpop_nonce retries are automatic, and passing
# the access token binds the ath claim (required by PDS).
client = httpx.Client(auth=DPoPAuth(key))
token_resp = client.post(as_token_url, data={...}).json()

api = httpx.Client(auth=DPoPAuth(key, access_token=token_resp["access_token"]))
api.post(pds_url + "/xrpc/com.atproto.repo.createRecord", json={...})
```

Notes specific to ATProto:

- **Nonces are per-host**: track them separately for the authorization server
  and each PDS. Use one `DPoPAuth` (hence one client) per host, or manage
  `DPoPAuth.nonce` yourself across hosts.
- **`htu` has no query/fragment** (RFC 9449 §4.2) — pydpop strips them; the
  cookbook bug class disappears.
- **Key persistence**: `private_jwk(key)` → JSON on disk;
  `private_key_from_jwk(...)` to reload. ATProto clients are long-lived;
  don't regenerate the key per session or your grants break.

If you maintain one of the hand-rolled Python ATProto OAuth implementations,
swapping its DPoP layer for these three calls removes an entire class of
interoperability bugs. Issues and PRs welcome.
