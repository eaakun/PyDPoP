# Forty-Nine Token Thefts, One Missing Control

## The incident

**Pomerium**, 0.30.0 through before 0.34.0 —
CVE-2026-135300, **HIGH 7.4**, published
2026-11-23T17:17Z:

- The MCP token endpoint `/.pomerium/mcp/token` skips
  client secret verification for `client_secret_basic`
  clients.
- An attacker holding an intercepted authorization code
  or refresh token can redeem it at the token endpoint
  with any secret and obtain the victim's access tokens.
- Fixed in 0.34.0. Upstream: pomerium/pomerium, PR #6787.

Pomerium is the zero-trust access proxy whose MCP support
lets AI clients reach internal services through the same
identity-aware front door as browsers. The token endpoint
is the one place in the OAuth flow where the client's
identity is supposed to be checked before a code or a
refresh token turns into access — and for
`client_secret_basic` clients, it was not checked at all.
The attacker still needs an intercepted code or refresh
token first; the advisory does not name the interception
channel. But once held, the redemption that should have
been the last locked door was open.

Sources: NVD CVE-2026-135300; the fix commit and release
linked in the NVD record.

## Why it's DPoP-shaped

The misdelivery family's ninth outing — and the first to
arrive at a token endpoint itself. Every earlier member
of the family was about a token going to the wrong place:
a redirect target (Camel #85251), a registry impostor
(kaniko #105769), a wrong resource (mcp-go #123272,
Obot #130766). Pomerium is the same story one step
later: the token is already in the wrong hands, and the
question is whether the token endpoint will still honor
it. It did, because the only check standing between the
intercepted refresh token and the victim's access tokens
was a client secret the endpoint never verified.

The proof-key-hands test passes. The attacker holds the
victim's refresh token, but he does not hold the
victim's proof key. A DPoP-bound refresh token requires
its proof at redemption: presented without the holder's
private key, the intercepted string redeems nothing, and
the victim's access tokens stay unissued. That is the
check the token endpoint is for — not just "is this
client who it claims to be", but "is this presenter the
holder the token was bound to". This is also the first
series case at an MCP token endpoint, which is where
DPoP proofs are verified: the shape is on home ground.

The honest boundary, as ever: DPoP does not fix the
underlying bug. Client secret verification at the token
endpoint must be restored, and the primary fix is the
upgrade to 0.34.0. Two further limits: DPoP binding of
refresh tokens is a mitigation at redemption, not a
repair of the missing client-authentication check; and
the interception channel that puts the code or refresh
token in the attacker's hands is outside this CVE, so
whatever leaks refresh tokens in the deployment still
needs its own fix. What DPoP changes is the value of
the intercepted string: a refresh token that only its
holder can redeem is a string the interceptor cannot
spend.
