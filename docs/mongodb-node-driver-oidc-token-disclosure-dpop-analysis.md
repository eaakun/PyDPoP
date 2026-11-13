# Thirty-Six Token Thefts, One Missing Control

## The incident

The MongoDB Node.js driver, versions 6.7.0 through 7.8.x —
CVE-2026-126835, **MEDIUM 6.5** (CVSS 3.1; 5.9 under CVSS 4.0),
CWE-923, published 2026-11-12T17:17Z:

- During OIDC authentication the driver does not consistently
  enforce its permitted-host restriction, so a **bearer token
  produced by the embedding application's own login callback**
  (`OIDC_CALLBACK` / `OIDC_HUMAN_CALLBACK`) can be transmitted to
  a host **outside the configured set of permitted hosts**.
- No database account is required. The party supplying the
  connection configuration needs only to influence the settings
  the application passes to the driver — in practice, a connection
  string whose `authMechanismProperties` include `ENVIRONMENT`
  (for example `ENVIRONMENT:azure`) pointed at an attacker host.
  The driver then hands the application's own OIDC access token
  to that host.
- Fixed in **7.9.0**, released the same day (2026-11-12). The
  release notes carry the mitigation for applications that cannot
  upgrade immediately: refuse connection strings whose
  `authMechanismProperties` include `ENVIRONMENT` when a callback
  is in use. From 7.9.0, passing both `ENVIRONMENT` and a callback
  to `MongoClient` throws outright.

Sources: NVD CVE-2026-126835 (CNA: MongoDB); mongodb
`node-mongodb-native` release v7.9.0 (2026-11-12).

## Why it's DPoP-shaped

This is the misdelivery family, back for its fifth outing — #2
Splunk MCP Server sending the platform token to an
attacker-configured URL, #13 Camel re-attaching `Authorization:
Bearer` to a redirect target, #28 kaniko handing an Azure AD
token to a counterfeit registry, #31 Vikunja posting a stored
bearer token to an attacker-chosen API URL. The verb is always
the same: the software, doing exactly what it was told by a
setting the attacker influenced, delivers a live token to the
attacker's doorstep. The token here is the embedding
application's OIDC access token — the credential that authenticates
the application itself to MongoDB — and once the attacker's host
has the string, it replays against the real service for as long
as the token lives.

The proof-key-hands test passes cleanly, and the two halves of
it are worth spelling out. The token belongs to the embedding
application, not to whoever supplied the connection string, so
the attacker receives a credential minted for someone else's key.
And the attacker holds no proof key of his own for it — he never
completed a flow, never registered a key, never touched the login
callback. A sender-constrained token presented without its
holder's private key is a string the resource server will not
honour, however perfectly it was delivered.

The honest boundary, as ever: DPoP does not fix the driver bug.
Upgrade to 7.9.0 — or apply the `ENVIRONMENT` mitigation — is
the fix, and the driver must enforce its permitted-host list.
One further limit, specific to this case: MongoDB OIDC today
runs on plain bearer tokens, so the DPoP angle is conditional on
the identity provider issuing DPoP-bound tokens for the MongoDB
audience; until then the control is a property the token *could*
have, not one it has. And the gating is real — the attacker must
get the application to accept a hostile connection string, which
is why the blast radius concentrates where applications and AI
agents routinely pass user-supplied MongoDB URIs straight into
the driver. That is also why this one belongs in the series:
the connection string is becoming the new redirect URI, and the
lesson is the same — a bearer token that any endpoint can
collect is a bearer token that any endpoint will.
