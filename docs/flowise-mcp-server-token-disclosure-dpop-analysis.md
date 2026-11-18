# Forty-One Token Thefts, One Missing Control

## The incident

**Flowise**, 3.1.3 through 3.1.4 —
CVE-2026-130796, **HIGH 8.2** (CVSS 3.1), CWE-212, published
2026-11-17T20:17Z:

- The unauthenticated `GET /api/v1/public-chatflows/:id`
  handler returns the chatflow record **including its
  `mcpServerConfig`** — and with it, the MCP server bearer
  token configured for that chatflow.
- An unauthenticated attacker can take the leaked token and use
  it on `POST /api/v1/mcp/:chatflowId` to **invoke chatflows,
  bypassing API key protection and consuming the owner's model
  quota**.
- No fixed version is named in the NVD record or the VulnCheck
  advisory as of this writing, and the latest release is still
  3.1.4 (2026-07-29); no GHSA has been published for the issue
  in the Flowise repository. The disclosure is visible in the
  published source (`packages/server/src/controllers/chatflows/index.ts`,
  `packages/server/src/services/mcp-server/index.ts`).

Sources: NVD CVE-2026-130796; VulnCheck advisory
(flowise-3.1.3-through-3.1.4-mcp-server-token-disclosure-via-public-chatflow-endpoint);
FlowiseAI/Flowise source references in the NVD record.

## Why it's DPoP-shaped

This is the disclosure family's MCP-native outing. The series
has met the shape twice before: #19 Kruize, where an
unauthenticated REST API serialized datasource configs with
bearer tokens in cleartext, and #38 DeepAudit, where an
unauthenticated config endpoint returned the operator's tokens.
Flowise is the same failure with the MCP label on it: a public
endpoint returns a record that was never meant to leave the
server, and the record contains a bearer token — here, the very
token that guards the MCP server.

The proof-key-hands test passes. The token belongs to the
chatflow owner, and the attacker holds no proof key for it — he
never completed the chatflow owner's login, never registered a
key, never touched the owner's browser. He read a public
endpoint and replayed a string. A sender-constrained token
presented without its holder's private key is a string the
server will not honour, however perfectly it matches the MCP
server's config. That is the same answer the series gave for
Kruize and DeepAudit: the bearer string is the identity only
while nobody binds it to a key.

The honest boundary, as ever: DPoP does not fix the underlying
bug. The endpoint must stop returning `mcpServerConfig` to
unauthenticated callers — that is the patch, and it is the
whole of the fix for the disclosure itself. Three further
limits, specific to this case: the token is a static MCP-server
credential configured by the chatflow owner, so the DPoP angle
is conditional on that server issuing sender-bound tokens;
the impact is bounded to invoking chatflows and consuming the
owner's model quota, not full account takeover; and with no
fixed version named, every 3.1.3–3.1.4 deployment is exposed
until the project ships one. What the case gives the series is
the setting: the token that walked out the door this time was
an MCP server's own bearer token, read out of the public API
of one of the most popular LLM agent builders — the disclosure
family has arrived at the protocol's front door.
