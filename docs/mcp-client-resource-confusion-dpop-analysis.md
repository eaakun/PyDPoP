# Twenty-Nine Token Thefts, One Missing Control

## The incident

Two MCP clients, one missing check, published the same day
(2026-11-05):

**CVE-2026-123272, mcp-go < 1.2.1** (HIGH 8.0, GHSA-xf6j-693p-wqxx):

- `OAuthHandler.fetchServerMetadata` takes whatever resource a
  server declares in its well-known Protected Resource Metadata and
  uses it directly as the RFC 8707 resource indicator, without
  validation. The authorization server then issues a token for the
  attacker's declared resource, and the attacker replays it there.
- Fixed in v1.2.1 (PR #1053). Sources: NVD record for
  CVE-2026-123272; GitHub Security Advisory GHSA-xf6j-693p-wqxx
  (verified against the advisory record at publish time).

**CVE-2026-123271, ChatCLI < v1.215.2** (HIGH 8.0, GHSA-95vg-3r9c-2v5q):

- The MCP OAuth login flow uses the server-supplied Protected
  Resource Metadata as the resource indicator, without checking it
  against the configured server URL. A malicious MCP server can
  declare another resource on the same authorization server, receive
  the user's bearer token for it, and replay it on that resource.
- Fixed in v1.215.2. Sources: NVD record for CVE-2026-123271;
  GitHub Security Advisory GHSA-95vg-3r9c-2v5q (verified against the
  advisory record at publish time).

## Why it's DPoP-shaped

This is the same failure the series opened with — the September
official-SDK credential steering (GHSA-qx49-fqc8-xw99 /
CVE-2026-104850), where a malicious server named its own token
endpoint and the client handed over its OAuth credentials. The
difference this time is the loot: not the client secret, the
authorization code, or the PKCE verifier, but the user's access
token itself, issued for a resource the user never asked for.

The resource indicator is a trust statement, not a hint. It is the
client telling the authorization server "this token is for *that*
resource" — and both clients let the server fill in the blank. A
sender-constrained token changes that deal: the string alone is not
sufficient without the holder's private key, so a token issued for
the attacker's resource is inert in the attacker's hands. The
honest boundary, as ever: DPoP does not fix the missing check. The
fix is upgrading (1.2.1 / v1.215.2) and validating the indicator
against the configured server URL — and the authorization server
issues plain bearer tokens today, so the DPoP angle is conditional
on sender-bound issuance. The client-side lesson stands on its own:
never trust a server's self-description of the resource.

Both clients are Go projects; per the series' rule, this is
analysis only, no pydpop plug.
