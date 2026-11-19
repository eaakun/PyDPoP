# Forty-Three Token Thefts, One Missing Control

## The incident

**Obot**, 0.26.0 through before 0.27.0 —
CVE-2026-130766, **HIGH 8.0** (CVSS 3.1), published
2026-11-18T19:17Z:

- Obot fails to validate the resource identifier in a remote MCP
  server's Protected Resource Metadata. A malicious MCP server
  can name a *different* service — and a different authorization
  server, with chosen scopes — as the resource its tools
  require.
- Obot then obtains the victim's access token **for that other
  service** and forwards it to the attacker. The token the user
  authorized for one thing arrives in the hands of the party
  who asked for another.
- Fixed in 0.27.0. The advisory is
  GHSA-x3hf-v55x-jcp6 (obot-platform/obot).

Sources: NVD CVE-2026-130766; GHSA-x3hf-v55x-jcp6.

## Why it's DPoP-shaped

This is the resource-confusion shape's third outing, and the
misdelivery family's eighth. The series met the shape in #29,
when mcp-go and ChatCLI each took the resource indicator
straight from the server's Protected Resource Metadata and let
a malicious MCP server claim another resource and walk away
with the user's bearer token. Obot is the same missing check
in a different client: the server names the resource, the
client believes it, the authorization server issues for it,
and the token lands where the attacker said it should.

The proof-key-hands test passes cleanly. The token belongs to
the victim; the attacker never completed the victim's login,
never registered a key, never touched the victim's browser.
He named a resource and waited for the client to deliver. A
sender-constrained token presented without its holder's
private key is a string the resource server will not honour —
and the proof key never leaves the client that obtained the
token, so the forwarded string is inert in the attacker's
hands. That is the whole of the DPoP answer here: the client
can be confused about *where* the token goes, and the token
still cannot be spent by the party who receives it.

The honest boundary, as ever: DPoP does not fix the
underlying bug. The client must validate the resource
identifier against the server it actually connected to — that
is the patch, shipped in 0.27.0, and it is the whole of the
fix for the confusion itself. Two further limits, specific
to this case: the DPoP angle is conditional on the
authorization server issuing sender-bound tokens for the
resource in question, and a malicious server that can name
any resource can still obtain tokens *scoped* to that
resource for the victim's account — DPoP stops the replay,
not the issuance. What the case gives the series is the
setting: the resource-confusion flaw is no longer a
two-client curiosity. Three MCP clients, three codebases,
one missing check — and the check that was missing is the
one DPoP makes survivable.

A same-release sibling, recorded for completeness rather
than as a co-headline: CVE-2026-130764 (HIGH 7.6,
GHSA-57qx-69p6-3w3g) lets a Power User advertise a malicious
OAuth token endpoint in remote MCP server metadata, directing
token-exchange and refresh requests — including redirected
GETs — to cloud metadata services or private-network hosts.
That is endpoint hijack, the class the series filters
(GitLab #112212, Umbraco #117553): DPoP binds access tokens,
not authorization codes or token-endpoint choice, so the
fix is endpoint validation, not sender binding. It shares
the 0.27.0 release and the same root cause — metadata taken
on trust — which is why the two advisories belong in one
breath even though only one of them is DPoP-shaped.
