# Thirty-Eight Token Thefts, One Missing Control

## The incident

Three tokens that walked out the door — one handed over to
anyone who asked, one delivered to an attacker-chosen host, one
sent to a crafted endpoint by a prompt injection. All three
published on the same day, all three the same failure: a token
that should only ever be presented by its holder ends up in
someone else's hands, and nothing about the token itself objects.

**DeepAudit** — the unauthenticated hand-over. Versions
2.0.0-beta.1 through 3.8.0 —
CVE-2026-129877, **HIGH 7.5** (CVSS 3.1; 8.7 under CVSS 4.0),
CWE-306, published 2026-11-16T15:17Z:

- A single unauthenticated `GET` to `/api/v1/config/defaults`
  returns the operator's server secrets.
- Among them: the operator's **LLM provider API keys and GitHub
  or GitLab tokens** — which the attacker can then use against
  those services and the repositories they can reach.

Sources: NVD CVE-2026-129877; VulnCheck advisory
(deepaudit-2.0.0-beta.1-through-3.8.0-information-disclosure-via-api-v1-config-defaults);
DeepAudit repository (`backend/app/api/v1/endpoints/config.py`);
research write-up at vul.yulun.ac.cn (2026-11-06).

**DeepAudit** — the SSRF delivery. Versions 2.0.0-beta.5
through 3.8.0 —
CVE-2026-129880, **HIGH 7.7** (CVSS 3.1; 8.3 under CVSS 4.0),
CWE-918, published 2026-11-16T15:17Z:

- A registered user creates a GitLab or Gitea project pointing
  at a **controlled host** and requests its branches.
- The server fetches the branch list with the **server-wide
  GitLab or Gitea token**, so the token arrives at the attacker's
  host — and the same request reaches internal hosts.

Sources: NVD CVE-2026-129880; VulnCheck advisory
(deepaudit-2.0.0-beta.5-through-3.8.0-ssrf-via-project-branch-listing-leaks-git-tokens);
DeepAudit repository (`backend/app/api/v1/endpoints/projects.py`,
`backend/app/services/scanner.py`, `backend/app/utils/repo_utils.py`).

No fixed version is named in either DeepAudit NVD record as of
this writing.

**AWS Labs Timestream for InfluxDB MCP Server** — the
prompt-injection delivery. Before 0.0.19 —
CVE-2026-126681, **MEDIUM 5.5** (CVSS 3.1; 6.8 under CVSS 4.0),
CWE-923, published 2026-11-16T21:17Z:

- The server does not properly restrict the endpoints in its
  connection configuration, so a remote unauthenticated actor —
  **via prompt injection** — can obtain the **InfluxDB API token
  configured on the server**, sent to a crafted endpoint
  controlled through an InfluxDB URL introduced in the MCP client
  context.
- Fixed in **0.0.19**; the advisory instructs users to upgrade
  and to **rotate any InfluxDB API tokens** configured for the
  server.

Sources: NVD CVE-2026-126681; GHSA-2f9r-g4f3-wc2j; AWS
security bulletin 2026-185.

## Why it's DPoP-shaped

This is the misdelivery family, back for its sixth and seventh
outings — #2 Splunk MCP Server sending the platform token to an
attacker-configured URL, #13 Camel re-attaching `Authorization:
Bearer` to a redirect target, #28 kaniko handing an Azure AD
token to a counterfeit registry, #31 Vikunja posting a stored
bearer token to an attacker-chosen API URL, #36 MongoDB handing
an OIDC token to a non-allowlisted host — with the DeepAudit
config-endpoint disclosure as the family's theft-side sibling:
the token is not mis-sent, it is simply given away. The verb
changes; the noun does not. In all three cases the attacker ends
up holding a live token minted for someone else — the DeepAudit
operator, the InfluxDB account owner — and presents it from his
own infrastructure.

The proof-key-hands test passes for all three. The tokens belong
to the operator, not to whoever asked for them, and the attacker
holds no proof key for any of them — he never completed a flow,
never registered a key, never touched the issuing service. A
sender-constrained token presented without its holder's private
key is a string the resource server will not honour, however
perfectly it was delivered. The AWS case is the purest
demonstration of the series' MCP thesis: the prompt injection is
the new phishing email, and the token is what the injected
instruction walks out with — the sixth misdelivery outing, and
the first to arrive through a prompt rather than a connection
string or a redirect.

The honest boundary, as ever: DPoP does not fix any of the
three underlying bugs. DeepAudit must close the config endpoint
and validate repository URLs against an allowlist; the MCP
server must restrict connection endpoints (fixed in 0.0.19).
Two further limits, specific to these cases. First, the tokens
here are third-party bearer tokens — GitHub, GitLab, Gitea,
InfluxDB — so the DPoP angle is conditional on those services
issuing DPoP-bound tokens, exactly as in #36; until then the
control is a property the token *could* have, not one it has.
Second, the LLM provider API keys in the DeepAudit disclosure
are static secrets, not bearer tokens at all — DPoP does not
cover them, and they need their own fix, the same distinction
#19 drew for Kruize. And none of the three projects is Python,
so this is analysis only. What the trio gives the series is the
delivery mechanism, updated for the agent era: the token no
longer needs to be stolen from a victim's browser — the server
hands it over itself, to a URL the attacker chose, sometimes
because a prompt told it to.
