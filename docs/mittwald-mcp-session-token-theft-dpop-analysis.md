# Thirty-Two Token Thefts, One Missing Control

## The incident

A German web host's MCP server became the way into its customers'
accounts — not through a password, and not through a phishing page, but
through the session tokens the server itself was holding for the people
who used it.

**Mittwald** (Mittwald CM Service, a hosting provider for web agencies)
disclosed the breach on **2026-11-07** in an incident report by founder
and managing director Robert Meyer:

- **2026-10-21:** the attacker first probes a flaw in Mittwald's MCP
  server — the interface that let customers connect AI assistants to
  mStudio, Mittwald's control panel for websites and hosting.
- **2026-10-23:** the attacker moves around the platform as an ordinary
  registered user — test accounts, Extensions, simple injection attempts.
- **2026-10-27, 15:03:** five minutes after registering another account,
  the attacker exploits the flaw in the MCP server. Mittwald treats all
  data from 27 October onward as compromised.
- **2026-11-04:** Mittwald spots unusual behaviour, locks the attacker's
  first account, identifies the MCP server as the entry point, and
  switches it off. mStudio logins and SSH access to customer projects
  are disabled; external forensic experts are brought in and the
  authorities informed.
- **2026-11-06:** forensic review counts **56 compromised customer
  projects**; repeated scans find no further compromised projects and no
  current attacker activity.
- **2026-11-07:** mStudio and SSH access come back; the MCP server stays
  offline until Mittwald decides whether to offer it again. Passkeys
  are now offered for mStudio logins.

What was stolen: **session tokens, not passwords**. Mittwald's FAQ is
direct — no passwords were read; session tokens were. Each token opened
mStudio with the customer's own rights, including every project that
customer could access. All tokens were revoked; API keys were blocked as
a precaution. Only customers who used the MCP server are affected, and
Mittwald is emailing each of them. No sign of customer data published
online so far.

No CVE has been assigned. Mittwald says the gap was in its MCP server
and is closed, and promises a detailed account once analysis and
recovery are complete.

Sources: Mittwald incident report
(https://www.mittwald.de/blog/mittwald/sicherheitsvorfall-am-mcp-server)
and MCP FAQ (https://www.mittwald.de/lp/mcp-faq), both in German;
independent coverage 2026-11-09 (The Record; ByteSized Security
analysis, https://blog.bytesizedsecurity.show/2026/11/09/mcp-security-best-practices-mittwald-breach/).

## Why it's DPoP-shaped

The token was the identity, and the token was replayable. The attacker
never needed a customer's password or second factor — both had already
been checked when the token was issued. Whoever held the token looked
like the customer to mStudio. That is the series thesis in its purest
form, and it is the first time the series meets it inside a production
MCP server: the connector that exists to hand an AI assistant working
access became the store of bearer credentials worth stealing.

Two checks matter here, and both cut in favour of the DPoP reading:

1. **The proof-key-hands test passes.** The tokens were stolen out of
   the MCP server's store — the attacker breached the holder, he did
   not complete a login flow as the victim. A sender-constrained token
   would have been dead in his hands: the string alone is not
   sufficient without the holder's private key, and the key never sat
   in the store he raided. This is the opposite of the near-misses the
   watch keeps filtering (Keycloak CVE-2026-19688, IBM API Connect
   CVE-2026-16720), where the token is minted to the attacker himself
   and the proof key travels with him.
2. **The concentration is the point.** One MCP server held working
   tokens for many customers, and a single flaw in it exposed all of
   them at once. The MCP authorization guidance already says servers
   "MUST NOT accept any tokens that were not explicitly issued for the
   MCP server" and "MUST NOT use sessions for authentication" — the
   spec knew this shape. Sender-constrained tokens are the control
   that makes the next token-store breach a non-event: the thief gets
   strings that no resource server will honour.

Same family as #5 (Open WebUI's session token harvested by any website
the victim visited), #28 (kaniko's Azure token posted to a lookalike
host), and #31 (Vikunja's bearer token sent to an attacker-chosen API
URL): the delivery layer differs — a missing origin check, a regex, a
URL switch, a flawed MCP server — and the missing control is identical.

The honest boundary, as ever: DPoP does not fix the flaw. The flaw is
still undisclosed — whether it sat in Mittwald's own code or in the
open-source MCP libraries is unknown — and closing it, separating
tenants, and revoking the tokens is the cure. Two further limits: the
tokens here are **mStudio session tokens, not RFC 9449 OAuth access
tokens**, so DPoP as specified does not bolt onto them directly — the
argument is that sender-constraining the tokens an MCP server holds,
at the OAuth layer where the protocol provides for it, kills exactly
this replay; and Mittwald's claim that AI tools ran the attack rests
on log timing alone (seconds between steps a human would take longer
over) — unproven, and irrelevant to the defence either way. The
passkeys Mittwald now offers harden the login; they do not protect a
session after the login is done — the same gap two-factor
authentication leaves open.

Mittwald is not a Python project and its MCP server is offline, so
this is analysis only: no pydpop plug, no upstream patch to write from
here. What the incident does give the series is its first real-world
MCP-server token theft with customer impact — 56 projects, eight days
undetected — and the clearest demonstration yet that the MCP ecosystem's
next hardening step is not another login check, but tokens that cannot
be replayed by whoever happens to hold the string.
