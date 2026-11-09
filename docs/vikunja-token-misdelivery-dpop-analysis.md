# Thirty-One Token Thefts, One Missing Control

## The incident

Two CVEs in one Vikunja security release, published 2026-11-08, both fixed
in **2.7.1** — and both are the same failure wearing two different clothes:
a bearer token delivered to the wrong party, replayed as-is.

**CVE-2026-123513** (MEDIUM 6.8, CWE-201, GHSA-rj93-wmch-2crq):

- Vikunja before 2.7.1 contains a credential exposure vulnerability: an
  attacker who induces a user to switch the frontend API URL can steal the
  user's stored auth tokens. `checkAndSetApiUrl` leaves
  origin-independent localStorage tokens in place, so the **bearer token
  and the desktop OAuth refresh token are sent to the attacker's server**,
  enabling account takeover.
- The trigger needs user interaction — the victim has to be talked into
  pointing the frontend at the attacker's URL — but once that happens, the
  token leaves through the victim's own client, no exploit chain required.

**CVE-2026-123499** (MEDIUM 5.9, CWE-346, GHSA-3rrq-h284-5vpx):

- Vikunja veans before 2.7.1 contains a credential exposure vulnerability:
  a malicious repository author specifies an attacker-controlled server in
  `.veans.yml`, and when veans runs in an untrusted checkout it sends
  `VEANS_TOKEN` as a Bearer header — or login passwords, TOTP codes and
  tokens — to that server, granting the attacker the victim's Vikunja
  access.
- The trigger here is running veans inside a checkout you do not control;
  the config file, not the user, chooses where the credential goes.

Sources: NVD records for CVE-2026-123513 and CVE-2026-123499; GitHub
Security Advisories GHSA-rj93-wmch-2crq and GHSA-3rrq-h284-5vpx;
VulnCheck advisories for both CVEs.

## Why it's DPoP-shaped

Same family as #28 (kaniko's ACR credential helper posting the build's
Azure token to a lookalike host), #13 (Camel re-attaching `Authorization:
Bearer` to redirect targets), and #6 (mcp-remote transmitting tokens in
cleartext): the token itself never had to be stolen — it was handed over
by the victim's own tooling, to a host that merely had to be named in a
config value or an API URL field. The delivery layer differs in each case
(a regex, a redirect, a frontend URL switch, a repo-controlled YAML file);
the missing control is identical.

A sender-constrained token changes that deal: the string alone is not
sufficient without the holder's private key, so a token that arrives at
the wrong host is dead on arrival — and the same holds for the desktop
OAuth refresh token in CVE-2026-123513, which under DPoP cannot be
redeemed without a proof signed by the key that requested it. The proof
key never leaves the victim's client in either attack: the exfiltration
channel carries the token string only.

The honest boundary, as ever: DPoP does not fix either bug. The fix is
upgrading to 2.7.1, and in the veans case DPoP says nothing about the
passwords and TOTP codes that can leak down the same channel — only the
bearer-token replay dies. The upgrade is the cure; DPoP is the depth.

Vikunja is a Go project, and this is its second appearance in the series
(#11 was the WebSocket revocation bypass, CVE-2026-111917) — the project
keeps re-learning, one endpoint at a time, that the token string is
treated as the identity. Per the series' rule, this is analysis only, no
pydpop plug.
