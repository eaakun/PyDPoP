# Sixty-Two Token Thefts, One Missing Control

## The incident

Budibase before 4.0.0 lets any non-admin Creator or app-scoped
builder read every pending invite's secret bearer `code` — along
with the invitee's email and the full intended roles, up to
`admin.global` — via `GET /api/global/users/invites`
(CVE-2026-137500, HIGH 7.2, published 2026-11-26). The public
`POST /api/global/users/invite/accept` endpoint then creates the
invited identity with an attacker-chosen password and no
proof-of-email, so a low-privileged user can hijack any pending
invited identity, including a pending admin invite, and walk away
with global-admin privileges.

- Affected: Budibase before 4.0.0; fixed in 4.0.0.
- Sources: NVD record (CVE-2026-137500); GitHub Security Advisory
  GHSA-j3jq-gq5m-gv3v
  https://github.com/Budibase/budibase/security/advisories/GHSA-j3jq-gq5m-gv3v
  (verified proof of concept on release tag 3.40.1; the advisory
  was filed while no fix existed on master); VulnCheck advisory
  https://www.vulncheck.com/advisories/budibase-before-4.0.0-privilege-escalation-via-invite-code-disclosure.

## Why it's DPoP-shaped

The stolen-bearer family's first invite-code specimen — kin to the
remember-me token replayed from a database dump (#63160) and the
share tokens forged offline (#120209), but cleaner: the bearer code
is the *sole* credential gating invite acceptance, it is handed out
verbatim to anyone with builder permissions, and the accept
endpoint asks nothing else. A sender-constrained invite code would
be unredeemable by the thief, because acceptance would need the
invitee's proof key, not just the string. The advisory's own
suggested fix says the same thing in other words: "bind privileged
invite acceptance to proof of email ownership so a leaked code
alone cannot mint an admin identity." Binding is the fix; DPoP is
the general form of it.

## Notes / honesty checks

- An invite code is not an OAuth access token — the angle is the
  binding principle, not a pydpop plug. The primary fixes are
  admin-only invite listing, never returning the raw code, and
  proof of email ownership at acceptance.
- The attacker must already be an authenticated tenant user
  (Creator/builder); the theft is insider-privilege escalation,
  not an unauthenticated break-in. The ceiling is what makes it
  series-worthy: a pending admin invite means full global-admin
  takeover from a non-admin account.
- Budibase disclosed two sibling issues the same day — an
  unverified-email OIDC account-linking takeover
  (CVE-2026-137499, CRITICAL 9.8) and a legacy LiteLLM credential
  disclosure (CVE-2026-137497) — both recorded in the watch log;
  neither is DPoP-shaped (issuance logic and static credentials),
  and neither is in this entry.
