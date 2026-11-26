# Fifty-Six Token Thefts, One Missing Control

## The incident

GitLab CE/EE 13.7.0 through before 19.4.11 / 19.5.9 / 19.6.2 let an
authenticated user with Maintainer-role permissions obtain another
user's authenticated session cookie (CVE-2026-119452, MEDIUM 6.7,
published 2026-11-25). Improper session storage handling in the
dependency proxy authentication flow, when a redirect-pending state
was triggered, handed the victim's session cookie to the Maintainer —
and the cookie is the account.

- Affected: GitLab CE/EE 13.7.0–19.4.11 / 19.5.9 / 19.6.2; fixed in
  19.4.11, 19.5.9, and 19.6.2.
- Sources: NVD record (CVE-2026-119452); GitLab work item
  https://gitlab.com/gitlab-org/gitlab/-/work_items/637297; HackerOne
  report https://hackerone.com/reports/3964486.

## Why it's DPoP-shaped

The session-cookie replay shape, in its most ordinary clothes. No
exploit chain, no network position, no phishing — a flaw in session
storage simply delivers the victim's live session credential to
another user, who presents it and is the victim. Every replay in this
series works the same way because the credential is a bare string.
Bind the session to its holder — a proof key the attacker's browser
does not have — and the stolen cookie stops being an account.

## Notes / honesty checks

- The stolen credential is a GitLab session cookie, not an OAuth
  access token — the angle is sender-bound issuance as the shape of
  the fix, not a pydpop plug.
- Gating: the attacker must hold Maintainer permissions and trigger a
  redirect-pending state in the dependency proxy flow. An insider
  flaw, not a drive-by — but insiders with a cookie are still
  account takeover, and the dependency proxy is exactly where
  CI-adjacent users live.
- The patch is the session-storage fix in 19.4.11 / 19.5.9 / 19.6.2;
  sender binding is the control that makes the next storage bug a
  non-event.
