# Twenty-Two Token Thefts, One Missing Control

## The incident

**CVE-2026-117532** (CRITICAL, CVSS 3.1 9.8, `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`,
NVD-published 2026-10-27) in **REDAXO core** (the PHP CMS), versions
>= 5.3.0 through <= 5.21.3, patched in **5.21.4**:

- The bundled `structure/history` plugin offers a frontend "article
  history" login for a given backend account. The temporary login token
  is derived from the login name, a validity timestamp, and a
  server-side secret tied to the user's session.
- The flaw (CWE-287, improper authentication) is that this secret could
  be brought into a **known, predictable state without authenticating**.
  Once it is, the token depends only on attacker-controlled inputs and
  can be forged — no valid session or prior access required. The
  precondition of knowing a valid login name is weak in practice:
  `admin` is a common default and login names can be enumerated.
- An **unauthenticated** attacker thereby obtains a backend session for
  an existing account, including an administrator. On installations
  **not running in live mode**, that admin session escalates to remote
  code execution, because an administrator can introduce executable PHP
  through templates.
- The fix shipped in **5.21.4** (2026-08-03), whose release notes single
  out the `structure/history` plugin as urgently needing the update — or,
  if an immediate update is impossible, the plugin disabled. Note the
  disclosure lag: the patch predates the CVE publication by nearly
  three months, so this is a retrospective write-up, not a live fire.
- Scope: only installations with the `structure/history` plugin
  installed **and activated** are affected; it is not enabled by
  default.
- Sources: NVD record for CVE-2026-117532; REDAXO security advisory
  GHSA-px8f-whj8-hrpq; the 5.21.4 release notes.

## Why it's DPoP-shaped

Another "the string is the identity" forgery — but with a twist the
series has not seen before: the key was never leaked and never
hardcoded. It was **made guessable**. Nothing is stolen; the attacker
pushes a secret into a predictable state and mints a login token from
it. A sender-constrained token changes the shape of that deal: the
string alone is not sufficient, because presenting it requires the
client's proof key, which the forger never had.

## Notes / honesty checks

- DPoP does **not** fix a predictable secret, and it is not a
  substitute for the actual remediation — upgrade to 5.21.4, or disable
  the plugin. What it changes is only the post-forgery half: a minted
  string that cannot be presented without a proof key.
- Form matters: the forged object is a **temporary login token**, not a
  standard JWT access token, so the right framing is the general
  principle — sender-constrained session tokens — not a forced fit to
  the OAuth DPoP flow. REDAXO is a PHP CMS, so per the series'
  "雪中送炭" rule this one is analysis only: no pydpop plug.
- Scope, stated plainly: only plugin-activated installations in the
  affected version range are vulnerable, and the code-execution
  escalation applies only outside live mode. This is not "every REDAXO
  instance falls."
