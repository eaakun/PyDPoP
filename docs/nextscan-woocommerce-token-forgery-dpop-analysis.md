# Thirty-Five Token Thefts, One Missing Control

## The incident

Two CRITICAL 9.8s, published on the same day, both answering the
same question — how does an unauthenticated stranger end up holding
a valid token for any user? — with two different answers: one forges
it, the other just asks the server for it.

**NextScan** (ns-admin), versions 1.1.0 through 1.2.0 —
CVE-2026-126797, **CRITICAL 9.8** (CVSS 3.1; 9.3 under CVSS 4.0),
CWE-321, published 2026-11-11T21:16Z:

- The admin panel uses a **hardcoded JWT signing key**.
- An unauthenticated remote attacker can sign an HS256
  `X-Access-Token` carrying the **public super administrator role
  ID** and gain full access to user management, scan tasks, and
  stored vulnerability results.
- No fixed version is named in the NVD record or the VulnCheck
  advisory as of this writing; the upstream issue is
  tongcheng-security-team/NextScan#48.

Sources: NVD CVE-2026-126797; VulnCheck advisory
(nextscan-1.1.0-through-1.2.0-hardcoded-jwt-key-authentication-bypass-in-ns-admin);
NextScan repository (`docker/docker-compose.yaml`, issue #48).

**Security For WooCommerce** (plugin slug
`ultimate-security-for-woocommerce`), through 1.0.16 —
CVE-2026-123695, **CRITICAL 9.8**, CWE-269, published
2026-11-11T06:17Z:

- The plugin does not restrict access to several of its REST API
  routes (WPScan titles the entry "REST API Options Update and User
  Token Disclosure").
- An unauthenticated user can **generate login tokens for every
  user, retrieve them, and log in as any user, including
  administrators**.
- WPScan lists the entry as PRIVESC, researcher Aabideen Bangash,
  published 2026-11-09, and — the detail that matters most right
  now — **"No known fix"**, with the proof of concept scheduled for
  publication on 2026-12-09, so the window between disclosure and
  public exploit code is still open.

Sources: NVD CVE-2026-123695; WPScan vulnerability
ad945f05-fc7e-4dad-8a37-b9a6a7acf7e0 (verified 2026-11-12).

## Why it's DPoP-shaped

Both cases are the same sentence with the verb changed: the token
string *is* the account, and nothing else is asked for. NextScan is
the forgery family's ninth occurrence in the series — #8 Hitachi,
#9 mcp-context-forge, #20 Kener, #21 nest-admin, #26 OpenDeepWiki
and ng-antd-admin, #27 AJ-Report, #30 OFBiz, #34 WHMS and Versa —
and now a vulnerability scanner that ships its own signing key in
the open. WooCommerce is the family's mirror image: no forgery is
needed at all, because the server itself mints the victim's login
token on request and hands it over.

The proof-key-hands test passes for both, and the two cases show
why it has two halves. In NextScan, the attacker mints the token
himself but holds no legitimate holder's proof key — the forged
string has no key behind it, exactly the #34 distinction. In
WooCommerce, the token is genuinely issued, but it is issued *for
the victim*: the attacker retrieves the victim's credential and
presents it without the victim's key. In both, a sender-constrained
token presented without its holder's private key is a string the
resource server will not honour, however perfectly formed it is.

The honest boundary, as ever: DPoP does not fix either underlying
bug. NextScan deployments must replace the hardcoded key and watch
upstream issue #48 for a fixed release — there is none named yet,
and the key, like the WHMS one, is public. WooCommerce sites must
restrict those REST routes; there is no known fix as of 2026-11-11,
and the PoC date (2026-12-09) is a deadline, not a rumour. One
further limit, specific to WooCommerce: the binding has to be to
the *account owner's* key at issuance. If a token-generation
endpoint let the caller supply the binding key, the attacker would
simply bind his own — the control only works when the server binds
the token to the key of the account the token is for, not to
whoever asked for it. And neither project is Python, so this is
analysis only: no pydpop plug, no upstream patch to write from
here. What the pair gives the series is the two shapes of the same
failure side by side on one day — forge the token, or ask for it —
and the same answer to both: make the token worthless without its
key, so the next hardcoded secret, and the next unguarded route,
buy the attacker nothing.
