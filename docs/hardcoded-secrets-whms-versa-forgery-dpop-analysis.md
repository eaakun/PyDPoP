# Thirty-Four Token Thefts, One Missing Control

## The incident

Two hardcoded-secret forgeries, published within about an hour of
each other on the same day — the forgery family the series keeps
meeting, twice over before lunch.

**INDOTALENT WHMS** (Asp.Net-Core-Inventory-Order-Management-System),
before 10.20261109 — CVE-2026-125383, **CRITICAL 9.3**, CWE-321,
published 2026-11-10T00:17Z:

- The application shipped a **hard-coded JWT signing key, issuer,
  and audience** in `appsettings.json`.
- An unauthenticated remote attacker can forge tokens for **any user
  ID and any role** that the `Tokens/DI.cs` validator trusts, gaining
  administrator access to the entire API.
- Fixed in 10.20261109.

Sources: NVD CVE-2026-125383; repository
go2ismail/Asp.Net-Core-Inventory-Order-Management-System
(`appsettings.json`, fix commits 65609b5 and ded7d8a).

**Versa VOS** (previously Versa FlexVNF) — CVE-2026-107244,
**HIGH 7.6**, CWE-1390, published 2026-11-10T01:17Z:

- The Node.js web service used for URL-based Zero Touch Provisioning
  (ZTP) registers its `/decryptTest` endpoint **before the session
  authentication middleware**, and creates a fully authenticated
  session whenever it receives a token that decrypts successfully.
- The **key and initialization vector used for decryption are
  hardcoded and identical across all VOS appliances** — so an
  unauthenticated attacker with network access can compute a valid
  token offline and submit it for a fully authenticated session,
  without providing any credentials.
- Gating: the flaw is not exploitable on VOS devices where the Node.js
  web service has been disabled, and Versa's hardening guide for
  Hubs, Branches, and Controllers recommends disabling it after the
  initial provisioning.

Sources: NVD CVE-2026-107244; Versa security bulletin
(https://security-portal.versa-networks.com/emailbulletins/6af22b38dd1c93ddc0a3e83a).

## Why it's DPoP-shaped

Nothing is stolen in either case — the credential is minted on
demand, from a secret the vendor shipped in the open. The attacker
never touches the victim's account, password, or second factor; the
forged string *is* the account. That is the forgery family's purest
shape, and the series has now met it eight times: #8 Hitachi, #9
mcp-context-forge, #20 Kener, #21 nest-admin, #26 OpenDeepWiki and
ng-antd-admin, #27 AJ-Report, #30 OFBiz — and now WHMS and Versa.

The proof-key-hands test passes for both, and the distinction is
worth stating precisely, because it is what separates these two from
the near-misses the watch keeps filtering: the attacker mints the
token himself, but he does **not** hold any legitimate holder's proof
key. The forged string has no key behind it. In the filtered
near-misses (Keycloak CVE-2026-19688, IBM API Connect
CVE-2026-16720, ZITADEL CVE-2026-119129), the token is minted to the
attacker's own client and the proof key travels with him — sender
binding changes nothing there. Here it changes everything: a
sender-constrained token presented without its holder's private key
is a string the resource server will not honour, however perfectly
signed it is.

The honest boundary, as ever: DPoP does not fix the hardcoded
secret. WHMS deployments must upgrade to 10.20261109 **and** replace
the shipped secret — the key in `appsettings.json` is public, and
every instance still running it accepts forged tokens. Versa
deployments must disable the ZTP web service after provisioning
**and** rotate the key and IV — upgrading alone leaves the old
secret in place, the same "patched is not protected" gap #26 and
#30 already documented. Two further limits: the Versa token is a
proprietary ZTP session token, not a JWT or OAuth access token, so
DPoP as specified does not bolt onto it directly — the argument is
that sender-constraining the credential at the point it is presented
kills exactly this replay; and WHMS is a small inventory system,
not a mainstream project — its CRITICAL score is what qualifies it
under the watch's bar, and the write-up is the lesson, not the
blast radius.

Neither project is Python, so this is analysis only: no pydpop plug,
no upstream patch to write from here. What the pair does give the
series is a measure of the family's persistence — two vendors, two
token formats, the same mistake, the same morning — and the clearest
possible statement of the fix hierarchy: rotate the secret first,
and then make the token worthless without its key, so the next
hardcoded secret buys the attacker nothing.
