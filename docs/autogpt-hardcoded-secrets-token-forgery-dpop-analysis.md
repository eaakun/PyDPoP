# Forty-Seven Token Thefts, One Missing Control

## The incident

**AutoGPT Platform**, two CVEs published 2026-11-23T23:17Z, one
root cause — secrets shipped in `backend/.env.default`:

- CVE-2026-130169, **CRITICAL 10.0**, versions 0.6.26 through
  0.7.4: a publicly known, hardcoded default JWT verification
  key sits in `backend/.env.default` and
  `autogpt_platform/.env.default`. HS256 is symmetric, so
  anyone who knows the secret can forge valid JWTs for any
  user or for the admin role, bypassing authentication and
  authorization without user interaction. GHSA-24q6-6h89-f9p7.
- CVE-2026-132257, **HIGH 8.2**, versions 0.6.23 and above:
  a hardcoded default Fernet encryption key in
  `backend/.env.default` encrypts every user's OAuth tokens,
  API keys, and integration credentials in the
  `User.integrations` column. Anyone with read access to the
  database of a deployment using the default key can decrypt
  the stored credentials. GHSA-57mf-wqwq-6g6x.
- Both fixed in AutoGPT Platform 0.8.0. Upstream:
  Significant-Gravitas/AutoGPT.

The same 2026-11-23 batch also carried CVE-2026-133455
(HIGH 6.5, nested-tool billing credits) — a billing-logic
flaw, not a token class, recorded here and left out of the
series.

AutoGPT is the agentic workflow platform whose users hand
it their OAuth tokens so their agents can act on their
behalf — GitHub, Google, Slack, and every integration in
the catalogue. The two CVEs are the same failure seen from
both ends: the JWT key lets an attacker mint the tokens
that prove identity, and the Fernet key lets an attacker
unwrap the tokens that prove access to everything else.
One shipped default file, two directions of compromise.

Sources: NVD CVE-2026-130169 and CVE-2026-132257; the
GitHub security advisories linked in the NVD records.

## Why it's DPoP-shaped

The forgery family's fourteenth occurrence — and the
stored-token disclosure family's return. CVE-2026-130169
is the purest form of the family: the secret was never
leaked, only never secret, the same shape as AnsibleForms
#73969 and BISHENG #130840. The forged object is a
standard JWT access token itself, squarely on DPoP's home
ground: a sender-bound token is unredeemable without the
holder's private key, and no amount of knowing the signing
secret mints a working proof.

CVE-2026-132257 is the other half of the same lesson, and
the kin of Omnispace #63160 and Kruize #110975: a stored
bearer token is only as safe as the key that wraps it, and
here the wrapping key is public source. The decrypted
OAuth tokens are bearer strings, replayable against their
providers from anywhere. A DPoP-bound OAuth token would be
inert in the attacker's hands — the string without its
proof key buys nothing.

The honest boundary, as ever: DPoP does not fix the
underlying bug. Both keys must be replaced with
deployment-generated secrets, and every deployment that
ran on the defaults must rotate — the JWT key, the Fernet
key, and every OAuth token and integration credential the
Fernet key ever wrapped, because a decrypted token stays
valid until its provider revokes it. Three further limits:
the attacker needs database read access for the Fernet
half, so it is a disclosure gated on that access, not an
open endpoint; the static API keys and integration
credentials in the same column are not DPoP-bindable and
need their own rotation; and the DPoP angle on the OAuth
tokens is conditional on the providers issuing
sender-bound tokens, the same conditional the series drew
for kaniko #105769 — Entra issues plain bearer tokens
today, and so do most integration providers. Upgrade to
0.8.0, rotate everything, and stop shipping secrets in
`.env.default`.
