# Forty-Six Token Thefts, One Missing Control

## The incident

**Xen Orchestra (XO)**, before 6.9.2 and 6.10.1 — CVE-2026-133469,
**CRITICAL 9.8**, published 2026-11-23T17:17Z, **actively exploited in
the wild**:

- REST cookie parsing turns `authenticationToken=j:{}` into the
  empty object `{}`. REST authentication passes that object to the
  XO token provider without requiring a string.
- The token collection treats `{}` as an unfiltered lookup and
  returns its first token; the provider authenticates as that
  token's owner if it is unexpired. No credential is presented,
  no password is guessed, no secret is leaked — an empty object
  becomes a wildcard.
- Once authenticated, the `/rest/v0/users/me/authentication_tokens`
  route returns reusable login token IDs, so the attacker walks
  away with durable credentials for the account, not just one
  session.
- Fixed in 6.9.2 and 6.10.1. Upstream: vatesfr/xen-orchestra,
  GHSA-2r3w-c2vx-fv5g, Vates advisory VATES-SA-2026-062.

XO is the management plane for XCP-ng and XenServer
infrastructure — the console that visualizes, backs up, and
delegates whole virtualization fleets. The attacker needs no
account on the instance at all: one crafted cookie, and the
first unexpired token in the collection decides whose
infrastructure they now administer.

Sources: NVD CVE-2026-133469; the Vates security advisory
linked in the NVD record.

## Why it's DPoP-shaped

The second type-confusion case in the series, after Rucio
#100397 — and the first where the confusion is in the
token store itself rather than the validator. In Rucio, an
SSH challenge nonce was accepted as an auth token. Here, an
empty JSON object is accepted as a token lookup, and the
lookup answers with a real user's token. The string was
never issued to the attacker as an auth token at all; the
provider minted the authentication out of a type error.

The proof-key-hands test passes. The attacker holds no
proof key for the victim — he holds an empty object. A
sender-constrained login token is two objects, not one:
the string and the key that must present it. Presented
without its holder's private key, the stolen token fails,
and the reusable login token IDs the endpoint hands out
are inert in the attacker's hands for the same reason.
That is the same answer the series gave for Rucio: the
confusion is in the plumbing, but the damage is done by
the replay, and the replay dies on contact with a bound
token.

The honest boundary, as ever: DPoP does not fix the
underlying bug. The cookie parser must not turn `j:{}`
into a live object, and the token provider must require a
string before it queries the collection — that is a type
boundary, and it needs its patch. Two further limits: the
tokens at stake are XO login tokens, not OAuth access
tokens, so the DPoP angle is the sender-bound-credential
shape rather than RFC 9449 itself (the same boundary the
series drew for OpenAM #45049 and FlowIntel #133652); and
which account the attacker lands in depends on which
unexpired token the collection returns first — the
advisory's "actively exploited" note is the reason to
treat the worst case as the case. Upgrade to 6.9.2 or
6.10.1, and rotate every token the instance holds: any
token issued before the patch was issued into a world
where an empty object could claim it.
