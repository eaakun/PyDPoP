# Forty-Eight Token Thefts, One Missing Control

## The incident

**Kerberos Agent**, before 3.14.4 — CVE-2026-135208,
**CRITICAL 9.8**, published 2026-11-23T16:17Z:

- `JWTMiddleWare()` falls back to the hard-coded key
  `TOBECHANGED`. An unauthenticated attacker can sign HS256
  tokens with arbitrary username and role claims.
- The forged tokens open the `/api` and `/config` routes:
  RTSP, ONVIF, Hub, and encryption keys are exposed,
  configuration can be rewritten, and the camera can be
  stopped.
- Fixed in 3.14.4. Upstream: kerberos-io/agent,
  GHSA-3c52-7fc8-c39j, PR #361.

Kerberos Agent is the open-source video-surveillance agent
that turns cameras into a managed fleet. The key is not
merely hard-coded — it is a placeholder. Somebody wrote
`TOBECHANGED` where the signing secret goes, and nobody
changed it before the release shipped. The most literal
member of the forgery family yet: the secret announces
itself as a to-do item.

Sources: NVD CVE-2026-135208; the GitHub security advisory
linked in the NVD record.

## Why it's DPoP-shaped

The forgery family's fifteenth occurrence. The shape is
unchanged since Hitachi #108336 opened the family: a
signing key that is public by construction, a forged
token that the verifier accepts, an administrator that
never logged in. The forged object is a JWT admin token —
the same object DPoP was designed to bind. A
sender-constrained token is two objects, not one: the
string and the key that must present it. Knowing
`TOBECHANGED` mints the string; it does not mint the
proof key, and the forged token fails the moment it is
presented without it.

The honest boundary, as ever: DPoP does not fix the
underlying bug. The fallback must go, the key must be
deployment-generated, and every deployment that ran the
default must rotate — a forged token stays valid until
the key it was signed with is retired. The fix is one
line of configuration and one rotation; the lesson is the
one the series has now written fifteen times, and this
time the codebase said it out loud: change the key, or
the key is the vulnerability.
