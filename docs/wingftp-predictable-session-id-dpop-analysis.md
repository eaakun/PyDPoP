# Fifty Token Thefts, One Missing Control

## The incident

**Wing FTP Server**, before 8.2.8 — CVE-2026-135171,
**HIGH 8.1**, published 2026-11-23T15:17Z:

- Session identifiers are predictable, derivable from
  process, time, `ServerID`, and client IP state.
- An unauthenticated attacker can enumerate candidate
  identifiers using the `service_get_license.html`
  endpoint as a validity oracle, and replay live sessions
  to gain administrative control — including the Lua
  console.
- Fixed in 8.2.8. Upstream: wftpserver.com, VulnCheck
  advisory.

Wing FTP Server is a commercial file-transfer server
with a web administration console. The session
identifier is not random; it is arithmetic on state the
attacker can observe or guess. The oracle endpoint
turns guessing into a testable search: each candidate
identifier gets a yes-or-no answer, and the first yes
is an administrator's live session, Lua console
included.

Sources: NVD CVE-2026-135171; the VulnCheck advisory
linked in the NVD record.

## Why it's DPoP-shaped

The forgery family's sixteenth occurrence — and the
second predictable-session-identifier specimen after
FlowIntel #133652, the thirteenth. FlowIntel's session
identifier was a bare numeric user ID; Wing FTP's is a
derivable function of process, time, server ID, and
client IP. The arithmetic differs; the shape is the
same. There is no secret in the credential, or none
the attacker cannot compute: the value that proves who
you are is a function of observable state, and the
first row — the administrator — is one enumeration
away.

The proof-key-hands test passes. The forger holds no
proof key for the victim — he holds a prediction. A
sender-constrained credential is two objects, not one:
the string and the key that must present it. A session
issued as a bound token would fail the moment it is
presented without its holder's private key, and no
amount of enumerating identifiers would mint a working
session. That is the same answer the series gave for
FlowIntel: the predicted string is unredeemable without
the holder's private key.

The honest boundary, as ever: DPoP does not fix the
underlying bug. Session identifiers must be random,
credential-bound, and rotated — and the oracle endpoint
that answers yes-or-no to candidate identifiers must
not exist in a form the attacker can query. Two further
limits, specific to this case: the forged object is a
browser session identifier, not an OAuth access token,
so the DPoP angle is the sender-bound-credential shape
rather than RFC 9449 itself (the same boundary the
series drew for FlowIntel #133652 and OpenAM #45049);
and session fixation and revocation semantics are
outside DPoP's claim, as always. Sixteen times now, the
credential that proved identity was public by design or
by arithmetic — and sixteen times the fix has been the
same: make the token random, bind it to its holder, and
revoke it when the session ends.
