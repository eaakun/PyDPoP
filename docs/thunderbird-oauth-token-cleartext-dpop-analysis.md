# Thirty-Three Token Thefts, One Missing Control

## The incident

The cleartext-theft shape the series has met in libraries and servers
has now shown up in a mainstream desktop mail client. **Thunderbird**
sent the user's OAuth2 access token over unencrypted HTTP — and an
attacker watching the network could pick it up and walk into the
mailbox with it.

Mozilla announced it on **2026-11-10** (MFSA 2026-128, CVE-2026-126136,
Bug 2085865, reported by Álvaro Chico Martínez, Mozilla impact
**moderate**; fixed in Thunderbird 160 and Thunderbird 153.7):

- For Exchange accounts using EWS or Microsoft Graph with OAuth2
  authentication, Thunderbird sent the OAuth2 access token to the
  server **even when the configured server URL used unencrypted
  HTTP**.
- An attacker able to observe network traffic could obtain the token
  and use it to access the user's mailbox **until the token expired**.
- An attacker positioned on the network during account setup could
  cause such a URL to be configured in the first place.

No CVSS score in the NVD record yet; Mozilla's own rating is moderate.
The exposure is bounded by the token's lifetime, and it needs a
network-positioned attacker — public Wi-Fi, a corporate network, a
compromised router — but Exchange + Microsoft Graph OAuth is the
default way Thunderbird talks to Microsoft 365 mail, so the
population at risk is every Thunderbird user on an HTTP-configured
Exchange account.

Sources: NVD CVE-2026-126136; Mozilla Foundation Security Advisory
2026-128 (https://www.mozilla.org/security/advisories/mfsa2026-128/)
and 2026-129 (Thunderbird 153.7,
https://www.mozilla.org/security/advisories/mfsa2026-129/).

## Why it's DPoP-shaped

The token was the identity, and the token travelled in the clear.
Nothing was broken into and no password was guessed: the client
itself handed a working mailbox credential to anyone listening on the
wire, and the credential was replayable from anywhere until it
expired. That is the series thesis in its simplest form — possession
of the string is possession of the account.

Same family as #6 (mcp-remote's device-code OAuth tokens in
cleartext), #13 (Camel re-attaching `Authorization: Bearer` to
redirect targets), #18 (req_llm's WebSocket bearer header readable
on-path), and #31 (Vikunja's bearer token sent to an attacker-chosen
API URL): the delivery layer differs — a missing TLS check, a
redirect, a cleartext flow, a URL switch — and the missing control is
identical.

Two checks matter here, and both cut in favour of the DPoP reading:

1. **The proof-key-hands test passes.** The token was issued to
   Thunderbird, not to the attacker. The attacker holds the string
   and nothing else. A sender-constrained token would have been dead
   in his hands: the string alone is not sufficient without the
   holder's private key, and the key never crossed the wire. This is
   the opposite of the near-misses the watch keeps filtering
   (Keycloak CVE-2026-19688, IBM API Connect CVE-2026-16720), where
   the token is minted to the attacker himself and the proof key
   travels with him.
2. **The theft channel is the network itself.** No server flaw, no
   phishing page, no malware — just a client that sent a bearer
   credential where anyone could read it. Sender binding is the
   control designed exactly for this: it makes the wiretap worthless
   even when the transport fails.

The honest boundary, as ever: DPoP does not fix the bug. Thunderbird
must not send tokens over HTTP, and the fix is to upgrade to 160 or
153.7 — the patch closes this door. Two further limits: the token's
short lifetime bounds the damage (the replay window is "until the
token expired", not forever), and the DPoP angle is conditional on
sender-bound issuance — Microsoft's EWS/Graph flow issues plain
bearer tokens today, so the defence only bites if the token is issued
DPoP-bound (the same caveat as #28 kaniko). The setup-time
URL-planting angle is a separate configuration-trust issue that
sender binding does not address.

Thunderbird is not a Python project, so this is analysis only: no
pydpop plug, no upstream patch to write from here. What the incident
does give the series is its first cleartext-theft specimen in a
mainstream end-user client — proof that the bearer-string problem is
not a library bug or a server misconfiguration, but a property of the
token format itself, present wherever a client can be made to send
the string somewhere it should not go.
