# Fifty-One Token Thefts, One Missing Control

## The incident

**DreameHome**, three CVEs from one research batch
(researcher je-lv, VulnCheck advisories), NVD-published
2026-11-23T19:17Z — the cloud API fixed 2026-10-14 and
the MQTT broker fixed 2026-10-26, so this is a
retrospective disclosure: the exposure window closed
about six weeks before the CVEs published, and the
disclosure itself is fresh:

- CVE-2026-49964, **HIGH 7.1**: `POST
  /dreame-user-iot/token/rtc2` is an insecure direct
  object reference — an authenticated attacker obtains
  an Agora RTC token for another user's device by
  supplying its device DID and owner UID. The endpoint
  issued the token without verifying device ownership,
  letting the attacker join the device's live-video
  channel and publish video under the targeted device's
  identity.
- CVE-2026-49960, **MEDIUM 6.5**: `POST
  /smart-app/meari-cloud/redirectAndLogin` takes a
  caller-supplied `uid` and selects the Meari account
  without verifying that it belonged to the account
  authenticated by the Dreame-Auth token. An
  authenticated attacker obtains another user's Meari
  camera-platform identity and session credentials —
  target UIDs are obtainable through public forum
  profiles and an email-to-uid lookup — and uses the
  leaked credentials to access live video, microphone
  audio, the camera speaker, and stored recordings of
  Meari-backed cameras.
- CVE-2026-49961, **MEDIUM 6.5**: the MQTT broker's
  incorrect authorization lets an authenticated
  attacker subscribe to another device's status topic,
  `/status/{DID}/{UID}/{model}/#`, without owning or
  having access to the device — and receive the
  device's telemetry, including compressed LiDAR map
  frames exposing the home's layout, the Wi-Fi SSID
  and BSSID, local IP address, gateway, firmware
  version, and the session key used for encrypted
  video.

DreameHome is the companion app for Dreame's robot
vacuums and cameras — devices that live inside people's
homes, with microphones, speakers, and lenses pointed
at their living rooms. All three flaws are the same
missing check in three places: the endpoint trusts the
identifier the caller supplies and never asks whether
the caller owns it. The attacker needs only an
authenticated account of their own and a victim's
public identifiers.

Sources: NVD CVE-2026-49964, CVE-2026-49960, and
CVE-2026-49961; the researcher's repository and the
VulnCheck advisories linked in the NVD records.

## Why it's DPoP-shaped

The victim-credential theft class, in the room where
people sleep. The attacker does not mint a token and
does not confuse the issuer: he asks the API for
somebody else's credential, and the API hands it over.
The Agora RTC token in CVE-2026-49964 and the Meari
session credentials in CVE-2026-49960 are the victim's
tokens, replayed from the attacker's device — the same
shape as OpenAM #45049, where a stolen session token
was replayed across every domain the session had logged
into. A sender-constrained credential is two objects,
not one: the string and the key that must present it.
Bound to the device owner's key, the issued token
fails the moment it is presented from the attacker's
session, and the live-video channel stays closed.

The honest boundary, as ever: DPoP does not fix the
underlying bug. The ownership check is the primary fix,
and it shipped in October; the disclosure is fresh, the
exposure is not. Three further limits: the Agora RTC
tokens and Meari session credentials are proprietary
platform credentials, not OAuth access tokens, so the
DPoP angle is the sender-binding principle rather than
RFC 9449 itself (the same boundary the series drew for
OpenAM #45049 and FlowIntel #133652); the MQTT case in
CVE-2026-49961 discloses a session key for encrypted
video, which is a static-key disclosure DPoP does not
cover — the key, once known, decrypts the stream from
anywhere; and the attacker must already hold an
authenticated DreameHome account, so this is a
cross-user attack inside the platform, not an
unauthenticated break-in. What DPoP changes is the
value of the credential the API should never have
issued: a token that only its owner can present is a
token the IDOR cannot spend.
