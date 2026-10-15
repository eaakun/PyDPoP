# Eight Token Thefts, One Missing Control

Hitachi Vantara is not a startup with a `.env.example` problem — it is an enterprise infrastructure vendor whose storage arrays sit in datacenters that bill by the rack. Its Remot Ops Agent, the remote-management layer for those deployments, shipped CVE-2026-108336, published October 14, 2026, rated CRITICAL (9.1). The vulnerability is CWE-321, use of hard-coded cryptographic key, and the key in question is almost poetic in its wrongness.

The bug: the agent's web interface uses its TLS certificate to sign JWT access tokens — the same certificate that terminates HTTPS is also the signing key for "this user is logged in." And when the appliance runs on its default self-signed certificate, that private key is not a secret at all: it ships with the product, identical on every unhardened deployment. An attacker who knows the default key can mint JWT access tokens at will, bypass login entirely, and walk in as an administrator — configuring the service, pulling logs. (Honest scope, per the advisory: device credentials and customer data are not reachable through this hole. Admin is bad enough.)

Two details make this one sting. First, this is a key-management failure wearing a TLS costume. A certificate's private key is an identity credential for the server; pressing it into service as a JWT signing key means the authentication of every user session now depends on a key whose entire job description is "present yourself to strangers." Second, the default is the vulnerability. Every deployment that never got around to installing a proper certificate — the exact deployments least likely to have a security team watching — shares one globally-known signing key. The patch is 2.1: stop trusting the default.

Different app, different bug, identical failure mode — the eighth time in this series: a bearer credential that anyone can produce, and a server that cannot tell the forger from the owner. The attacker never breaks crypto; the vendor shipped them the key.

To be precise about what DPoP can and cannot do here: RFC 9449 would not have fixed the default key — replacing it with a real secret (2.1) is the patch, full stop. But notice the shape of the failure. Authentication here reduces to "present a correctly-signed string," and the forged string is byte-for-byte indistinguishable from a legitimate admin's. That indistinguishability is the whole disease: theft, leak, misconfiguration, and forgery are all the same event to a bearer-token server. Sender-constrained tokens break the equivalence. With DPoP, possession of the token string is never sufficient — the proof key never leaves the client, so a token that can be copied, leaked, dumped, misconfigured, or minted is not a credential. The forged JWT still has to be presented, and presentation requires the key. The key rotation closes this hole; the control converts the entire class of "the string is the identity" failures into failures that require stealing an actual private key. Anywhere a bearer credential is the whole of authentication, binding it to the holder is the missing control.

I maintain pydpop ([github.com/eaakun/PyDPoP](https://github.com/eaakun/PyDPoP), `pip install pydpop`): a pure-RFC 9449 DPoP library for Python — ES256 proof generation plus full server-side verification, drop-in integrations for httpx/requests/aiohttp and FastAPI/Django/Flask/Starlette, post-quantum hybrid algs, v0.2.1 on PyPI, [live demo](https://huggingface.co/spaces/tatkuen/pydpop-demo). If this month sent you rotating secrets, DPoP is the control that makes the next theft a non-event.

---

**Sources**

- CVE-2026-108336 (NVD): https://nvd.nist.gov/vuln/detail/CVE-2026-108336
- Hitachi Vantara security advisory (solution 261012131624707): https://knowledge.hitachivantara.com/portal/app/portlets/results/viewsolution.jsp?solutionid=261012131624707&guest=0
