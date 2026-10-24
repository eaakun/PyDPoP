# Eighteen Token Thefts, One Missing Control

## The incident

**CVE-2026-107685** (published 2026-10-23; CVSS 4.0
`AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H` — HIGH) in **req_llm**, the Elixir
LLM client library (agentjido), GHSA-6vww-5m28-f26v, fixed in 1.29.0:

- Affected: req_llm ≥ 1.9.0, < 1.29.0 — a long vulnerable window across
  twenty minor versions of a young, fast-moving library.
- The WebSocket streaming client
  (`ReqLLM.Streaming.WebSocketSession.Client.start/3`) starts WebSockex
  **without TLS options**, and WebSockex 0.5.1 defaults to
  `insecure: true` — i.e. `verify: :verify_none`. Worse, the option
  allowlist in `start/3` drops any caller-supplied `cacerts` or
  `ssl_options`, so an application **cannot turn verification on** even
  if it tries.
- The OpenAI Responses, Realtime, and Codex WebSocket paths send the
  `authorization` header — the OpenAI **API key or OAuth access
  token** — over this connection. An on-path attacker who terminates
  TLS with their own certificate receives the upgrade request with the
  bearer token, sees every frame of the session, and can rewrite frames
  in either direction (CAPEC-94, Adversary in the Middle).
- HTTP streaming through Finch and the HTTP/2 duplex session through
  Mint verify certificates and are not affected; the CNA's only
  workaround on affected versions is "do not use the WebSocket paths".
- Sources: NVD record (published 2026-10-23); CNA
  (cna.erlef.org/cves/CVE-2026-107685.html, ErlEF security working
  group, coordinated by Jonatan Männchen); fix commits in
  agentjido/req_llm.

## Why it's DPoP-shaped

The attacker's objective is the oldest one in this series: **take the
captured bearer string home and use it from another machine** — against
OpenAI's APIs, where an OAuth access token is a first-class identity
document. That is precisely the step DPoP (RFC 9449) breaks: a
sender-constrained access token is inert without the proof-of-possession
key, so the upgrade-request capture yields a dead string. Same class as
#6 (mcp-remote cleartext device-code flow) and #13 (Camel redirect
re-attachment) — transit exposure is inevitable in some deployments,
but "the string is the identity" is a design choice, not a law of
nature.

## Notes / honesty checks

- DPoP fixes "the stolen token can be replayed", not the root cause:
  missing certificate verification (CWE-297) still needs the 1.29.0
  patch — an attacker who can already read and rewrite session frames
  can alter model output and tool calls, and no token binding stops
  that. Real fix first, DPoP as the last line.
- Only the **OAuth access-token path** is DPoP-shaped. Static OpenAI
  API keys sent through the same header are not OAuth tokens and DPoP
  cannot bind them — say that plainly when the advisory's "API key or
  OAuth access token" is quoted.
- Elixir project; pydpop is Python. No product plug — "shape of the
  fix" narrative only.
