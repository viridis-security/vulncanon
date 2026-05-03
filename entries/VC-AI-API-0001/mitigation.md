# Mitigation — VC-AI-API-0001

## Required controls

1. **Fixed outbound allowlist.** Every host the agent is permitted to POST to is enumerated in a config file. Any other destination is rejected at the dispatcher. Tool-scoped allowlists are stronger: the `stripe_tool` may only reach `api.stripe.com`; the `slack_tool` may only reach `slack.com`.
2. **Data classification at the source.** Records leave the database with a class tag (`private`, `internal`, `public`). The agent runtime preserves the tag through tool calls. The egress guard checks the body for private-tagged fields and refuses to send them to non-private-allowlisted destinations.
3. **Body classifier defense in depth.** Even untagged bodies are scanned for known sensitive patterns: email regex, AKIA…, sk-…, xoxb-…, AWS account numbers, US SSN format, JWT structure. Hits raise the body class to `private`.
4. **No "trust the LLM" allowlist.** The model cannot widen the allowlist via prompt or tool args. Allowlist is a server-side static config.
5. **Audit every outbound call.** Append-only log of `{tool, destination, body_class, allowed, ts}`. Alert on `body_class=private` regardless of allow decision so analysts can detect sustained exfil attempts.
6. **Rate-limit by destination.** Per-host outbound budget per session. A burst of POSTs to a single host is a strong exfil signal.

## Anti-patterns

- A generic `http_post(url, body)` tool with no per-call allowlist check.
- Allowlist-by-regex on the URL string (attackers use IDN, subdomain takeover, open redirects).
- Trusting `Origin` / `Referer` / "the LLM said so".
- Putting customer PII through analytics tools without classification (the LLM doesn't know what's PII).

## Regression test

`patched_fixture/exploit.test.js` attempts to exfiltrate a tagged-private profile to `attacker.example`. CI must run on every change to outbound HTTP, tool definitions, or the data classification layer.
