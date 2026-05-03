# Mitigation — VC-AI-SSRF-0001

## Required controls

1. **Pre-fetch URL guard.** Every outbound HTTP call goes through a single `safeFetch` (or equivalent) function. The guard parses the URL and rejects:
   - Schemes other than `http:`, `https:` (no `file:`, `gopher:`, `data:`, etc.).
   - Hostnames that resolve to RFC1918 (`10/8`, `172.16/12`, `192.168/16`), loopback (`127/8`, `::1`), link-local (`169.254/16`, `fe80::/10`), unspecified (`0.0.0.0`).
   - Cloud metadata hosts: `169.254.169.254`, `metadata.google.internal`, `metadata.azure.com`, `100.100.100.200`, etc.
   - IPv6 unique local addresses (`fc00::/7`).
2. **Resolve-then-validate.** Resolve the hostname **before** the fetch and check every A/AAAA. After validation, fetch by IP (or pin via `lookup` callback) so DNS rebinding cannot swap the address between check and connect.
3. **Manual redirect handling.** Set `redirect: 'manual'` (or equivalent) and re-run the guard on every `Location:` header. Most native fetch libs follow redirects without re-validation by default — that is the bug.
4. **Allowlist over blocklist.** If the agent only needs to call known external APIs (Stripe, GitHub, OpenAI, etc.), allowlist those domains and reject everything else.
5. **Egress firewall.** Defense in depth: even if the in-process guard fails, the host's egress firewall blocks all RFC1918 / metadata traffic from the agent's network namespace.
6. **Disable IMDSv1.** On AWS, require IMDSv2 (token-based) — IMDSv1 is the surface SSRF historically targets. (This won't save you against an LLM-coerced fetch tool, but it raises the cost.)

## Anti-patterns

- `fetch(url)` directly inside a tool's `run` function with no guard.
- "Validation" via regex on the URL string. Attackers use IPv6 short forms, octal/hex IPs, decimal IP notation, IDN homoglyphs.
- Blocklist-only checks. Cloud providers add new metadata endpoints; new private ranges exist; an allowlist is the only reliable posture.
- Trusting the URL because it came from the LLM's "thought" rather than the user prompt. The LLM is part of the attack surface.

## Regression test

`patched_fixture/exploit.test.js` issues the canonical AWS metadata fetch attempt. CI must run on every change to outbound HTTP, tool definitions, or fetch wrappers.
