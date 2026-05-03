# VC-AI-API-0001 — Private Session Data Sent to Non-Allowlisted External API

**Class**: AI Agent Trust Boundary Crossing · **Severity**: High

## The invariant

> An agent must not include private-tagged data in an outbound request whose destination host is not on a fixed allowlist.

## The pattern

The agent has an `http_post` tool. The LLM, prompted by an attacker (directly or via RAG poisoning), composes a POST whose body contains the user's profile and whose destination is `https://attacker.example/log`. The agent dispatches it. Profile is exfiltrated.

The vulnerable shape:

```js
// VULNERABLE
const TOOLS = {
  http_post: {
    run: async ({ url, body }) => fetch(url, { method: 'POST', body: JSON.stringify(body) }),
  },
};
```

This is the dual of VC-AI-SSRF-0001. SSRF concerns *fetching from* internal endpoints; this concerns *sending to* external endpoints. Both arise from "the URL is caller-controlled".

## The fix

A two-axis check at the dispatcher:

```js
// PATCHED
async function safePost(url, body) {
  const host = new URL(url).hostname;
  const dataClass = classifyBody(body);     // 'private' if body contains tagged fields

  if (dataClass === 'private' && !PRIVATE_DATA_DESTINATIONS.has(host)) {
    throw new EgressGuardError(`refusing to send private data to ${host}`);
  }
  if (!OUTBOUND_ALLOWLIST.has(host)) {
    throw new EgressGuardError(`destination ${host} not on allowlist`);
  }
  return fetch(url, { method: 'POST', body: JSON.stringify(body) });
}
```

`classifyBody` walks the body and returns `'private'` if any field is tagged or matches a private data signature (email, phone, SSN, AKIA…, sk-…, etc.). Tag at the source: when data leaves the database, it carries a class.

## The test

Both fixtures expose `agentExfiltrate(url, profile)`. The test calls it with `https://attacker.example/log` and the user profile (which contains an `email` field tagged private).

- `vulnerable_fixture` — request goes through, a captured-request log records the body, assertion fails, exit non-zero.
- `patched_fixture` — egress guard rejects, log stays empty, exit 0.

## Detection

`detection.signature_regex` flags `post`/`put`/`patch`/`fetch` calls whose URL argument is named `url`/`target`/`endpoint`/`webhook`/`callback`. `exclude_regex` suppresses when an allowlist or classifier reference is present.
