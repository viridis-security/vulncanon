# VC-AI-SSRF-0001 — Agent-Coerced SSRF to Internal and Metadata Endpoints

**Class**: AI Agent Trust Boundary Crossing · **Severity**: Critical

## The invariant

> An agent's outbound HTTP tool must reject requests targeting private, link-local, loopback, or cloud metadata addresses — including after DNS resolution and HTTP redirects.

## The pattern

Give an LLM a `fetch_url` tool with no validation, and any prompt that reaches the model can coerce a fetch of `http://169.254.169.254/latest/meta-data/iam/security-credentials/`. That returns IAM credentials in cloud environments. Same surface: internal admin endpoints, *.consul, *.svc.cluster.local, localhost debug ports. Capital One 2019 was this exact bug at a different layer.

The vulnerable shape:

```js
// VULNERABLE
const TOOLS = {
  fetch_url: {
    run: async ({ url }) => (await fetch(url)).text(),
  },
};
```

Three sub-bugs that compound it:

1. No URL parse / host check before fetch.
2. No re-check after DNS resolution (an attacker can control a public hostname that resolves to a private IP — *DNS rebinding*).
3. No re-check after redirects (an external URL can `302` to `http://169.254.169.254`).

## The fix

A pre-fetch guard:

```js
// PATCHED
async function safeFetch(url) {
  const resolved = await assertSafeUrl(url);   // throws on private IP, metadata host, etc.
  return fetch(resolved, {
    redirect: 'manual',                         // we re-validate redirects ourselves
  }).then(handleRedirectChain);
}
```

`assertSafeUrl` parses the URL, resolves the hostname to all A/AAAA addresses, and rejects if any of them is private/loopback/link-local/metadata. It also rejects `file://`, `gopher://`, raw IPv6, and obviously bad schemes.

For maximum safety, prefer an *allowlist* of known external destinations (the agent rarely needs to fetch arbitrary URLs).

## The test

Both fixtures expose `agentFetch(url)`. The test calls it with `http://169.254.169.254/latest/meta-data/iam/security-credentials/admin-role` and asserts the request is **rejected**.

- `vulnerable_fixture` — fetch goes through, mocked metadata service returns a fake IAM credential, assertion fails, exit non-zero.
- `patched_fixture` — `assertSafeUrl` throws SSRFGuardError, exit 0.

## Detection

`detection.signature_regex` flags fetch/axios/http calls whose URL argument comes from a parameter named `url`/`target`/`endpoint`/`href`/`link` — i.e., caller-controlled. `exclude_regex` suppresses when an SSRF guard reference is present in the same file.
