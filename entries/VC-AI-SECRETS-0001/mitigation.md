# Mitigation — VC-AI-SECRETS-0001

## Required controls

1. **Server-side capability vault.** Every secret the agent might use lives in a vault keyed by an opaque handle. The vault is the only thing that knows the secret's value. Handles look like `cap:7c4f1a` and carry no information about the secret itself.
2. **Handle indirection in tool args.** Tools that need a secret declare a capability slot in their schema (`apiKeyRef: CapabilityHandle`). The LLM populates this with a handle, never with the raw secret. The runtime gives the LLM a list of available handles; the LLM picks one by purpose, never by content.
3. **Just-in-time dereference.** The dispatcher resolves handles to values *immediately before* calling the tool implementation. The dereferenced value lives only on the call stack of `tool.run` and never escapes into args, traces, logs, or LLM context.
4. **Trace and log redaction.** The observability layer redacts capability handles to `cap:****` and absolutely refuses to record anything that looks like a known secret format (AKIA…, sk-…, xoxb-…, JWT, etc.). Defense in depth — even if a secret slips through, it gets caught at the sink.
5. **Per-tool capability scoping.** A handle minted for the Stripe tool cannot be dereferenced by the Slack tool. Capabilities are bound to tool name at mint time.
6. **TTL and revocation.** Handles expire (e.g., 1 hour) and can be revoked instantly. Stolen handles have a small blast radius compared to stolen raw secrets.
7. **Egress redaction.** When the LLM emits text to the user, scan for known secret formats and refuse — secrets that the model has no business knowing should not appear in output. Combined with VC-AI-PROMPT-0001's output filter, this closes the loop.

## Anti-patterns

- `args: { apiKey: process.env.STRIPE_KEY }` — even if env-sourced, the secret is now in the args object that gets logged.
- "Redaction by string replace" of known secret formats *after* logging. Logs are append-only; redaction post-hoc doesn't fix already-leaked entries.
- Putting a secret in the system prompt as `Your API key is sk-...`. Now the LLM "knows" the secret and can serialize it via VC-AI-PROMPT-0001.
- Stuffing secrets into a "context" or "memory" field that gets joined into prompts.

## Regression test

`patched_fixture/exploit.test.js` exercises the canonical scenario: a tool call that requires an API key. CI must run on every change to tool args, dispatchers, capability vault code, or observability sinks.
