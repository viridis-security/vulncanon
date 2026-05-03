# VC-AI-SECRETS-0001 — Session Secrets Leaked via Tool Call Arguments

**Class**: AI Agent Memory Disclosure · **Severity**: High

## The invariant

> Session secrets must never appear verbatim in tool call argument JSON. Tools reference secrets by an opaque server-side handle.

## The pattern

The LLM is told (via system prompt or by the agent runtime) that it has an API key. It is then asked to call a tool, and it dutifully includes the key in the args:

```json
{
  "name": "stripe.charge",
  "args": { "apiKey": "sk_live_EXAMPLE_NOT_REAL...", "amount": 4200 }
}
```

That JSON is now in:
- The LLM provider's transcript (you don't control the retention).
- Your observability stack's request log (probably indefinitely).
- Distributed traces (Datadog, Honeycomb, OpenTelemetry).
- Error reports if any tool throws (Sentry).
- Any audit trail.

A read of any one of those sinks yields the key. The blast radius is enormous and *not bounded by the agent's own security model*.

The vulnerable shape: secrets *travel* in args.

## The fix

Capability handles. Secrets live in a server-side vault. Tools receive an opaque handle:

```json
{
  "name": "stripe.charge",
  "args": { "apiKeyRef": "cap:7c4f1a", "amount": 4200 }
}
```

The dispatcher dereferences `cap:7c4f1a` immediately before calling the underlying Stripe SDK. The dereferenced value never crosses the trace boundary. Loggers redact dereferences. The LLM context never contains a raw secret; if the model "sees" the secret it can also serialize it back, which is the bug.

```js
// PATCHED
async function dispatch(call) {
  const tool = TOOLS[call.name];
  const args = await resolveCapabilityHandles(call.args);  // server-side deref
  return tool.run(args);
}
```

## The test

Both fixtures expose `agentChargeCard(toolName, args)`. The test inspects an observability sink (`state.tracedCalls`) and asserts the trace contains no string matching the secret's signature.

- `vulnerable_fixture` — args carry the raw `sk_live_...` key, the trace records it, the regex match fires, assertion fails, exit non-zero.
- `patched_fixture` — args carry only `apiKeyRef`, dispatcher dereferences and calls Stripe; trace stores the handle (not the secret), exit 0.

## Detection

`detection.signature_regex` flags assignment of `apiKey` / `secret` / `bearer` / `password` / `access_token` etc. to a 12+ char alphanumeric value. `exclude_regex` suppresses when capability-handle indirection (`apiKeyRef`, `process.env`, `getSecret()`) is present.
