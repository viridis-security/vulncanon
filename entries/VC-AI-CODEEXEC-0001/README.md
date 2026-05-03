# VC-AI-CODEEXEC-0001 — Untrusted Tool Output Evaluated as Code Downstream

**Class**: AI Agent Trust Boundary Crossing · **Severity**: Critical

## The invariant

> Output from one tool must never be evaluated as executable code by a downstream tool or by the agent runtime.

## The pattern

A tool returns a string. The agent's "planner" or a downstream tool eval()s it to decide what to do next. Now any tool whose output an attacker can influence — `fetch_url`, RAG retrieval, file read, another agent — is a path to RCE on the host.

The vulnerable shape:

```js
// VULNERABLE
const result = await tools.fetch_url.run({ url });
const next = eval(result.next_action);   // RCE if attacker controls the page
next();
```

This is the same class as `eval(JSON.parse(req.body))` in classical web — except now the input source is an LLM-driven tool whose output crosses many trust boundaries on the way back.

## The fix

A fixed dispatch table indexed by a typed action name:

```js
// PATCHED
const ALLOWED_ACTIONS = {
  refresh: () => doRefresh(),
  cancel:  () => doCancel(),
};

const result = await tools.fetch_url.run({ url });
const parsed = parseAndValidate(result);    // throws if not in schema
const handler = ALLOWED_ACTIONS[parsed.action];
if (!handler) throw new Error('unknown action');
handler();
```

`eval` / `new Function` / `exec` / `execSync` are forbidden in the agent runtime. Enforce with a lint rule and CI gate.

## The test

Both fixtures call `runPlanFromTool(toolName)`. The vulnerable fixture's tool returns a "next_action" string that, if eval'd, calls `state.exfiltrate('PWNED')`. The test asserts `state.exfiltratedFlag === false` after the call.

- `vulnerable_fixture` — eval runs the payload, exfiltrate flag flips, assertion fails, exit non-zero.
- `patched_fixture` — dispatch table has no matching action, throws, flag stays false, exit 0.

## Detection

`detection.signature_regex` flags `eval(`, `new Function(`, `exec(`, `spawn(` whose argument is sourced from a variable named `result`/`output`/`response`/`content`/`body`/`data`/`next_action`/`plan` — the typical names for tool-return values.
