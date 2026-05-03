# VC-AI-TOOL-0001 — Privileged Tool Call Without Permission Gate

**Class**: AI Agent Authorization Failure · **Severity**: High

## The invariant

> An AI agent must not execute a privileged external tool unless the active session contains an explicit valid permission state for that tool.

## The pattern

A typical agent stack looks like this:

```
user prompt → LLM → tool_call(name, args) → dispatcher → tool implementation
```

The dispatcher is the security boundary. Whatever the LLM "decides" to call, the dispatcher is the only thing that actually executes side effects. If the dispatcher does not check whether the active session is authorized to invoke a privileged tool, then *anyone whose prompt reaches the LLM* can trigger arbitrary privileged side effects — account deletion, payment movement, file exfiltration, infrastructure mutation.

The vulnerable shape is almost always a registry lookup with no gate:

```js
// VULNERABLE
async function dispatch(call, session) {
  const tool = TOOLS[call.name];
  return tool.run(call.args);   // no permission check
}
```

## The fix

Privileged tools must declare a required capability. The dispatcher resolves the session's capabilities and throws on mismatch:

```js
// PATCHED
async function dispatch(call, session) {
  const tool = TOOLS[call.name];
  if (tool.privileged && !session.permissions.has(tool.name)) {
    throw new PermissionDeniedError(tool.name);
  }
  return tool.run(call.args);
}
```

## The test

Both fixtures call `dispatch({ name: 'delete_account' }, session)` with a session that has *no* permissions. The test asserts that `accounts['victim']` still exists afterwards.

- `vulnerable_fixture` — the dispatcher calls `delete_account`, the account is gone, the assertion fails, the test exits **non-zero**.
- `patched_fixture` — the dispatcher throws `PermissionDeniedError`, the account survives, the assertion passes, the test exits **zero**.

`vulnc check` enforces both outcomes.

## Detection

`rule.semgrep.yml` matches the vulnerable shape: a tool registry lookup followed by `.run(` (or `.execute(`, `.call(`) within the same function, with no preceding capability/permission check.
