# VC-AI-CHAIN-0001 — Multi-Agent Delegation Expands Permission Scope

**Class**: AI Agent Authorization Failure · **Severity**: High

## The invariant

> The effective permissions for a delegated call must be `caller.permissions ∩ callee.permissions`, never `callee.permissions` alone.

## The pattern

This is the *confused deputy* problem (Hardy 1988) reborn in the multi-agent era. Agent A is talking to a low-privilege user. Agent A delegates a task to Agent B. Agent B is a service account with broad permissions (it has to be — it serves many callers). When B authorizes the delegated call, it checks **its own** permissions, not the caller's. The user has just used A as a stepping stone to wield B's powers.

The vulnerable shape:

```js
// VULNERABLE
async function delegate(toAgent, call, fromSession) {
  return toAgent.dispatch(call);   // toAgent uses ITS OWN permissions
}
```

## The fix

Capability-based delegation. The caller mints a capability token bound to its own permissions (or a subset), and the callee's dispatcher honors only that token:

```js
// PATCHED
async function delegate(toAgent, call, fromSession) {
  const token = mintDelegationToken({
    caller: fromSession.id,
    permissions: fromSession.permissions,   // caller's, not callee's
    tool: call.name,
    expiresAt: Date.now() + 60_000,
  });
  return toAgent.dispatch(call, { delegationToken: token });
}
```

The callee verifies the token, computes `effective = caller_permissions ∩ callee_permissions`, and authorizes against `effective`. Without a valid token, the callee refuses delegations entirely.

## The test

Both fixtures:

- Agent A: low-privilege session, **no** `delete_account` permission.
- Agent B: high-privilege service account, **has** `delete_account` permission.
- A delegates `delete_account` to B.

The test asserts that the account survives.

- `vulnerable_fixture` — B authorizes against its own permissions, deletes the account, assertion fails, exit non-zero.
- `patched_fixture` — B requires a delegation token; without it, refuses; account survives, exit 0.

## Detection

`rule.semgrep.yml` and `detection.signature_regex` flag the shape: a `delegate`/`handoff`/`spawn_agent` call without a `delegation_token` / `capability_token` / `effective_permissions` reference in scope.
