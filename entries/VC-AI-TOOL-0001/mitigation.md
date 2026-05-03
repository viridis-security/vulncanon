# Mitigation — VC-AI-TOOL-0001

## Required controls

1. **Capability-tagged tool registry.** Every tool declares a `privileged: boolean` (or a required capability set). Treat the registry as the policy surface, not the dispatcher.
2. **Permission gate at the dispatcher.** Before any privileged tool runs, the dispatcher resolves `session.permissions` and throws `PermissionDeniedError` on mismatch. The gate must be unconditional and run before any tool side effects.
3. **Permission state binding.** Capabilities are bound to a session, not to the user, not to the agent, not to the LLM. Sessions are short-lived and require reauthorization for elevation.
4. **Audit log.** Every privileged dispatch — whether allowed or denied — emits an audit record `{ session_id, tool_name, args_hash, decision, ts }`. Logs are append-only and exfilable to SIEM.
5. **Default-deny.** New tools default to `privileged: true`. Demoting a tool to non-privileged requires an explicit code review, not an env flag.

## Anti-patterns to reject in code review

- A `dispatch` function that calls `tool.run(...)` without a preceding permission check in the same control flow.
- Permission checks performed only in the LLM system prompt ("only call this tool if the user is admin"). System prompts are advisory; only code is enforcement.
- Permission checks based on the *prompt content* rather than the *session*. An attacker can write any prompt; only the session is server-controlled.
- Checks that compare to a constant like `if (user.role === 'admin')` without re-validating the session token.

## Regression test

`patched_fixture/exploit.test.js` is the canonical regression test. It MUST exit 0 against any future implementation. Drop a copy into your CI as `vulncanon/VC-AI-TOOL-0001.test.js` and run it on every commit that touches the dispatcher.

## Patch verification (Phase 2)

When `vulnc verify-patch` lands, applying any candidate patch should:
1. Cause `vulnerable_fixture/exploit.test.js` to start exiting 0 (invariant restored).
2. Cause `rule.semgrep.yml` to stop matching the patched code.

If either fails, the patch is incomplete.
