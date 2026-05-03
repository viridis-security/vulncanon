# VC-AI-ACTION-0001 — Irreversible Action Executed Without Confirmation

**Class**: AI Agent Irreversible Action · **Severity**: High

## The invariant

> Irreversible side effects must not execute in the same turn the prompt arrives. They require an out-of-band confirmation token bound to the planned action's hash.

## The pattern

A user types "send the report to my team", the agent calls `send_email`, the email goes out. Now imagine: the user types "delete the project", and the agent calls `delete_project`. There is no rollback path. If the agent misunderstood, mis-pronoun-resolved, or was prompt-injected, you've lost data.

The vulnerable shape: any tool with a permanent side effect is called in the same control-flow path as the prompt that triggered it.

## The fix

Two-turn flow with a confirmation token:

1. Turn N — user asks. Agent emits a *plan* with a `pending_action_id` and a hash of the canonicalized arguments. The action does NOT execute.
2. Turn N+1 — user (or a separate authorization channel) supplies the matching `confirmation_token`. The dispatcher hashes the plan again and compares; on match, it executes; on mismatch, it rejects.

This converts every irreversible tool into a stateful protocol the LLM cannot bypass even under prompt injection.

## The test

Both fixtures call `delete_project({ id: 'p-1' })` in a single turn with no confirmation token.

- `vulnerable_fixture` — the project is deleted. Assertion fails. Exit non-zero.
- `patched_fixture` — the dispatcher returns `{ status: 'pending_confirmation', token_hash, plan_id }`, the project survives. Exit 0.
