# Mitigation — VC-AI-ACTION-0001

## Required controls

1. **Tool taxonomy.** Every tool declares `irreversible: boolean`. Anything that mutates persistent state in a way that cannot be cheaply rolled back — delete, send, transfer, deploy, post — is `true`. Default is `true`; demoting requires an explicit code review.
2. **Two-turn confirmation protocol.** The dispatcher converts an irreversible tool call into a *plan* — `{ plan_id, tool, canonical_args, hash }` — and returns it. Execution is gated on a subsequent turn presenting a matching `confirmation_token` whose hash equals the plan's hash.
3. **Hash includes args.** The hash is over the canonicalized argument object so an attacker cannot reuse a confirmation token issued for a different action.
4. **Out-of-band confirmation channel for high-blast-radius tools.** For payments, deploys, mass-delete: confirmation must come over a separate channel (push notification, signed email link, hardware key) — not the same chat.
5. **Plan TTL.** Plans expire (e.g., 5 minutes). An expired plan cannot be confirmed.
6. **Append-only plan log.** Every plan and every confirmation/rejection is logged immutably for audit.

## Anti-patterns

- A `delete` tool that runs synchronously inside `dispatch`.
- "Confirmation" implemented as the LLM asking "are you sure?" in the chat. The model can be persuaded to skip it.
- Confirmation tokens that are not bound to the planned arguments.
- Reusing a single global confirmation token for an entire session.

## Regression test

`patched_fixture/exploit.test.js` attempts a single-turn delete. CI must run it on every change to the dispatcher or any tool flagged `irreversible: true`.
