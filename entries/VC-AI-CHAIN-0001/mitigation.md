# Mitigation — VC-AI-CHAIN-0001

## Required controls

1. **Capability-token delegation.** Every delegation from agent A → agent B carries a signed token containing `{caller_id, caller_permissions_subset, tool_name, exp}`. The token is minted by A's runtime, signed by a trusted authority, and bound to a single tool invocation.
2. **Intersection at the callee.** B's dispatcher computes `effective = caller_permissions ∩ B.permissions` for the delegated call. Authorization runs against `effective`, never against `B.permissions` directly.
3. **Default-refuse delegations.** If no valid token is present, B refuses all delegations from A. Internal tools that B uses on its own behalf still work; cross-agent calls without tokens do not.
4. **Tokens are short-lived and single-use.** TTL ≤ 60 seconds. After redemption the token is consumed and rejected on replay.
5. **Audit lineage.** Every privileged dispatch logs the full delegation chain (`A → B → C`) and the effective permission set used. SIEM alerts on unexpected lineage shapes.
6. **No "agent" privilege tier.** Service accounts that other agents delegate to should not have a privilege superset of any caller. Run them with the *least* common privilege; let callers raise via tokens.

## Anti-patterns

- `await otherAgent.dispatch(call)` with no token argument.
- Tokens that contain only `caller_id` (B then looks up "A's permissions" from its own table — same problem as no token).
- Permission-elevation via "trust the previous agent" rules in the system prompt. Prompts are not authorization.
- Long-lived delegation tokens that span sessions.

## Regression test

`patched_fixture/exploit.test.js` constructs the canonical confused-deputy scenario: low-privilege A asks high-privilege B to delete an account. CI must run this on every change to delegation, dispatch, or session-token handling.

## Patch verification (Phase 2)

`vulnc verify-patch` (Phase 2) will apply candidate patches to the vulnerable fixture and confirm:
1. The exploit test starts exiting 0 (intersection enforced).
2. The Semgrep rule no longer matches the patched code.
