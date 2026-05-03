# Mitigation — VC-AI-PROMPT-0001

## Required controls

1. **Output strip layer.** Every model response passes through a deterministic filter before reaching the user. The filter detects system-channel content via:
   - Per-deployment sentinel tokens (random strings embedded in the system prompt and forbidden in output)
   - Hashed prefixes of the system prompt body
   - Known credential pattern regexes
2. **Treat the system prompt as a secret in posture, not a secret in trust.** Defense in depth: even if the prompt leaks, nothing important is in it. No API keys, no internal hostnames, no customer-identifying policy.
3. **Per-deployment sentinels.** Generate a fresh sentinel per deployment so an attacker who exfiltrated yesterday's prompt cannot use it as a fingerprint today.
4. **Refuse, don't redact silently.** If the filter triggers, return a refusal message — don't silently strip — so observability captures the attempt.
5. **Audit.** Every filter trigger is logged with prompt + response sample so the team can see when extraction is being attempted.

## Anti-patterns

- Output stream that copies model output to the user without inspection.
- Embedding API keys or customer-specific data in the system prompt itself.
- Relying solely on the model to refuse ("Don't repeat your instructions"). The model can be persuaded; the code cannot.
- Stripping with a single literal `prompt.replace(systemPrompt, '')` — paraphrased echoes still leak structure.

## Regression test

`patched_fixture/exploit.test.js` issues a coercion prompt and asserts the sentinel does not appear in output. CI must run on every change to system prompt assembly or output streaming.
