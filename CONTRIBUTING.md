# Contributing to VulnCanon

VulnCanon is currently maintained by **Viridis Security** as the canonical founder. Public contributions open after the v1 canon stabilizes (~30 entries) and the schema reaches v1.0.

In the interim, internal authoring (Justin + the Viridis Security AI Agent) follows the protocol below.

## Authoring an entry

### 1. Pick the next id

Format: `VC-<CATEGORY>-<NNNN>`. For AI-agent entries the prefix is `VC-AI-<TOPIC>-<NNNN>`. Existing AI categories: `TOOL`, `RAG`, `MEM`, `ACTION`, `PROMPT`. New topics get the next available `NNNN` slot in the topic.

### 2. Restate the invariant first

Before writing any code, write `invariant.statement` as plain English. This is your **spec invariance** check. If you cannot state the invariant in one sentence, you don't have a finding yet — you have a hypothesis.

### 3. Build the vulnerable fixture

The fixture must:

- Be self-contained Node, no `npm install`.
- Be the **minimum** code that exhibits the pattern. Strip everything that isn't load-bearing.
- Avoid live targets. No real URLs. No real keys. The fixture demonstrates the pattern; it does not exploit anything in the world.

### 4. Write the regression test

`vulnerable_fixture/exploit.test.js` calls the vulnerable code path and asserts the invariant. The assertion must fail — Node exits non-zero. This is the proof-of-non-hypothesis.

### 5. Build the patched fixture

`patched_fixture/agent.js` applies the minimal fix. Copy the same `exploit.test.js`. The assertion must now pass — Node exits zero.

### 6. Write the Semgrep rule

`rule.semgrep.yml` pattern-matches the vulnerable shape. It should match `vulnerable_fixture/agent.js` and **not** match `patched_fixture/agent.js`. (Phase 2: vulnc will enforce this differential.)

### 7. Write the mitigation

`mitigation.md` lists required controls, anti-patterns, and a regression test pointer. This is the part enterprise customers actually pay for.

### 8. Set the confidence tier

`detection.confidence` tells customers how much triage attention to give a match. Choose carefully — this is the field that makes the canon's output actionable rather than noisy.

- **`high`** — the regex matches a *literal vulnerability shape*. Examples: a quoted secret with a known prefix (`apiKey: "sk_live_..."`), `eval(<tool result>)`, retrieved-doc interpolation into a `systemPrompt` string. Triggers should be rare; when they fire, they're almost always exploitable.
- **`medium`** — pattern-true, but exploitability depends on context. Examples: an irreversible-action tool definition (could be safe if guarded elsewhere), an outbound POST to a caller-supplied URL (could be safe if URL is internal). Worth review.
- **`low`** — framework-level signal that fires often. Examples: a tool dispatcher that *could* be wrapped without a permission gate downstream, a generic `fetch(url)` that *could* be SSRF if the URL is attacker-controlled. Customer must do the contextual check.

Wrong tiering is worse than no tiering. Don't mark something HIGH because the underlying vulnerability is severe — mark it HIGH because the *signature is highly specific*. The bug class severity is `severity`; the confidence is about the regex's true positive rate.

### 9. Compile

```bash
node compiler/vulnc/bin/vulnc.js check entries/VC-AI-XXX-NNNN
```

If it doesn't return ACCEPTED, the entry is not done. Fix and re-run.

### 10. Update top-level README

Add the new entry to the table in `canon/vulncanon/README.md`.

## Authoring lessons (from the 2026-04-27 stress test)

These are the lessons captured from running the canon against 619 files of public AI-agent code (langchain-ai/langgraphjs, vercel/ai-chatbot, openai/swarm). Apply them to every new entry.

1. **Never anchor on a bare keyword.** `eval` will appear in comments ("eval is forbidden"), in identifier names (`evaluate`), and in regex methods (`pattern.exec()`). Always require a function-call shape (`\beval\s*\(`) and exclude the false-positive call sites (`pattern.exec`, `RegExp.prototype.exec`).
2. **Identifier references are not values.** `apiKey: options.apiKey` is wiring code, not a leaked secret. When detecting secret leakage, require a quoted-string literal with a known prefix (`sk-`, `sk_live_`, `AKIA`, `ghp_`, `xox[abprs]-`) — never a 12-char identifier match.
3. **Cross-rule overlap is a smell.** If two rules match the same line every time, they're not actually distinct rules. Differentiate by the *shape*: API-0001 requires a body argument (POST shape); SSRF-0001 stays generic. Test by scanning a few files of real agent code and checking the same-line overlap count.
4. **SDK client code is a recurring contextual FP.** Framework code that takes URL as a parameter is "honest signal" even when the surrounding system is safe — it's the *consumer* of the SDK who needs the guard. Don't try to suppress these in the regex; mark the entry as `confidence: low` so customers know to do the contextual check.
5. **Comment-vs-code distinction matters.** Both vulnerable and patched fixtures often mention the bug class in prose. Exclude regexes must target code identifiers (`mintDelegationToken`, `delegationToken[:=]`, `safePost\(`), not concept names (`capability_token`, `safe_post`). Test by scanning the patched fixture only — if the rule fires, the exclude is too loose.

## Anti-patterns in submissions

The following are **rejected by design**. vulnc enforces some; reviewer judgment enforces the rest.

- **Hypothesis dressed as a finding.** "This pattern *could* be exploitable" without a fixture that demonstrates the violation. (vulnc rejects via fixture exit codes.)
- **Live-target instructions.** Anything that exfiltrates real data, hits real URLs, or runs real shells. (vulnc rejects via the safety scan.)
- **Tautological invariant.** The "claim" cannot be the conjunction of preconditions; it must be a non-trivial consequence. Reviewer-enforced.
- **Mitigation that's just "validate input".** Mitigations must be specific and verifiable. Reviewer-enforced.
- **Duplicate id.** vulnc rejects.

## Style

- Fixtures use plain Node.js (`require`, `node:assert/strict`). No frameworks.
- 4-space indent for YAML, 2-space for JSON and JS.
- Line length ~100.
- No emojis in entry content.
- Mitigations and READMEs in English; future translations are derivative.

## Phase 2 contributor flows (planned, not yet open)

- External agent submissions via the Canon protocol's settlement layer (see `canon/SPEC_V0.md`).
- Lean theorem co-authoring for the highest-value entries (auth, payment).
- Patch verification rewards (apply candidate fix; if it makes the vulnerable fixture exit 0 *and* the rule stops matching, reward).
