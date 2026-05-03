# Mitigation — VC-AI-CODEEXEC-0001

## Required controls

1. **Forbid dynamic evaluation in the agent runtime.** Lint rules ban `eval`, `Function`, `setTimeout`/`setInterval` with string arg, `vm.runIn*`, `child_process.exec`, `child_process.execSync`, `os.system`, `subprocess.shell=True`. CI gates the lint.
2. **Dispatch tables, not strings.** Downstream actions are looked up in a fixed `Record<ActionName, Handler>` (or equivalent). Action names are an enum/literal type. Unknown actions throw.
3. **Validate tool outputs against a schema.** Every tool declares an output schema (Zod / JSON Schema / pydantic). Outputs are parsed and validated before any downstream use. Validation failure aborts the turn.
4. **No string-template SQL/shell from tool output.** Parameterized queries only. `child_process.execFile` with array argv only. Never `exec(template_string)`.
5. **Sandboxed evaluation if absolutely required.** If the agent legitimately needs to run code (e.g., a "code interpreter" tool), it runs in a separate process with no network egress, no host filesystem access, and a 30-second wallclock limit. Output crosses back as data, not as code.

## Anti-patterns

- `eval(toolResult.next_action)` — the canonical bug.
- `new Function(retrievedDoc)` — same bug, different keyword.
- `child_process.exec(\`gh issue create -b "${toolOutput}"\`)` — shell injection via tool output.
- "Validation" by whitelist regex on the eval input. Attackers reshape payloads.
- Allowing the LLM to emit raw JS/Python that the runtime then runs as the next "step." This is the architecture of every successful agent jailbreak in 2024–2025.

## Regression test

`patched_fixture/exploit.test.js` passes a poisoned tool result that, if eval'd, would mutate observable state. CI must run on every change to dispatch logic, tool result handling, or any code path that ingests tool output.
