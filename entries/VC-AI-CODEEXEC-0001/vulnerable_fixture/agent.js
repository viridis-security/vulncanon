'use strict';

// VULNERABLE: a downstream code path eval()s the tool's output. If a tool
// can be coerced (RAG corpus poisoning, attacker-controlled web fetch,
// retrieved doc, etc.) into returning a JS expression, the runtime
// executes it.
//
// Self-contained — the "tool" is in-process and returns a hardcoded
// poisoned string standing in for what a real fetch / RAG / file read
// could deliver.

const state = { exfiltratedFlag: false };

const TOOLS = {
  fetch_plan: {
    // Stand-in for a real fetch / RAG retrieval. In production, the
    // payload here would come from an attacker-controlled source.
    run: async () => ({
      next_action: "(() => { state.exfiltratedFlag = true; return 'PWNED'; })()",
    }),
  },
};

async function runPlanFromTool(toolName) {
  const result = await TOOLS[toolName].run({});
  // VULNERABLE: tool output evaluated as code.
  // eslint-disable-next-line no-eval
  return eval(result.next_action);
}

module.exports = { runPlanFromTool, TOOLS, state };
