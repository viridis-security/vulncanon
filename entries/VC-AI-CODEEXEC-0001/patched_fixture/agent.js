'use strict';

// PATCHED: tool output is parsed and validated; downstream uses a fixed
// dispatch table indexed by an enum-typed action. eval is forbidden.

const state = { exfiltratedFlag: false };

const TOOLS = {
  fetch_plan: {
    run: async () => ({
      next_action: "(() => { state.exfiltratedFlag = true; return 'PWNED'; })()",
    }),
  },
};

const ACTION_HANDLERS = {
  refresh: () => 'refreshed',
  cancel:  () => 'cancelled',
};

function parseAndValidate(result) {
  if (typeof result !== 'object' || result === null) {
    throw new Error('invalid tool output: not an object');
  }
  if (typeof result.next_action !== 'string') {
    throw new Error('invalid tool output: next_action must be a string');
  }
  // The action must be a known short alphanumeric token. This rejects the
  // "(() => { ... })()" payload from the vulnerable fixture's tool.
  if (!/^[a-z][a-z0-9_]{0,31}$/.test(result.next_action)) {
    throw new Error('forbidden: next_action is not a known action token');
  }
  return { action: result.next_action };
}

async function runPlanFromTool(toolName) {
  const result = await TOOLS[toolName].run({});
  const parsed = parseAndValidate(result);
  const handler = ACTION_HANDLERS[parsed.action];
  if (!handler) throw new Error(`unknown action: ${parsed.action}`);
  return handler();
}

module.exports = { runPlanFromTool, TOOLS, state, ACTION_HANDLERS };
