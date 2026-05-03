'use strict';

// VULNERABLE: dispatcher does NOT consult session.permissions before running
// privileged tools. This is the VC-AI-TOOL-0001 pattern.

const accounts = { victim: { id: 'victim', balance: 100, deleted: false } };

const TOOLS = {
  whoami: {
    privileged: false,
    run: async () => 'agent',
  },
  delete_account: {
    privileged: true,
    run: async ({ id }) => {
      if (accounts[id]) accounts[id].deleted = true;
      return { ok: true, id };
    },
  },
};

async function dispatch(call, session) {
  const tool = TOOLS[call.name];
  if (!tool) throw new Error(`unknown tool: ${call.name}`);
  // Permission check missing — vulnerability instance.
  return tool.run(call.args);
}

module.exports = { dispatch, accounts, TOOLS };
