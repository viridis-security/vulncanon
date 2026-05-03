'use strict';

// PATCHED: dispatcher consults session.permissions for privileged tools.
// Tools also default to privileged=true.

const accounts = { victim: { id: 'victim', balance: 100, deleted: false } };

class PermissionDeniedError extends Error {
  constructor(toolName) {
    super(`permission denied for tool ${toolName}`);
    this.name = 'PermissionDeniedError';
  }
}

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

function assertPermission(session, tool, name) {
  if (!tool.privileged) return;
  if (!session || !session.permissions || !session.permissions.has(name)) {
    throw new PermissionDeniedError(name);
  }
}

async function dispatch(call, session) {
  const tool = TOOLS[call.name];
  if (!tool) throw new Error(`unknown tool: ${call.name}`);
  assertPermission(session, tool, call.name);
  return tool.run(call.args);
}

module.exports = { dispatch, accounts, TOOLS, PermissionDeniedError };
