'use strict';

// VULNERABLE: agent B authorizes delegated calls against its own permission
// set, not the intersection with agent A's. Classic confused deputy.

const accounts = { victim: { id: 'victim', deleted: false } };

function makeAgent({ id, permissions }) {
  const TOOLS = {
    delete_account: {
      privileged: true,
      requires: 'delete_account',
      run: async ({ id }) => { if (accounts[id]) accounts[id].deleted = true; },
    },
  };

  // VULNERABLE: dispatch checks the agent's *own* permissions, regardless of
  // who is delegating the call.
  async function dispatch(call) {
    const tool = TOOLS[call.name];
    if (!tool) throw new Error(`unknown tool: ${call.name}`);
    if (!permissions.has(tool.requires)) throw new Error('permission denied');
    return tool.run(call.args);
  }

  return { id, permissions, dispatch };
}

// A: low-privilege user-facing agent. Cannot delete accounts directly.
const A = makeAgent({ id: 'A', permissions: new Set([]) });
// B: high-privilege service account. Has delete_account.
const B = makeAgent({ id: 'B', permissions: new Set(['delete_account']) });

// VULNERABLE: A delegates to B with no capability token. B authorizes
// using its own permissions and runs the privileged call.
async function delegate(toAgent, call, fromSession) {
  return toAgent.dispatch(call);
}

module.exports = { A, B, delegate, accounts };
