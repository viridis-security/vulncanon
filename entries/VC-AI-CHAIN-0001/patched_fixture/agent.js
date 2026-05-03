'use strict';

// PATCHED: delegations carry a capability token bound to the caller's
// permissions. The callee computes effective = caller ∩ callee for the
// delegated call.

const crypto = require('node:crypto');

const accounts = { victim: { id: 'victim', deleted: false } };
const SIGNING_KEY = 'shared-trusted-authority-key-test-only';

function mintDelegationToken({ caller_id, caller_permissions, tool_name }) {
  const payload = {
    caller_id,
    caller_permissions: [...caller_permissions],
    tool_name,
    exp: Date.now() + 60_000,
  };
  const json = JSON.stringify(payload);
  const sig = crypto.createHmac('sha256', SIGNING_KEY).update(json).digest('hex');
  return Buffer.from(json).toString('base64') + '.' + sig;
}

function verifyDelegationToken(token, expectedTool) {
  const [b64, sig] = String(token).split('.');
  if (!b64 || !sig) return null;
  const expected = crypto.createHmac('sha256', SIGNING_KEY).update(Buffer.from(b64, 'base64')).digest('hex');
  if (expected !== sig) return null;
  const payload = JSON.parse(Buffer.from(b64, 'base64').toString('utf8'));
  if (payload.tool_name !== expectedTool) return null;
  if (Date.now() > payload.exp) return null;
  return payload;
}

function makeAgent({ id, permissions }) {
  const TOOLS = {
    delete_account: {
      privileged: true,
      requires: 'delete_account',
      run: async ({ id }) => { if (accounts[id]) accounts[id].deleted = true; },
    },
  };

  // PATCHED: delegations require a token; effective = caller ∩ callee.
  async function dispatch(call, opts = {}) {
    const tool = TOOLS[call.name];
    if (!tool) throw new Error(`unknown tool: ${call.name}`);

    let effective;
    if (opts.delegationToken) {
      const payload = verifyDelegationToken(opts.delegationToken, call.name);
      if (!payload) throw new Error('invalid or expired delegation token');
      const callerPerms = new Set(payload.caller_permissions);
      effective = new Set([...callerPerms].filter((p) => permissions.has(p)));
    } else {
      // No token → not a delegation; use callee's own permissions.
      effective = permissions;
    }
    if (!effective.has(tool.requires)) throw new Error('permission denied');
    return tool.run(call.args);
  }

  return { id, permissions, dispatch };
}

const A = makeAgent({ id: 'A', permissions: new Set([]) });
const B = makeAgent({ id: 'B', permissions: new Set(['delete_account']) });

// PATCHED: delegate mints a token bound to A's permissions; B intersects.
async function delegate(toAgent, call, fromSession) {
  const token = mintDelegationToken({
    caller_id: fromSession.id,
    caller_permissions: fromSession.permissions,
    tool_name: call.name,
  });
  return toAgent.dispatch(call, { delegationToken: token });
}

module.exports = { A, B, delegate, accounts, mintDelegationToken, verifyDelegationToken };
