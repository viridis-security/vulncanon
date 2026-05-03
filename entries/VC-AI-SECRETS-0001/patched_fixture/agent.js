'use strict';

// PATCHED: tool args carry an opaque capability handle. The secret lives
// in a server-side vault and is dereferenced just-in-time, after tracing.

const crypto = require('node:crypto');

const state = { tracedCalls: [] };

// Server-side capability vault.
class CapabilityVault {
  constructor() { this.entries = new Map(); }
  mint(value, { tool, ttlMs = 3600_000 } = {}) {
    const handle = 'cap:' + crypto.randomBytes(8).toString('hex');
    this.entries.set(handle, { value, tool, expiresAt: Date.now() + ttlMs });
    return handle;
  }
  resolve(handle, expectedTool) {
    const e = this.entries.get(handle);
    if (!e) throw new Error('unknown capability handle');
    if (Date.now() > e.expiresAt) throw new Error('capability expired');
    if (e.tool && e.tool !== expectedTool) throw new Error('capability scoped to a different tool');
    return e.value;
  }
}

const VAULT = new CapabilityVault();
const STRIPE_HANDLE = VAULT.mint(
  'sk_test_EXAMPLEFAKEKEYXXXX01',
  { tool: 'stripe_charge' }
);

const TOOLS = {
  stripe_charge: {
    run: async ({ apiKey, amount }) => ({ ok: true, charged: amount }),
  },
};

function trace(call) {
  // Args at trace time still contain the handle — never the resolved
  // secret, because resolution happens *after* this point.
  state.tracedCalls.push({
    name: call.name,
    args: JSON.parse(JSON.stringify(call.args)),
    ts: 0,
  });
}

function resolveCapabilityHandles(args, toolName) {
  const out = { ...args };
  for (const [k, v] of Object.entries(args)) {
    if (k.endsWith('Ref') && typeof v === 'string' && v.startsWith('cap:')) {
      const realKey = k.slice(0, -'Ref'.length);  // apiKeyRef → apiKey
      out[realKey] = VAULT.resolve(v, toolName);
      delete out[k];
    }
  }
  return out;
}

async function dispatch(call) {
  trace(call);                                          // handle traced, not secret
  const tool = TOOLS[call.name];
  const resolved = resolveCapabilityHandles(call.args, call.name); // JIT deref
  return tool.run(resolved);
}

// PATCHED: agent passes a handle, not the secret. The LLM context sees
// only `cap:...`; the LLM does not — and cannot — serialize the actual key.
async function agentChargeCard(amount) {
  return dispatch({
    name: 'stripe_charge',
    args: { apiKeyRef: STRIPE_HANDLE, amount },
  });
}

module.exports = { agentChargeCard, dispatch, TOOLS, state, VAULT, STRIPE_HANDLE };
