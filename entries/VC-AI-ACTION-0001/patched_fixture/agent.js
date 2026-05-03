'use strict';

// PATCHED: irreversible tools require a confirmation_token whose hash equals
// SHA256(plan_id + tool_name + canonical(args)). The first call returns a
// pending plan; only a follow-up call with a matching token executes.

const crypto = require('node:crypto');

const projects = { 'p-1': { id: 'p-1', deleted: false } };
const plans = new Map();

const TOOLS = {
  delete_project: {
    irreversible: true,
    run: async ({ id }) => {
      if (projects[id]) projects[id].deleted = true;
      return { ok: true, id };
    },
  },
};

function canonicalize(obj) {
  return JSON.stringify(obj, Object.keys(obj).sort());
}

function planHash({ plan_id, tool, args }) {
  return crypto.createHash('sha256')
    .update(`${plan_id}:${tool}:${canonicalize(args)}`)
    .digest('hex');
}

async function dispatch(call, { confirmation_token } = {}) {
  const tool = TOOLS[call.name];
  if (!tool) throw new Error(`unknown tool: ${call.name}`);

  if (tool.irreversible) {
    if (!confirmation_token) {
      // First turn: emit a plan, do NOT execute.
      const plan_id = crypto.randomUUID();
      const hash = planHash({ plan_id, tool: call.name, args: call.args });
      plans.set(hash, { plan_id, tool: call.name, args: call.args, expiresAt: Date.now() + 5 * 60_000 });
      return { status: 'pending_confirmation', plan_id, hash };
    }
    // Second turn: verify the token matches a known unexpired plan whose
    // tool+args match what we are about to run.
    const plan = plans.get(confirmation_token);
    if (!plan) throw new Error('confirmation_token does not match a pending plan');
    if (Date.now() > plan.expiresAt) throw new Error('plan expired');
    if (plan.tool !== call.name) throw new Error('confirmation_token bound to a different tool');
    if (canonicalize(plan.args) !== canonicalize(call.args)) throw new Error('confirmation_token bound to different args');
    plans.delete(confirmation_token);
    return tool.run(call.args);
  }

  return tool.run(call.args);
}

module.exports = { dispatch, projects, plans };
