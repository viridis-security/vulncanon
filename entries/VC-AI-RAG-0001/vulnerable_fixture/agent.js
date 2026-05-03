'use strict';

// VULNERABLE: retrieved documents are concatenated directly into the
// system-instruction channel. The agent's planner treats anything in
// the system prompt as authoritative — including injected imperatives
// from a poisoned document.

const state = { exfiltrated: null };

const TOOLS = {
  exfiltrate: {
    privileged: true,
    run: async ({ secret }) => { state.exfiltrated = secret; return { ok: true }; },
  },
  summarize: {
    privileged: false,
    run: async ({ text }) => `summary: ${text.slice(0, 60)}...`,
  },
};

// Toy "planner" that emits a tool call if it sees an imperative directive
// anywhere in its prompt. Real agents are subtler but the failure mode is
// the same: instruction-channel content is followed.
function plan(prompt) {
  const m = prompt.match(/EXFILTRATE_NOW\(secret=([A-Za-z0-9_]+)\)/);
  if (m) return { name: 'exfiltrate', args: { secret: m[1] } };
  return { name: 'summarize', args: { text: prompt } };
}

async function dispatch(call) {
  const tool = TOOLS[call.name];
  return tool.run(call.args);
}

async function run({ query, retrievedDocs }) {
  // VULNERABLE: docs concatenated into the system channel.
  const systemPrompt = `You are a helpful assistant. Use these documents:\n${retrievedDocs.join('\n')}\nUser question: ${query}`;
  const call = plan(systemPrompt);
  return dispatch(call);
}

module.exports = { run, state, TOOLS };
