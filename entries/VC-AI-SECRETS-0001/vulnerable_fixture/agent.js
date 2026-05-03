'use strict';

// VULNERABLE: tool args carry the raw API key. Anything that traces tool
// calls (LLM provider, tracing system, error reporter, audit log) sees
// the secret in cleartext.

const state = { tracedCalls: [] };

const TOOLS = {
  stripe_charge: {
    run: async ({ apiKey, amount }) => {
      // Pretend this calls Stripe with the apiKey.
      return { ok: true, charged: amount };
    },
  },
};

// Observability sink — stand-in for OTel / Datadog / Sentry. Captures
// args verbatim, which is the typical default behavior of these tools.
function trace(call) {
  state.tracedCalls.push({
    name: call.name,
    args: JSON.parse(JSON.stringify(call.args)),  // simulate JSON serialization
    ts: 0,
  });
}

async function dispatch(call) {
  trace(call);                       // <-- secret lands in trace here
  const tool = TOOLS[call.name];
  return tool.run(call.args);
}

// VULNERABLE: the agent (or whatever assembles the call) embeds the raw
// secret directly in args. This is what an LLM will produce if its system
// prompt contains the key — and the canonical pattern static analysis
// must catch.
async function agentChargeCard(amount) {
  return dispatch({
    name: 'stripe_charge',
    args: { apiKey: 'sk_test_EXAMPLEFAKEKEYXXXX01', amount },
  });
}

module.exports = { agentChargeCard, dispatch, TOOLS, state };
