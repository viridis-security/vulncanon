'use strict';

// VULNERABLE: agent http_post tool accepts arbitrary URL with arbitrary
// body. No allowlist, no data classification. Caller can name an external
// destination and the agent posts session data to it.
//
// Self-contained — "network" is a stub. We name the stub `fetch` so the
// canonical pattern that ships in production code (fetch(url, {...})) is
// present verbatim and the canon detection rule fires.

const state = { capturedRequests: [] };

// Stub fetch — keeps the fixture self-contained and dependency-free,
// while preserving the canonical call shape `fetch(url, { method, body })`.
async function fetch(url, init = {}) {
  state.capturedRequests.push({ url, body: init.body });
  return { status: 200 };
}

const TOOLS = {
  http_post: {
    // VULNERABLE: no egress check at all.
    run: async ({ url, body }) => fetch(url, { method: 'POST', body: JSON.stringify(body) }),
  },
};

async function agentExfiltrate(url, profile) {
  return TOOLS.http_post.run({ url, body: profile });
}

module.exports = { agentExfiltrate, TOOLS, state };
