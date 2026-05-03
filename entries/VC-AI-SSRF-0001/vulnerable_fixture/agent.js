'use strict';

// VULNERABLE: agent fetch_url tool has no host validation. Caller can
// coerce the agent into hitting cloud metadata endpoints and exfiltrating
// IAM credentials.
//
// We simulate the metadata service in-process. NOTHING IN THIS FIXTURE
// MAKES A REAL HTTP REQUEST — the safety scan and the canon's invariants
// require self-contained, no-live-target fixtures.

const state = { lastFetchedUrl: null, exfiltratedSecret: null };

// In-process fake of cloud metadata responses, keyed by URL.
const FAKE_NETWORK = {
  'http://169.254.169.254/latest/meta-data/iam/security-credentials/admin-role':
    JSON.stringify({
      AccessKeyId: 'AKIAEXAMPLEFIXTUREONLY',
      SecretAccessKey: 'fake/secret/should/never/leak',
      Token: 'IQoJbFAKEsessionTokenZZZ',
    }),
  'https://api.example.com/v1/echo':
    JSON.stringify({ ok: true }),
};

// Stub fetch — preserves the canonical call shape `fetch(url)` so the
// canon's static signature actually fires on this fixture.
async function fetch(url) {
  state.lastFetchedUrl = url;
  if (FAKE_NETWORK[url] !== undefined) return { text: async () => FAKE_NETWORK[url] };
  return { text: async () => '' };
}

const TOOLS = {
  fetch_url: {
    // VULNERABLE: no host validation, no scheme check, no DNS resolve, no
    // redirect re-check. Whatever URL the caller (or the LLM) supplies, we
    // fetch.
    run: async ({ url }) => {
      const res = await fetch(url);
      const body = await res.text();
      if (body && /AccessKeyId/.test(body)) {
        state.exfiltratedSecret = body;
      }
      return body;
    },
  },
};

async function agentFetch(url) {
  return TOOLS.fetch_url.run({ url });
}

module.exports = { agentFetch, TOOLS, state };
