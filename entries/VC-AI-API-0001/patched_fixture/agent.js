'use strict';

// PATCHED: every outbound POST passes through a safePost wrapper that
// (1) validates the destination against an allowlist, (2) classifies the
// body and refuses private bodies to non-private destinations.

const state = { capturedRequests: [] };

const OUTBOUND_ALLOWLIST = new Set([
  'api.stripe.com',
  'api.example.com',
]);
const PRIVATE_DATA_DESTINATIONS = new Set([
  // Hosts that are explicitly approved to receive private data.
  'internal-api.example.com',
]);

class EgressGuardError extends Error {
  constructor(message) { super(message); this.name = 'EgressGuardError'; }
}

const PRIVATE_PATTERNS = [
  /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/,           // email
  /\bAKIA[0-9A-Z]{16}\b/,                                       // AWS access key
  /\bsk-[A-Za-z0-9]{20,}\b/,                                    // OpenAI key
  /\b\d{3}-\d{2}-\d{4}\b/,                                      // US SSN
];

function classifyBody(body) {
  // 1. tag-based: any field carrying _class: 'private'
  function walk(v) {
    if (v && typeof v === 'object') {
      if (v._class === 'private') return true;
      for (const k of Object.keys(v)) if (walk(v[k])) return true;
    }
    return false;
  }
  if (walk(body)) return 'private';
  // 2. signature-based: body string contains known sensitive patterns
  const text = JSON.stringify(body);
  for (const pat of PRIVATE_PATTERNS) if (pat.test(text)) return 'private';
  return 'public';
}

async function inProcessPost(url, body) {
  state.capturedRequests.push({ url, body });
  return { status: 200 };
}

async function safePost(url, body) {
  let host;
  try { host = new URL(url).hostname.toLowerCase(); }
  catch { throw new EgressGuardError(`malformed URL: ${url}`); }

  const dataClass = classifyBody(body);
  if (dataClass === 'private' && !PRIVATE_DATA_DESTINATIONS.has(host)) {
    throw new EgressGuardError(`refusing to send private data to ${host}`);
  }
  if (!OUTBOUND_ALLOWLIST.has(host) && !PRIVATE_DATA_DESTINATIONS.has(host)) {
    throw new EgressGuardError(`destination ${host} is not on the egress allowlist`);
  }
  return inProcessPost(url, body);
}

const TOOLS = {
  http_post: {
    run: async ({ url, body }) => safePost(url, body),
  },
};

async function agentExfiltrate(url, profile) {
  return TOOLS.http_post.run({ url, body: profile });
}

module.exports = { agentExfiltrate, TOOLS, state, safePost, classifyBody, EgressGuardError };
