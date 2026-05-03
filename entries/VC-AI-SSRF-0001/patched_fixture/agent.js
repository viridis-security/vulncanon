'use strict';

// PATCHED: every outbound fetch passes through assertSafeUrl, which
// rejects private/loopback/link-local/metadata hosts after parsing.
// (The fixture stops short of full DNS resolution to remain self-contained
// and dependency-free; the mitigation.md specifies the full real-world
// guard, which also resolves and re-validates after redirects.)

const state = { lastFetchedUrl: null, exfiltratedSecret: null };

const FAKE_NETWORK = {
  'http://169.254.169.254/latest/meta-data/iam/security-credentials/admin-role':
    JSON.stringify({ AccessKeyId: 'AKIAEXAMPLEFIXTUREONLY', SecretAccessKey: 'fake' }),
  'https://api.example.com/v1/echo': JSON.stringify({ ok: true }),
};

class SSRFGuardError extends Error {
  constructor(message) { super(message); this.name = 'SSRFGuardError'; }
}

const PRIVATE_IP_PATTERNS = [
  /^127\./,                          // loopback
  /^10\./,                           // RFC1918
  /^192\.168\./,                     // RFC1918
  /^172\.(1[6-9]|2\d|3[01])\./,      // RFC1918
  /^169\.254\./,                     // link-local (incl. AWS metadata)
  /^100\.64\./,                      // CGNAT
  /^0\./,                            // unspecified
  /^::1$/, /^fe80:/i, /^fc/i,        // IPv6 loopback / link-local / ULA
];

const FORBIDDEN_HOSTS = new Set([
  '169.254.169.254',
  'metadata.google.internal',
  'metadata.azure.com',
  '100.100.100.200',
  'localhost',
]);

function isIpLiteral(host) {
  return /^(?:\d{1,3}\.){3}\d{1,3}$/.test(host) || /:/.test(host);
}

function assertSafeUrl(url) {
  let u;
  try { u = new URL(url); }
  catch { throw new SSRFGuardError(`malformed URL: ${url}`); }

  if (!/^https?:$/.test(u.protocol)) {
    throw new SSRFGuardError(`forbidden scheme: ${u.protocol}`);
  }
  const host = u.hostname.toLowerCase();
  if (FORBIDDEN_HOSTS.has(host)) {
    throw new SSRFGuardError(`forbidden host (metadata / loopback): ${host}`);
  }
  if (isIpLiteral(host)) {
    for (const p of PRIVATE_IP_PATTERNS) {
      if (p.test(host)) {
        throw new SSRFGuardError(`forbidden private/loopback IP: ${host}`);
      }
    }
  }
  // (Real implementation would also resolve and re-check post-redirect.)
  return u.toString();
}

async function inProcessFetch(url) {
  state.lastFetchedUrl = url;
  return FAKE_NETWORK[url] !== undefined ? FAKE_NETWORK[url] : '';
}

const TOOLS = {
  fetch_url: {
    run: async ({ url }) => {
      const safe = assertSafeUrl(url);
      const body = await inProcessFetch(safe);
      if (body && /AccessKeyId/.test(body)) state.exfiltratedSecret = body;
      return body;
    },
  },
};

async function agentFetch(url) {
  return TOOLS.fetch_url.run({ url });
}

module.exports = { agentFetch, TOOLS, state, assertSafeUrl, SSRFGuardError };
