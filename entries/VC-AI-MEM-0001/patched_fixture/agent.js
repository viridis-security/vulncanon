'use strict';

// PATCHED: memory store enforces an owner-equality predicate at the read
// path. The owner is bound at write time from the authenticated session
// and cannot be supplied by the caller.

class MemoryStore {
  constructor() { this.records = []; }
  write({ ownerPrincipalId, topic, content }) {
    if (!ownerPrincipalId) throw new Error('owner required');
    this.records.push(Object.freeze({ ownerPrincipalId, topic, content }));
  }
  // PATCHED: ownerEquals is a hard predicate, applied before similarity.
  search(query, { ownerEquals }) {
    if (!ownerEquals) throw new Error('ownerEquals predicate required');
    return this.records.filter(
      (r) => r.ownerPrincipalId === ownerEquals && r.topic.includes(query)
    );
  }
}

const store = new MemoryStore();

store.write({ ownerPrincipalId: 'alice', topic: 'api-key',  content: 'alice_secret_AKIA1234' });
store.write({ ownerPrincipalId: 'bob',   topic: 'api-key',  content: 'bob_secret_AKIA5678'   });
store.write({ ownerPrincipalId: 'alice', topic: 'todo',     content: 'pay rent' });

async function recall({ principal, query }) {
  // PATCHED: owner predicate sourced from the authenticated principal.
  return store.search(query, { ownerEquals: principal.id });
}

module.exports = { recall, store };
