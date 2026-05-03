'use strict';

// VULNERABLE: memory store search has no owner predicate. Anyone who can
// invoke recall() can retrieve any tenant's records.

class MemoryStore {
  constructor() { this.records = []; }
  write({ ownerPrincipalId, topic, content }) {
    this.records.push({ ownerPrincipalId, topic, content });
  }
  // VULNERABLE: searches by topic substring only, no owner filter.
  search(query) {
    return this.records.filter((r) => r.topic.includes(query));
  }
}

const store = new MemoryStore();

// Tenants seed memories.
store.write({ ownerPrincipalId: 'alice', topic: 'api-key',  content: 'alice_secret_AKIA1234' });
store.write({ ownerPrincipalId: 'bob',   topic: 'api-key',  content: 'bob_secret_AKIA5678'   });
store.write({ ownerPrincipalId: 'alice', topic: 'todo',     content: 'pay rent' });

async function recall({ principal, query }) {
  // VULNERABLE: principal is ignored on the read path.
  return store.search(query);
}

module.exports = { recall, store };
