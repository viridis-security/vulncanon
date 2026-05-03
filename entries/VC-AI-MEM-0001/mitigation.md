# Mitigation — VC-AI-MEM-0001

## Required controls

1. **Owner-bound memory writes.** Every memory record carries `owner_principal_id`, set at write time from the authenticated session. Never accept `owner` from caller input.
2. **Owner-equality predicate on reads.** The memory store API enforces an owner predicate. The application layer cannot bypass it. Prefer enforcing this at the database layer (row-level security) so even raw SQL queries cannot leak across tenants.
3. **Embedding-space isolation (defense in depth).** Either index per-tenant (separate index per `owner_principal_id`) or include the owner id as a structured filter in vector search.
4. **Audit cross-tenant reads.** Any read that returns records whose owner ≠ caller is an exception event, not a normal log line. Alert on it.
5. **Treat the LLM as untrusted.** Never let the model construct the database query. The memory API takes a query string and applies its own owner predicate; the model cannot pass `owner: 'alice'` as an arg.

## Anti-patterns

- `memoryStore.search(query)` with no second argument.
- `memoryStore.search(query, { owner: callerSuppliedOwner })`.
- Filtering owner *after* retrieval in app code (information leak via timing or vector distance).
- Single shared embedding index with owner as metadata that is not used as a hard filter.

## Regression test

`patched_fixture/exploit.test.js` uses two tenants with overlapping topics. CI must run it on every change to memory write or read paths.
