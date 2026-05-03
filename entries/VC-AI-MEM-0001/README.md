# VC-AI-MEM-0001 — Cross-Tenant Memory Disclosure in Agent Long-Term Store

**Class**: AI Agent Memory Disclosure · **Severity**: High

## The invariant

> An agent must not return memory content to any actor whose principal id does not equal the owner principal id of that record.

## The pattern

Agent platforms ship a memory store. The lookup path looks like:

```js
// VULNERABLE
async function recall(query) {
  return memoryStore.search(query);   // returns globally-similar records
}
```

There is no owner filter. A user from tenant A asks "what did I tell you about my API key?" and the vector search happily returns tenant B's API key because the embeddings are similar. This is identical in kind to the IDOR class in classical web auth — the server uses a query parameter as the access key.

## The fix

Owner equality is a *predicate*, not a filter applied client-side:

```js
// PATCHED
async function recall(query, principal) {
  return memoryStore.search(query, { ownerEquals: principal.id });
}
```

The owner field on each record is bound at write time from the *authenticated session*, not from any caller-supplied parameter.

## The test

Two principals (`alice`, `bob`) write memories with overlapping topics. The test asks for `bob`'s recall, but with `alice`'s API key embedded in `bob`'s topic vector neighborhood.

- `vulnerable_fixture` — the recall returns `alice`'s record. Assertion fails. Exit non-zero.
- `patched_fixture` — owner predicate filters it out. Exit 0.
