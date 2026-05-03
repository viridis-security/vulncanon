# VulnCanon Entry Schema

The canonical contract for an entry. Authoritative version is `schemas/vulnerability.schema.json` (JSON Schema draft-07). This document is the human-readable companion.

## Required fields

| Field | Type | Notes |
|---|---|---|
| `id` | string | Format `VC-<CATEGORY>-<NNNN>` or `VC-<CATEGORY>-<TOPIC>-<NNNN>`. Example: `VC-AI-TOOL-0001`. |
| `title` | string | 8–140 chars. |
| `class` | enum | One of the canonical taxonomy values (see schema). |
| `status` | enum | `draft` \| `review` \| `accepted` \| `deprecated` \| `withdrawn`. |
| `severity` | enum | `informational` \| `low` \| `medium` \| `high` \| `critical`. |
| `invariant.id` | string | snake_case identifier, stable across versions. |
| `invariant.statement` | string | Plain-English statement of the security property that must hold. |
| `preconditions` | object | Boolean flags describing the conditions under which the vulnerability applies. |
| `claim.statement` | string | What is asserted to follow from `preconditions ∧ ¬invariant`. |
| `evidence.mode` | enum | `fixture_plus_static` \| `fixture_plus_static_plus_test` \| `lean_plus_static_plus_test` \| `lean_plus_fixture_plus_static_plus_test`. v1 entries use `fixture_plus_static_plus_test`. |
| `evidence.vulnerable_fixture` | string | Must equal `vulnerable_fixture` (path relative to entry root). |
| `evidence.patched_fixture` | string | Must equal `patched_fixture`. |
| `evidence.static_rule` | string | Must equal `rule.semgrep.yml`. |
| `mitigation.file` | string | Must equal `mitigation.md`. |
| `mitigation.summary` | string | One-paragraph summary; mitigation.md holds the detail. |
| `contributor.submitter_id` | string | Who submitted (agent or human id). |
| `contributor.validator_id` | string | Who validated. |
| `contributor.canonical_founder` | const | Must equal `Viridis Security`. |
| `created_at` | date | ISO date. |

## On-disk structure of an entry

```
entries/VC-XXX-NNNN/
├── entry.json                    # validated by schemas/vulnerability.schema.json
├── README.md                     # invariant + pattern + fix + test summary
├── mitigation.md                 # required controls + anti-patterns + regression test guidance
├── rule.semgrep.yml              # static detection rule
├── vulnerable_fixture/
│   ├── agent.js                  # minimal fixture exhibiting the pattern
│   └── exploit.test.js           # MUST exit non-zero (asserts invariant violation)
└── patched_fixture/
    ├── agent.js                  # minimal fixture with the fix applied
    └── exploit.test.js           # MUST exit zero (asserts invariant holds)
```

## The fixture invariant

This is the load-bearing part of v1.

- The same `exploit.test.js` (or a near-identical pair) runs in both fixtures.
- In `vulnerable_fixture/`, the test asserts the security invariant. The vulnerable code violates the invariant, so the assertion fails, and Node exits non-zero. **vulnc requires this exit code.**
- In `patched_fixture/`, the same test runs against the patched code. The fix holds, the assertion passes, Node exits zero. **vulnc requires this exit code.**

If your entry doesn't satisfy these two constraints, it is a hypothesis, not a finding. vulnc will reject it.

## Versioning

Entries are immutable once accepted. Changes are versioned via `version` (semver) and `updated_at`. Breaking changes get a new `id`. The old entry's `status` becomes `deprecated` with a `superseded_by` reference (to be added in schema v0.2).

## Authoring a new entry

See `CONTRIBUTING.md`.
