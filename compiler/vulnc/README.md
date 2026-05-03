# `vulnc` — VulnCanon Security Compiler

`vulnc` is the gate. Nothing enters VulnCanon without compiling through it.

## Axiom

> No proof, no payout. No compile, no canon. No mitigation, no merge.

For v1, the *proof* is fixture-based, not Lean. Each entry must ship:

1. A **vulnerable_fixture** whose `exploit.test.js` exits **non-zero** — proving the invariant violation reproduces deterministically.
2. A **patched_fixture** whose `exploit.test.js` exits **zero** — proving the fix actually fixes it.
3. A **Semgrep rule** that pattern-matches the vulnerable code shape.
4. A **mitigation.md** with concrete remediation guidance.

If any of those fail, the entry is rejected. There is no override path.

## Install

Zero external dependencies. Requires Node ≥ 18.

```bash
# from canon/vulncanon/compiler/vulnc
chmod +x bin/vulnc.js
./bin/vulnc.js --help
```

You can also `npm link` from this directory to expose `vulnc` globally.

## Usage

```bash
vulnc check ../../entries/VC-AI-TOOL-0001
vulnc check-all                            # validates the whole canon
```

## Exit codes

- `0` — every checked entry was ACCEPTED
- `1` — at least one entry was REJECTED
- `2` — invocation error

## Compile reports

Every run writes a JSON receipt to `canon/vulncanon/reports/<ENTRY-ID>.compile-report.json`. The receipt is what proves an entry passed every gate; in production it gets pinned (Phase 2) so the canon is auditable.

## What it checks (v1)

| Check | Required | What it does |
|---|---|---|
| `schema` | yes | `entry.json` validates against `schemas/vulnerability.schema.json` |
| `structure` | yes | All required artifacts exist on disk |
| `vulnerable_fixture_fails` | yes | `node vulnerable_fixture/exploit.test.js` exits non-zero |
| `patched_fixture_passes` | yes | `node patched_fixture/exploit.test.js` exits zero |
| `static_rule_valid` | yes | `rule.semgrep.yml` is structurally valid (semgrep `--validate` if installed) |
| `mitigation_present` | yes | `mitigation.md` exists and is substantive |
| `duplicate_check` | yes | No id collision elsewhere in the canon |
| `safety_scan` | yes | No live-target exploitation patterns in fixtures |
| `lean_compiles` | optional | Phase 2 — Aristotle/lake integration |

## Phase 2 hooks

- Lean theorem verification via Aristotle API
- Cross-entry novelty hashing (against existing canon)
- Patch verification (apply mitigation diff to vulnerable fixture, re-run)
- Semantic duplicate detection on claim+invariant
