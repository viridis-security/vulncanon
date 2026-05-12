# VulnCanon

The proof-compiled vulnerability theorem library. Maintained by **Viridis Security** as the canonical founder and steward.

## The axiom

> **No proof, no payout. No compile, no canon. No mitigation, no merge.**

A code pattern is a *hypothesis*. Only a compiled artifact — vulnerable fixture, patched fixture, static rule, mitigation, regression test — is a *finding*. VulnCanon stores findings.

## What's in v1

VulnCanon v1 ships an opinionated, focused canon: **AI-Agent Security**. Ten entries cover the dominant failure modes of LLM-based agent systems:

| ID | Title | Class | Severity |
|---|---|---|---|
| VC-AI-TOOL-0001 | Privileged Tool Call Without Permission Gate | AI Agent Authorization Failure | High |
| VC-AI-RAG-0001 | Untrusted Retrieved Content Crosses Trust Boundary | AI Agent Trust Boundary Crossing | High |
| VC-AI-MEM-0001 | Cross-Tenant Memory Disclosure in Agent Long-Term Store | AI Agent Memory Disclosure | High |
| VC-AI-ACTION-0001 | Irreversible Action Executed Without Confirmation | AI Agent Irreversible Action | High |
| VC-AI-PROMPT-0001 | System Instruction Disclosure via Output Reflection | AI Agent System Prompt Disclosure | Medium |
| VC-AI-CHAIN-0001 | Multi-Agent Delegation Expands Permission Scope | AI Agent Authorization Failure | High |
| VC-AI-SSRF-0001 | Agent-Coerced SSRF to Internal and Metadata Endpoints | AI Agent Trust Boundary Crossing | Critical |
| VC-AI-CODEEXEC-0001 | Untrusted Tool Output Evaluated as Code Downstream | AI Agent Trust Boundary Crossing | Critical |
| VC-AI-API-0001 | Private Session Data Sent to Non-Allowlisted External API | AI Agent Trust Boundary Crossing | High |
| VC-AI-SECRETS-0001 | Session Secrets Leaked via Tool Call Arguments | AI Agent Memory Disclosure | High |
| VC-AI-CHAIN-0002 | Cross-Agent State Channel Pollution | AI Agent Trust Boundary Crossing | High |

Each entry is a directory containing:

```
entry.json                 # The canonical theorem record (schema-validated)
README.md                  # Human-readable explanation
mitigation.md              # Concrete remediation
rule.semgrep.yml           # Static detection rule
vulnerable_fixture/        # Self-contained Node fixture; exploit.test.js MUST exit non-zero
patched_fixture/           # Self-contained Node fixture; exploit.test.js MUST exit zero
```

## Try it

Zero external dependencies. Node ≥ 18.

```bash
# from repo root
node compiler/vulnc/bin/vulnc.js check entries/VC-AI-TOOL-0001
node compiler/vulnc/bin/vulnc.js check-all
```

`vulnc check` validates schema, runs both fixtures, validates the static rule, checks duplicates, runs the safety scan, and emits `reports/<ENTRY-ID>.compile-report.json`. Exit 0 ⇔ ACCEPTED.

## Repository layout

```
.
├── README.md                 # this file
├── SCHEMA.md                 # entry contract — read before authoring
├── CONTRIBUTING.md           # how to add an entry
├── schemas/
│   ├── vulnerability.schema.json
│   └── compile-report.schema.json
├── compiler/
│   └── vulnc/                # the security compiler (single-file Node CLI)
├── entries/
│   ├── VC-AI-TOOL-0001/
│   ├── VC-AI-RAG-0001/
│   ├── VC-AI-MEM-0001/
│   ├── VC-AI-ACTION-0001/
│   ├── VC-AI-PROMPT-0001/
│   ├── VC-AI-CHAIN-0001/
│   ├── VC-AI-SSRF-0001/
│   ├── VC-AI-CODEEXEC-0001/
│   ├── VC-AI-API-0001/
│   ├── VC-AI-SECRETS-0001/
│   └── VC-AI-CHAIN-0002/
└── reports/                  # vulnc compile reports land here
```

## Relationship to the Canon protocol

VulnCanon is the **library** half of the Viridis stack. The **protocol** half — settlement, runner network, agent identity — lives in a separate repository (Viridis canon protocol), `architecture/`, etc.

The flywheel:

```
Viridis-Bounty-Hunter finds a live exploit
        ↓
VulnCanon entry created (theorem + fixtures + rule + mitigation + test)
        ↓
Enterprise scanner runs entries against customer code
        ↓
Revenue funds the next hunt
```

VulnCanon is the supply-side moat. Viridis-Bounty-Hunter is the supply mechanism.

## What's deliberately NOT in v1

- **Lean theorems** — reserved for a Phase-2 "proof-mode" premium tier on top of the highest-value entries (auth, payment, capability authorization). Not on the critical path.
- **PROOF Credits / DAO / contributor marketplace** — premature scaling of incentives. Will land after the first paying enterprise customers prove demand pull.
- **Public submission flow** — current contributor scope is `viridis-security-ai-agent` (Justin + Claude). External contributions open after the canon hits ~30 entries and the schema has stabilized.

## Status

v0.1.0 (first public release) — ten entries, all `vulnc check-all` ACCEPTED, all per-entry self-scan differentials hold.

## License

Apache 2.0 (see [LICENSE](./LICENSE)). Content licensed permissively for any use including commercial.

## Founder

**Viridis Security** is the canonical founder and steward of VulnCanon. Forks are welcome; the registry of accepted canon ids is maintained here.

## Cite this work

```
Hart, J. (2026). VulnCanon: A Theorem-Backed Catalog of AI-Agent Vulnerability Classes (v0.1.0)
[Software]. Viridis Security. https://github.com/viridis-security/vulncanon
```

GitHub's "Cite this repository" button (top-right of the repo page) generates BibTeX
and APA from `CITATION.cff`.

## Cross-references

Each canon entry's `entry.json` includes mappings to:

- **OWASP LLM Top 10** (e.g., `LLM01: Prompt Injection`, `LLM02: Insecure Output Handling`)
- **MITRE ATT&CK** techniques where applicable
- **CWE** identifiers for traditional security analogues

Consumers who already use those frameworks can look up VulnCanon entries via existing tooling.
