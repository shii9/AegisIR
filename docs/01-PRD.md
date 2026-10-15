# Product Requirements Document (PRD)

**Product:** AegisIR | **Version:** 0.2.0 | **Audience:** SOC L1/L2/L3, Linux IR, DFIR engineer, case owner

## Problem and product thesis

Linux incident responders often execute ad-hoc shell commands, collect evidence into unrelated files, then attempt to reconstruct decisions in a report. Repeated manual searches create omissions, inconsistent triage, weak evidence provenance and error-prone remediation. AegisIR combines *local discovery + normalized evidence + explainable heuristic findings + analyst-controlled actions + verifiable case records* into one terminal workbench.

## Scope and guiding principles

1. **Linux-first, terminal-first**, usable without network access or service installation.
2. **Collect before change** where feasible; immediate containment may override normal sequencing with clear approval.
3. **Evidence-based:** every auto-generated finding points to an actual stored scan, never ungrounded model speculation.
4. **Human authority:** no `scan` or `approve` command directly modifies a host. Skip/defer require reasons and do not imply incident closure.
5. **Explain limitations:** a partial collector or no findings must never be marketed as a clean host.
6. **Privacy and minimum collection:** fingerprint public SSH keys, avoid shadow files, private keys and process environment variables.

## Users and desired outcomes

- SOC L1: understand alert, validate context, identify three critical questions and document escalation.
- SOC L2 / IR analyst: run scoped collectors, triage risky users/processes/persistence, choose mitigation or deferral.
- Incident commander: track stage, assigned investigator, evidence coverage, outstanding risks, timeline and report.
- DFIR engineer: export hashed evidence and identify when more rigorous forensic acquisition is necessary.

## Functional requirements and acceptance

| ID | Requirement | Acceptance test | v0.2 |
|---|---|---|---|
| FR-01 | Stable terminal CLI + banner + menu | `aegisir`, `aegisir help`, `aegisir ui` | Implemented |
| FR-02 | Local Linux triage | 12 modules collect bounded structured results | Implemented |
| FR-03 | Case workflow | All six phases and checklist items stored in SQLite | Implemented |
| FR-04 | Detection | Rule, severity, confidence, evidence scan ID and advice | Implemented |
| FR-05 | Three IR questions | Report status as review indicator/unverified | Implemented |
| FR-06 | Decisions | Approve, skip, defer per finding; mandatory reason | Implemented |
| FR-07 | Safety | Default read-only; restricted optional actions guarded | Lab-only |
| FR-08 | Provenance | SHA-256 evidence copies + chained local audit integrity verification | Implemented (local only) |
| FR-09 | Report | Export Markdown containing evidence, decisions, checklist and activity timeline | Implemented |
| FR-10 | Event integrations | Wazuh/Splunk/Elastic alert import, correlation, remote agent | Not implemented |
| FR-11 | Trusted baseline engine | Approved host snapshots and deterministic delta comparison | Not implemented |
| FR-12 | Deep acquisition | Memory/disk capture, PCAP, YARA, rootkit forensic workflow | Not implemented |
| FR-13 | Enterprise safety | RBAC, multi-analyst approvals, signed executors, rollback, centralized chain of custody | Not implemented |

## Nonfunctional requirements

- **Correctness:** unknown/partial data surfaces as warnings, not successful proof of coverage.
- **Safety:** no `sudo` requests, generic shell executor, recursive delete or bulk user/group edits.
- **Performance:** bounded collection time, item counts and payload; CLI startup typically dominated by Python runtime and I/O, not expensive computations.
- **Portability:** Linux on amd64 and arm64; Go >=1.23 and Python >=3.10.
- **Security:** private per-user case directory; manual access control; process subprocess JSON protocol without network listener.
- **Reliability:** evidence hashes, SQLite commit and integrity validation; no tamper-resistant guarantee.
- **Usability:** offline help text for every collection module.

## Out of scope for this version

No claims of one-click total cleanup, high-assurance rootkit detection, automatic account deletion, remote containment or unattended AI executor. Those require external authority, threat modeling and verification.

## Success measures for future releases

- Fraction of required IR checklist items recorded with evidence; median alert-to-initial-triage time.
- Agreement between rule findings and validated expert labels across benign/attack datasets.
- Coverage of ATT&CK techniques *with supporting telemetry* (not by product presence).
- False-positive load per host-day, collection completeness and measured scan resource usage.
- Action failure/rollback rate; mean time to verified recovery; reviewed report completeness.
