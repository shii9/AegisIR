# System Architecture and Working Architecture

![Rendered system architecture](diagrams/system-architecture.png)

## Architecture A — operator and trust boundaries

```mermaid
flowchart TB
  Analyst[Authorized IR Analyst / Terminal] --> CLI[Go CLI + Numbered TUI]
  CLI --> Collector[Go Linux Read-only Collectors]
  CLI --> Gate[Go Live Action Gate - disabled by default]
  Collector --> Linux[Linux procfs / systemd / logs / user files]
  CLI --> Bridge[Bounded JSON stdin / stdout subprocess]
  Collector --> Bridge
  Bridge --> Engine[Python Investigation + Case Engine]
  Engine --> Rules[Deterministic Detection Rules]
  Engine --> DB[(SQLite: cases / scans / findings / decisions / audit)]
  Engine --> Evidence[(Private JSON Evidence + SHA-256)]
  Engine --> Report[Markdown IR Report]
  Gate -->|only after explicit approval and confirmation| Local[Restricted local lab action]
  Local -. result .-> Bridge
```

There is **no network API** and no privileged server in v0.2. Python is a child process of the analyst's Go CLI; both run at the same operator privileges. Live actions are limited to the operator's own temporary artifacts and are disabled by default.

## Architecture B — working data path

```mermaid
sequenceDiagram
    actor IR as IR Analyst
    participant G as Go CLI
    participant C as Go Collector
    participant P as Python Engine
    participant E as Evidence Store
    participant D as SQLite
    IR->>G: aegisir scan CASE --module all
    G->>C: run 12 bounded Linux collectors
    C-->>G: normalized JSON with warnings
    G->>P: JSON request via stdin
    P->>E: write evidence files (0600)
    E-->>P: SHA-256 digest
    P->>P: evaluate explainable rules
    P->>D: append scans, findings, audit events
    P-->>G: finding counts and module coverage
    G-->>IR: structured outcome
    IR->>G: inspect -> decide approve/skip/defer
    G->>P: record decision + reason
    P->>D: audit chain update
    opt Lab action specifically enabled
       IR->>G: act --live + interactive exact confirmation
       G->>P: prepare_action: verify finding approval
       P-->>G: approved limited action plan
       G->>G: revalidate target owner/PID/hash
       G->>G: local bounded action
       G->>P: append result to audit
    end
    IR->>G: verify / report
    G->>P: verify evidence hashes, audit chain / export
    P-->>IR: verdict / Markdown report
```

## Architecture C — roles of agents

| Logical agent | Running implementation | Write privileges | Safety boundary |
|---|---|---|---|
| Collection agent | Go `internal/collector` | None by design (read-only observations) | Module limits, path caps and subprocess timeouts |
| Detection agent | Python `detect()` | Case evidence/DB only | Deterministic rules, no arbitrary LLM output |
| Explanation agent | Python finding metadata + Go `guide` | Case DB only | Observed evidence and explicit caveats |
| Case agent | Python SQLite workflow | User-owned case directory | Scoped case IDs, auditable updates |
| Decision agent | Python approval record | Case DB | Analyst reason; no automatic execution |
| Response agent | Go `internal/actions` | Two limited lab changes | Non-root operator, ownership, exact PID start time/hash, TTY typed confirmation |
| Verification agent | Python `verify()` + operator re-scan | Case DB and outputs | Local integrity verification; action effectiveness must be independently checked |
| Report agent | Python Markdown exporter | Chosen report path | No overwrite, logged export hash |

**Future independent AI advisory agent** is intentionally disconnected from execution permissions; adding one requires prompt-injection resilience, isolated tools, factual citations to scan IDs and evaluation. Never let model prose directly issue shell commands.

## Architecture D — data and control planes

- **Control plane:** Go CLI/interactive menu, workflow requests and response-authorization controls.
- **Data plane:** Go Linux collectors, JSON evidence capture, Python rule engine, structured SQLite findings.
- **Evidence plane:** case-specific JSON snapshots and SHA-256; local chained audit hashes; Markdown report.
- **Security plane:** user ownership, `umask 077`, bounded reads, no network listener, explicit action approval, refusal of root actions.

## Attack surface and limitations

1. `/proc` and logs are mutable and can be influenced by a local attacker. A post-compromise root attacker may hide, remove or modify observations.
2. Permission limits mean only partial access to other users, firewall policies, secure journals and SSH key directories.
3. A process PID can be reused between validation and signal; the current restricted SIGTERM is not a high-assurance containment primitive.
4. Local JSON hash + SQLite chain is not a cryptographic chain of custody against a privileged local attacker; use external WORM storage, signatures, independent acquisition timestamps and controlled evidence transfers for evidentiary cases.
5. A case still needs incident commander escalation, legal approval and business-impact decisions. The terminal cannot automate human authority.

## Planned enterprise architecture (not implemented)

```mermaid
flowchart LR
  A[Endpoint Go Agents - signed mTLS] --> B[Collection Gateway]
  B --> C[(Encrypted Evidence Object Store)]
  S[SIEM: Wazuh / Splunk / Elastic] --> Q[Event Ingestion]
  Q --> O[Incident Orchestrator API]
  C --> O
  O --> D[(PostgreSQL + RBAC)]
  O --> R[Rule Engine + Optional Advisory AI]
  R --> H[Human Approval Workflow]
  H --> X[Policy Scoped Remote Executor]
  X --> V[Independent Verification]
  V --> O
```

Before building this, threat-model agent authentication, event provenance, customer data segregation, secrets storage, audit export, rollback and approver independence.
