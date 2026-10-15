# System Architecture and Component Design

![Rendered system architecture](diagrams/system-architecture.png)

## Architecture A — Operator & Trust Boundaries

```mermaid
flowchart TB
  subgraph OPERATOR ["TRUSTED OPERATOR DOMAIN"]
    Analyst["Authorized IR Analyst / Terminal"]
    CLI["Go CLI + ANSI Interactive TUI"]
    Collector["12 Linux Read-Only Collectors"]
    Gate["Live Action Gate (Lab Only, Disabled by Default)"]
  end

  subgraph TARGET ["TARGET HOST FORENSIC ARTIFACTS"]
    Host["Linux procfs / systemd / logs / user files"]
  end

  subgraph ENGINE ["DATA & PERSISTENCE PLANE"]
    Bridge["Bounded JSON stdin/stdout IPC Bridge"]
    Python["Python Analytics & Case Engine"]
    Rules["Deterministic ATT&CK Detection Rules"]
    DB[("SQLite Store (Cases, Findings, Audit Chain)")]
    Evidence[("Evidence Vault (SHA-256 Hashed JSON)")]
    Reports["Multi-Format Reports (MD / HTML / JSON / TXT)"]
  end

  Analyst --> CLI
  CLI --> Collector
  Collector --> Host
  CLI --> Gate
  CLI --> Bridge
  Collector --> Bridge
  Bridge --> Python
  Python --> Rules
  Python --> DB
  Python --> Evidence
  Python --> Reports
```

There is **no network API** and no privileged server in v0.2. Python is a child process of the analyst's Go CLI; both execute with the operator's unprivileged permissions. Containment actions are restricted to lab artifacts and are disabled by default.

---

## Architecture B — Working Data & Execution Sequence

```mermaid
sequenceDiagram
    actor IR as IR Analyst
    participant G as Go CLI Control Plane
    participant C as Go Linux Collectors
    participant P as Python Heuristic Engine
    participant E as Evidence Vault
    participant D as SQLite Database
    
    IR->>G: aegisir -all -o report.html (or aegisir -p)
    Note over G: [1/5] Auto-create case in SQLite
    G->>P: op: "new" (hostname, analyst, timestamp)
    P->>D: INSERT INTO cases
    P-->>G: case_id
    
    Note over G: [2/5] Read-only collection across 12 modules
    G->>C: collect(processes, network, files, etc.)
    C-->>G: normalized JSON evidence + warnings
    
    Note over G: [3/5] Heuristic & ATT&CK analysis
    G->>P: op: "scan" (case_id, modules)
    P->>E: write raw evidence (mode 0600)
    E-->>P: SHA-256 digest per evidence file
    P->>P: evaluate deterministic ATT&CK rules
    P->>D: record scans, findings, audit hashes
    P-->>G: summary (items, findings, status, warnings)
    
    Note over G: [4/5] Interactive finding inspection & mitigation
    G->>P: op: "findings", op: "inspect"
    P-->>G: finding details, recommendations, cross-verification commands
    G-->>IR: display finding cards & prompt [Y/N]
    alt Analyst approves mitigation
        IR->>G: [Y] approve
        opt Safe lab action executable
            G->>G: validate PID / file hash, execute action
        end
        G->>P: op: "decide" (choice: approve, reason: analyst rationale)
        P->>D: append to immutable audit chain
    else Analyst skips
        IR->>G: [N] skip
        G->>P: op: "decide" (choice: skip, reason: analyst passed)
        P->>D: append to immutable audit chain
    end
    
    Note over G: [5/5] Multi-format forensic report export
    G->>P: op: "report" (format, output path)
    P->>D: compile case metadata, findings, audit log, SHA-256 digests
    P-->>G: exported report path & hash
    G-->>IR: formatted report file + completion banner
```

---

## Architecture C — Roles of Architectural Components

| Component | Implementation | Write Privileges | Safety Boundary |
|---|---|---|---|
| **Collector Engine** | Go `internal/collector/` | None (Read-only observation) | Bounded reads, buffer limits, per-collector timeouts |
| **Detection Engine** | Python `engine.py:evaluate()` | Case evidence / DB only | Deterministic MITRE ATT&CK rules, explainable criteria |
| **Guidance Engine** | Go `cmd/aegisir/guide.go` | None | Built-in offline playbooks with verification commands |
| **Case & Audit Store** | Python SQLite `engine.py` | User-owned directory (`~/.aegisir`) | Scoped case IDs, chained hash integrity |
| **Mitigation Gate** | Go `internal/actions/` | Restricted lab targets only | Refuses root actions, verifies ownership, requires typed confirmation |
| **Report Exporter** | Python `engine.py` | Target file specified by user | Multi-format (.md, .json, .html, .txt), no silent overwrite |

---

## Architecture D — Data & Control Planes

- **Control plane:** Go CLI (`cmd/aegisir/main.go`), numbered ANSI terminal UI (`tui.go`), flag parser, and analyst authorization prompts.
- **Data plane:** 12 Go Linux collectors, JSON serialization, Python rule correlation engine, structured SQLite findings.
- **Evidence plane:** Case-specific JSON snapshots with SHA-256 digests, chained SQLite audit events, exported reports.
- **Security plane:** Per-user file permissions (`0700` directories, `0600` files), `umask 077`, bounded syscalls, zero network listeners, root action refusal.

---

## Attack Surface & Limitations

1. `/proc` and system logs are kernel/filesystem structures and can be manipulated by an attacker who has already obtained root privileges.
2. Unprivileged execution means access is partial for foreign user directories, raw packet sockets, and restricted systemd units.
3. Process PIDs can be reused between validation and signal delivery; lab containment is an educational/testing feature, not an enterprise containment agent.
4. Local evidence hashing provides tamper detection on the machine, but does not substitute for an off-host WORM storage audit archive in legal forensic proceedings.
