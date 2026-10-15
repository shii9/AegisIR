<div align=center>

`
  ╔═══════════════════════════════════════════════════════════╗
  ║     █████╗ ███████╗ ██████╗ ██╗███████╗██╗██████╗         ║
  ║    ██╔══██╗██╔════╝██╔════╝ ██║██╔════╝██║██╔══██╗        ║
  ║    ███████║█████╗  ██║  ███╗██║███████╗██║██████╔╝        ║
  ║    ██╔══██║██╔══╝  ██║   ██║██║╚════██║██║██╔══██╗        ║
  ║    ██║  ██║███████╗╚██████╔╝██║███████║██║██║  ██║        ║
  ╚═══════════════════════════════════════════════════════════╝
`

# AegisIR — Linux Incident Response & Forensic Tool

**v0.2.0** · Read-only by default · No network listener · No root required · NIST SP 800-61 aligned

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Go](https://img.shields.io/badge/Go-1.22+-00ADD8?logo=go)](https://go.dev)
[![Python](https://img.shields.io/badge/Python-3.9+-3776AB?logo=python)](https://python.org)
[![Platform](https://img.shields.io/badge/Platform-Linux%20x86__64%20%7C%20arm64-lightgrey)](.)
[![Tests](https://img.shields.io/badge/Tests-9%20passing-brightgreen)](#testing)

</div>

---

## Table of Contents

- [Overview](#overview)
- [Key Features](#key-features)
- [System Architecture](#system-architecture)
- [Incident Response Workflow](#incident-response-workflow)
- [Collection Modules](#collection-modules)
- [Quick Start](#quick-start)
- [Command Reference](#command-reference)
- [Output & Reports](#output--reports)
- [Past Case & Incident Management](#past-case--incident-management)
- [Investigation Guides](#investigation-guides)
- [Security Model](#security-model)
- [Project Structure](#project-structure)
- [Building from Source](#building-from-source)
- [Testing](#testing)
- [Limitations & Roadmap](#limitations--roadmap)
- [License](#license)

---

## Overview

**AegisIR** is a self-contained, offline-capable Linux incident response tool for authorized security analysts. It combines a fast Go CLI with a Python analysis engine to collect forensic evidence, detect suspicious behavior using deterministic rules, manage incident cases, and generate tamper-evident reports — all without a network connection or privileged daemon.

> **Designed for:** Security analysts, incident responders, SOC teams, and students performing authorized Linux triage.  
> **Not designed for:** Automated autonomous containment, enterprise multi-host response, or unauthenticated deployment.

---

## Key Features

| Feature | Description |
|---|---|
| 🔍 **12 Forensic Modules** | Processes, files, mounts, network, users, services, cron, SSH, shell profiles, logs, firewall, readiness |
| 🛡️ **Read-Only by Default** | All collectors are non-destructive; no system changes without explicit analyst approval |
| 📊 **Multi-Format Reports** | Export evidence as .md, .json, .html, or .txt |
| 🔐 **Tamper-Evident Audit** | SHA-256 evidence digests + chained audit log for every case |
| 📋 **NIST SP 800-61 Workflow** | Built-in 6-phase incident response checklist (Preparation → Lessons Learned) |
| 🧠 **ATT&CK-Aligned Detection** | Deterministic rules mapped to MITRE ATT&CK techniques |
| 💡 **Offline IR Guides** | 13 built-in investigation playbooks accessible without internet |
| 🗃️ **SQLite Case Management** | Full case lifecycle: create → scan → inspect → decide → report → verify |
| ⚡ **Zero Dependencies** | Single statically-linked binary + Python 3; no agent, no daemon, no root |

---

## System Architecture

AegisIR follows a strict **operator-trust boundary** model. The Go CLI is the control plane; the Python engine handles analysis and persistence. There is **no network API** and no privileged server process.

### Data Flow

`
┌──────────────────────────────────────────────────────────────────┐
│                    IR Analyst / Terminal                           │
└────────────────────────────┬─────────────────────────────────────┘
                             │  aegisir -process / -all / -cases
                             ▼
┌──────────────────────────────────────────────────────────────────┐
│                     Go CLI (cmd/aegisir)                           │
│  ┌─────────────┐  ┌──────────────┐  ┌──────────────────────────┐ │
│  │  Flag/TUI   │  │   Collector  │  │    Live Action Gate      │ │
│  │  Parser     │  │  (12 mods)   │  │  (disabled by default)   │ │
│  └──────┬──────┘  └──────┬───────┘  └──────────────────────────┘ │
└─────────┼────────────────┼───────────────────────────────────────┘
          │                │ read-only JSON
          │                ▼
          │  ┌─────────────────────────────────┐
          │  │   Linux procfs / systemd / logs  │
          │  │   /proc  /sys  /var  /etc  ~     │
          │  └─────────────────────────────────┘
          │
          │  Bounded JSON stdin/stdout (bridge)
          ▼
┌──────────────────────────────────────────────────────────────────┐
│                   Python Engine (python/engine.py)                 │
│  ┌──────────────┐  ┌─────────────────┐  ┌────────────────────┐  │
│  │  Detection   │  │  Case/Workflow   │  │   Report Export    │  │
│  │  Rules Engine│  │  SQLite Database │  │  md/json/html/txt  │  │
│  └──────┬───────┘  └────────┬────────┘  └────────────────────┘  │
│         │                   │                                     │
│  ┌──────▼───────────────────▼──────────────────────────────────┐ │
│  │   Evidence Store (JSON + SHA-256) · Audit Chain (SQLite)    │ │
│  └─────────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────────┘
`

### Component Roles

| Component | Role | Write Access |
|---|---|---|
| cmd/aegisir/main.go | CLI entrypoint, flag parsing, interactive prompts | None |
| cmd/aegisir/tui.go | Formatted terminal output for cases and findings | None |
| cmd/aegisir/guide.go | Offline IR playbooks and investigation guides | None |
| internal/collector/ | 12 read-only Linux collectors | None |
| internal/bridge/ | Bounded JSON subprocess IPC | None |
| internal/actions/ | Restricted lab-only action executor | Lab artifacts only |
| python/engine.py | Detection rules, case DB, report generation | Case evidence + DB |

### Control vs Data Planes

| Plane | Handles |
|---|---|
| **Control** | CLI flags, TUI menus, workflow requests, action authorization |
| **Data** | Go collectors, JSON evidence capture, Python rule evaluation, SQLite findings |
| **Evidence** | Case-specific JSON snapshots, SHA-256 digests, chained audit hashes, Markdown reports |
| **Security** | User ownership, umask 077, bounded reads, no network listener, explicit action approval |

---

## Incident Response Workflow

AegisIR is structured around the **NIST SP 800-61 Rev. 3** six-phase incident response lifecycle.

`
┌──────────────┐     ┌──────────────────┐     ┌─────────────────────┐
│ 1.PREPARATION│────▶│ 2. IDENTIFICATION │────▶│ 3. SCOPE & CONTAIN  │
│              │     │                  │     │                     │
│ -doctor      │     │ -demo            │     │ -all / -process     │
│ -guide       │     │ -process         │     │ -findings           │
│ -readiness   │     │ -network -user   │     │ -inspect            │
└──────────────┘     └──────────────────┘     └──────────┬──────────┘
        ▲                                                 │
        │  new controls                                   ▼
┌───────┴──────┐     ┌──────────────────┐     ┌─────────────────────┐
│ 6. LESSONS   │◀────│  5. RECOVERY     │◀────│ 4. ERADICATION      │
│    LEARNED   │     │                  │     │                     │
│ -verify      │     │ -checklist       │     │ -decide             │
│ -report      │     │ -note            │     │ -guide <topic>      │
│ -timeline    │     │ -show            │     │ -plan               │
└──────────────┘     └──────────────────┘     └─────────────────────┘
`

### Finding Decision State Machine

Each suspicious finding goes through a documented decision lifecycle:

`
            ┌─────────┐
            │ PENDING │  ◀── finding created after scan
            └────┬────┘
         ┌───────┼───────┐
         ▼       ▼       ▼
     ┌──────┐ ┌──────┐ ┌───────┐
     │ SKIP │ │DEFER │ │APPROVE│
     └──┬───┘ └──┬───┘ └───┬───┘
        │        │          │
        │        └──────────┤
        │                   ▼
        │          ┌─────────────────┐
        │          │ ACTION ELIGIBLE │  (lab only, analyst must confirm)
        │          └────────┬────────┘
        │                   ▼
        │          ┌─────────────────┐
        └─────────▶│    RECORDED     │  ◀── re-scan & verify independently
                   └─────────────────┘
`

> Every decision requires a written analyst reason. No automatic execution ever occurs.

---

## Collection Modules

All 12 modules are **read-only**. No system state is modified during collection.

| Flag | Module | What Is Collected | ATT&CK Relevance |
|---|---|---|---|
| -p / -process | Processes | PIDs, PPIDs, UIDs, executables, command lines, parent chains | T1059, T1543, T1055 |
| -f / -file | Files | Executables/scripts in /tmp, /var/tmp, /dev/shm; metadata & hashes | T1105, T1036 |
| -m / -mount | Mounts | Mount points, NFS/CIFS shares, filesystem types | T1039, T1083 |
| -n / -network | Network | Listening ports, active connections, socket states, owning PIDs | T1049, T1071 |
| -u / -user | Users | Accounts, UID 0 accounts, sudo/wheel members, service accounts | T1078, T1136 |
| -s / -service | Services | Systemd units, timers, ExecStart paths, enabled state | T1543.002 |
| -c / -cron | Cron | Scheduled tasks, cron.d entries, user crontabs | T1053.003 |
| -k / -ssh | SSH | Authorized key SHA-256 fingerprints, root keys, sshd config | T1098.004 |
| -b / -bash | Profiles | Shell init persistence: .bashrc, .profile, .bash_profile | T1546.004 |
| -l / -log | Logs | Auth logs, journal entries, failed logins, sudo events | T1070.002 |
| -fw / -firewall | Firewall | iptables/nftables policy rules, chain defaults | T1562.004 |
| -r / -readiness | Readiness | NTP sync, logging health, permissions, collector availability | — |

---

## Quick Start

### Prerequisites

`ash
# Required on the target Linux host
python3 --version   # Python 3.9+
# No other dependencies needed
`

### Installation

`ash
# Option 1 — Download pre-built binary (recommended)
wget https://github.com/shii9/AegisIR/releases/latest/download/aegisir-linux-amd64.tar.gz
tar -xzf aegisir-linux-amd64.tar.gz
chmod +x aegisir

# Option 2 — Per-user install via script
bash scripts/install.sh

# Option 3 — Build from source (see Building from Source)
`

### First Run

`ash
aegisir -doctor                         # Verify system & collector readiness
aegisir -demo                           # Safe synthetic demo (no real data)
aegisir -process                        # Scan running processes
aegisir -all -o incident-report.html    # Full scan → HTML report
aegisir -ui                             # Interactive terminal menu
`

---

## Command Reference

### General

`
aegisir -h / -help        Show this help message
aegisir -v / -version     Show version information
aegisir -ui               Interactive terminal menu
aegisir -doctor           Check system & collector readiness
aegisir -demo             Run a safe synthetic incident demo
aegisir -modules          List all 12 collection modules
`

### Scan Modules

`
aegisir -p  / -process    Scan processes — PIDs, executables, command lines
aegisir -f  / -file       Scan files    — executables in temp/writable paths
aegisir -m  / -mount      Scan mounts   — filesystem mount points & shares
aegisir -n  / -network    Scan network  — ports, connections, socket owners
aegisir -u  / -user       Scan users    — accounts, UID 0, sudo membership
aegisir -s  / -service    Scan services — systemd units, timers, ExecStart
aegisir -c  / -cron       Scan cron     — scheduled tasks & crontabs
aegisir -k  / -ssh        Scan SSH      — authorized keys & sshd config
aegisir -b  / -bash       Scan profiles — shell init persistence
aegisir -l  / -log        Scan logs     — auth logs & failed logins
aegisir -fw / -firewall   Scan firewall — iptables/nftables policy
aegisir -r  / -readiness  Check readiness — NTP, logging, permissions
`

### Combined Scan & Output

`
aegisir -all                      Scan all 12 modules at once
aegisir -all -o report.html       Scan all → save HTML report
aegisir -all -o report.json       Scan all → export SIEM-ready JSON
aegisir -all -o report.md         Scan all → save Markdown report
aegisir -fmt md / -format json    Explicitly set output format
`

**Supported formats:** .md (Markdown), .json (SIEM JSON), .html (Executive HTML), .txt (Plain text)

### Multi-Module Scan Examples

`ash
# Scan specific modules and save report
aegisir -file -mount -process -o new.md

# Scan network and users, export JSON for SIEM ingestion
aegisir -network -user -o siem-export.json
`

---

## Output & Reports

AegisIR generates structured forensic reports with SHA-256 evidence digests. Each report includes:

- **Executive Summary** — severity, asset, analyst, timestamps
- **Module Results** — per-module findings with raw evidence
- **Suspicious Findings** — scored, ATT&CK-mapped indicators
- **Recommendations** — actionable mitigation steps with cross-verification commands
- **Evidence Integrity** — SHA-256 digest for every collected artifact
- **Audit Trail** — chained log of all analyst decisions

### Report Format Examples

`ash
aegisir -all -o report.html          # Rich HTML for executives/presentations
aegisir -all -o report.md            # Markdown for wiki/ticketing systems
aegisir -all -o report.json          # Structured JSON for SIEM/SOAR ingestion
aegisir -all -o report.txt           # Plain text for terminal/email
aegisir -report -o incident.html     # Export existing case as HTML
`

---

## Past Case & Incident Management

AegisIR maintains a full SQLite-backed case lifecycle with cryptographic evidence integrity.

### Case Commands

`ash
aegisir -cases                           # List all incident cases
aegisir -show                            # Show 3 IR questions for latest case
aegisir -show CASE-2024-001              # Dashboard for a specific case
aegisir -timeline                        # Chronological activity for latest case
aegisir -timeline CASE-2024-001          # Timeline for a specific case
aegisir -verify                          # Verify SHA-256 evidence integrity
aegisir -verify CASE-2024-001            # Verify a specific case
aegisir -checklist                       # 6-phase NIST IR checklist
aegisir -checklist CASE-2024-001         # Checklist for a specific case
aegisir -report -o incident.html         # Export latest case report
aegisir -report CASE-2024-001 -o out.md  # Export specific case
aegisir -note Analyst note text        # Add timestamped note to latest case
`

### The 3 Core IR Questions

Every case dashboard (-show) answers:

1. **Is malware active?** — Live process analysis, executable provenance, memory indicators
2. **Is there suspicious communication?** — Socket analysis, network connections, service owners
3. **Is there persistence?** — Cron, services, authorized keys, shell profiles, scheduled tasks

---

## Investigation Guides

Built-in offline playbooks with step-by-step procedures, ATT&CK context, and cross-verification commands.

`ash
aegisir -guide process      # Process investigation playbook
aegisir -guide file         # File system forensics guide
aegisir -guide network      # Network analysis guide
aegisir -guide user         # User & privilege escalation guide
aegisir -guide service      # Service persistence investigation
aegisir -guide cron         # Scheduled task analysis
aegisir -guide ssh          # SSH key & config forensics
aegisir -guide firewall     # Firewall rule analysis
aegisir -guide logs         # Log analysis & tampering detection
aegisir -guide readiness    # IR readiness checklist
aegisir -guide workflow     # Full IR workflow overview
`

Each guide contains:

| Section | Content |
|---|---|
| **Purpose** | What to investigate and why |
| **Evidence Collected** | Exact data sources queried |
| **Suspicious Indicators** | What warrants escalation |
| **Cross-Verification Commands** | Shell commands to confirm findings (grep, ss, lsof, stat, systemctl) |
| **Containment Runbook** | Step-by-step response procedures |
| **MITRE ATT&CK Mapping** | Relevant technique IDs |

---

## Security Model

### Trust Boundaries

`
┌─────────────────────────────────────────────────────┐
│  TRUSTED: Authorized IR Analyst + Local Terminal     │
│                                                     │
│  ┌─────────────────────────────────────────────┐   │
│  │  AegisIR Process (same OS identity)          │   │
│  │  • Go CLI  •  Python Engine  •  Collectors   │   │
│  └─────────────────────────────────────────────┘   │
│                                                     │
│  UNTRUSTED: All data from the compromised host      │
│  • /proc entries   • Log files   • User input       │
└─────────────────────────────────────────────────────┘
`

### Security Properties

| Property | Implementation |
|---|---|
| **Read-only collection** | Collectors use only read syscalls; no writes to /proc, /sys, or system paths |
| **No root requirement** | Runs at analyst privilege level; refuses root live actions |
| **No network listener** | Zero open ports; Python is a child process via stdin/stdout |
| **Tamper-evident evidence** | SHA-256 digest per evidence file; chained audit log in SQLite |
| **Bounded resource use** | File count caps, depth limits, byte limits, subprocess timeouts |
| **Explicit action approval** | Live actions require: analyst approval + lab flag + TTY confirmation + preflight |
| **No credential collection** | Does not collect /etc/shadow, SSH private keys, or raw environment variables |

### Threat Model

| Threat | Control | Residual Risk |
|---|---|---|
| Unintended destructive action | Read-only scan; live actions require lab flag + typed confirmation | Operator error and race conditions |
| Unauthorized root execution | Explicit refusal of root live-action execution | Inadequate for enterprise remote response |
| Evidence tampering | SHA-256 digests + audit chain | Local root can modify both file and DB |
| Credential exposure | No shadow/private keys collected | Sensitive data may appear in cmdlines/logs |
| False positive → overblocking | Confidence shown; decision reason mandatory | Rules need production baseline evaluation |

> ⚠️ **AegisIR v0.2 is a triage and case-management tool. It is not a replacement for full forensic acquisition, enterprise SOAR platforms, or legal chain-of-custody evidence handling.**

---

## Project Structure

`
AegisIR/
├── cmd/
│   └── aegisir/
│       ├── main.go              # CLI entrypoint, all commands & flags
│       ├── tui.go               # Terminal UI — cases, findings, dashboards
│       └── guide.go             # 13 offline IR investigation playbooks
│
├── internal/
│   ├── collector/
│   │   ├── collector.go         # 12 read-only Linux forensic collectors
│   │   └── collector_test.go
│   ├── actions/
│   │   ├── actions.go           # Restricted lab-only action executor
│   │   └── actions_test.go
│   └── bridge/
│       └── bridge.go            # Bounded JSON stdin/stdout subprocess IPC
│
├── python/
│   ├── engine.py                # Case DB, detection rules, report export
│   └── test_engine.py           # 9 unit tests (all passing)
│
├── docs/
│   └── diagrams/                # Rendered architecture & workflow diagrams (PNG/SVG/DOT)
│
├── scripts/
│   ├── install.sh               # Per-user installation
│   ├── smoke.sh                 # CLI integration tests
│   └── package.sh               # Build Linux amd64/arm64 tarballs
│
├── examples/
│   └── demo-workflow.md         # Operator exercise & synthetic attack story
│
├── dist/
│   └── aegisir                  # Pre-built Linux amd64 binary
│
├── Makefile                     # Build, test, and package targets
├── go.mod
├── LICENSE
└── README.md
`

---

## Building from Source

### Requirements

- Go 1.22+ (Windows or Linux)
- Python 3.9+ (on target Linux host)
- Linux host for execution

### Build

`ash
# Clone the repository
git clone https://github.com/shii9/AegisIR.git
cd AegisIR

# Build Linux amd64 binary
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -o dist/aegisir ./cmd/aegisir

# Build for arm64 (Raspberry Pi, AWS Graviton)
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -o dist/aegisir-arm64 ./cmd/aegisir

# Or use make
make build
`

### Makefile Targets

`ash
make build      # Build Linux amd64 binary → dist/aegisir
make test       # Run Go + Python unit tests
make lint       # Run go vet and staticcheck
make package    # Build amd64 + arm64 distribution tarballs
make clean      # Remove build artifacts
`

---

## Testing

`ash
# Run all Python unit tests
python3 -m unittest python/test_engine.py -v

# Run Go unit tests
go test ./...

# Smoke test against the compiled binary
bash scripts/smoke.sh

# Safe synthetic demo (no real data collected)
aegisir -demo
`

### Test Coverage

| Suite | Tests | Status |
|---|---|---|
| Python engine unit tests | 9 tests | ✅ All passing |
| Tamper detection | Audit chain integrity | ✅ Passing |
| Workflow enforcement | Case lifecycle state machine | ✅ Passing |
| Detection rules | ATT&CK rule evaluation | ✅ Passing |
| Path validation | Input sanitization | ✅ Passing |
| Report integrity | Overwrite protection + hash | ✅ Passing |

---

## Limitations & Roadmap

### Current Limitations (v0.2)

- No real-time notifications or WebSocket live updates
- No multi-analyst RBAC or two-person approval workflow
- No GPS/map integration for network geolocation
- No SMS/email notification system
- No multi-factor authentication
- No memory capture or full disk imaging
- No enterprise multi-host orchestration
- Local SHA-256 chain is not admissible legal chain of custody

### Planned Features

| Feature | Description |
|---|---|
| 🌐 Cloud deployment | Multi-tenant SaaS with encrypted evidence object store |
| 📡 WebSocket updates | Real-time finding notifications during scan |
| 🗺️ Map integration | IP geolocation and network topology visualization |
| 📱 Mobile companion | Android/iOS app for on-call analysts |
| 🔑 MFA support | TOTP/hardware key authentication |
| 🧠 AI advisory | Optional isolated LLM advisory (citation-only, non-executive) |
| 🏢 Enterprise RBAC | Role-based access, two-person approval, WORM audit export |
| 📧 Notifications | Email/SMS alerts for critical findings |
| 📍 Asset inventory | Integrated CMDB for baseline comparison across hosts |

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development guidelines, branch conventions, and the pull request process.

## Security Disclosure

See [SECURITY.md](SECURITY.md) for responsible disclosure instructions. Please report security issues privately before publishing an exploit.

> **Test only on disposable VMs, non-sensitive lab accounts, or synthetic incidents.**  
> Never run live actions in CI or on production hosts without authorized change management approval.

---

## License

MIT License — see [LICENSE](LICENSE) for full text.

---

<div align=center>

**AegisIR** — Built for authorized incident responders. Read-only. Evidence-first. Analyst-controlled.

*Collect → Detect → Decide → Report → Verify*

</div>
