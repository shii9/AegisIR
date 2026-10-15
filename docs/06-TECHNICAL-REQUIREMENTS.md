# Technical Requirements and Engineering Decisions

## Chosen stack

- **Go 1.23+ standard library:** cross-compiled Linux CLI, bounded concurrent `/proc` collection, `os/exec` subprocess bridge, preflight checks for the two experimental local actions.
- **Python 3.10+ standard library:** deterministic detectors, `sqlite3`, case state machine, evidence serialization, SHA-256 and Markdown report generation.
- **SQLite WAL:** no database server required for a single analyst's local workflow.
- **Markdown + Mermaid:** versioned diagrams, PRD, response playbooks and implementation plans.
- **Go test and Python unittest:** dependency-free unit/integration tests; GitHub Actions CI sample.

## Performance strategy

1. Go `collector.Collect` limits concurrency to four collectors and sets per-module context timeouts.
2. Paths are intentionally bounded. `/tmp` and `/var/tmp` walking has depth, count and hash-size limits; process count and log lines are capped.
3. Python starts only for a case operation and processes structured JSON; SQLite is local. Avoid heavy Python ML startup cost when no AI model is used.
4. For high-volume logs and long-lived monitoring, future stream indexing and remote events should be implemented in an isolated collector service; no misleading 'real-time EDR' claim for this snapshot version.
5. Benchmark CPU, RSS, filesystem load and scan completeness under realistic Linux hosts before selecting new dependencies or rewriting working modules.

## Collector implementation requirements

| Collector | Bound/source | Key restrictions |
|---|---|---|
| readiness | hostname, OS, UTC, timedatectl | missing NTP must be reported as warning |
| users | /etc/passwd and /etc/group | no password hashes/shadow collection |
| processes | `/proc/[pid]/{status,stat,cmdline,exe}` capped | argv redaction best effort, may include sensitive context |
| files | /tmp and /var/tmp limited scan | no blanket recursive `/`, no symlink following |
| mounts | /proc/mounts capped | only active mounts, not historical completeness |
| network | `/proc/net` with socket inode → PID on visible FDs | no PCAP, IPv6 address abbreviated |
| firewall | nftables/iptables textual rules | may be inaccessible; must report partial |
| services | systemctl unit files and timer summaries | no change of systemd state |
| cron | system crontabs and readable spool | permission gaps possible |
| ssh | authorized_keys fingerprints | no private keys or full public-key collection |
| profiles | suspicious shell initialization lines | read limited size, redact obvious secrets |
| logs | bounded journalctl and auth logs | no proof of retention completeness |

## Detection requirements

Each finding MUST include a source scan ID, deterministic rule name, module, severity, confidence level, observed detail and recommended next step. MITRE mapping is applied only when supported by a reasonably corresponding observed indicator. No inference that a system is safe from a zero-hit scan.

## Response safety requirements

The Go action layer must reject root execution, unsupported action types, unapproved cases and synthetic demonstrations. Experimental SIGTERM is restricted to a matching non-root owner, PID > 99, preserved start ticks and executable under writable temporary locations. File quarantine requires regular operator-owned file, exact SHA256, permitted path, same filesystem, operator-owned 0700 destination and interactive confirmation. Both are lab-only and require `AEGISIR_ENABLE_LAB_ACTIONS=YES` plus `--live`. There is no generic shell, file deletion, cron edit, sudoers edit or account-disable executor.

## Operational and deployment requirements

- Linux kernel procfs and at least partial user visibility.
- Python executable available as `python3` on `PATH`.
- `python/engine.py` adjacent to binary in release folder, or explicit `AEGISIR_ENGINE`.
- A user-owned, private `AEGISIR_HOME` with enough space for scans, reports and SQLite WAL.
- No `sudo` required, although collection completeness will be limited without privilege or externally approved collection channels.
- Retention and secure deletion policy must be set externally; v0.2 has no purge scheduler or cloud backup.

## Identified security risks to fix before production

- PID reuse TOCTOU; use Linux pidfd APIs and a policy-signed request rather than raw PID signaling.
- File rename TOCTOU; use `openat2`, `renameat2`, file descriptor based checks, mount/user namespace awareness and replay protection.
- Trust of the local endpoint; compromised root can modify collector output, hashes and cases.
- Incomplete secret redaction in argv and logs.
- No independent verifier of outcome, no remote attestation, no legal evidentiary chain-of-custody controls.
- Database row migrations and concurrency are simple; not multi-tenant scalable.

The response engine must remain disabled on sensitive machines until these risks are independently reviewed and mitigated.
