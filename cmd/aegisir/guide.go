package main

import (
	"errors"
	"fmt"
	"strings"
)

// GuideSection represents a structured investigation runbook for analysts.
type GuideSection struct {
	Name         string
	Title        string
	Mitre        string
	Purpose      string
	Collects     string
	Indicators   []string
	Verification []string
	Remediation  []string
	Cautions     string
}

var detailedGuides = map[string]GuideSection{
	"processes": {
		Name:    "processes",
		Title:   "Active Process & Execution Triage",
		Mitre:   "T1059 (Command & Scripting Interpreter), T1055 (Process Injection), T1105 (Ingress Tool Transfer)",
		Purpose: "Identify unauthorized running binaries, hidden PIDs, shell-spawning services, and processes executing from writable temporary directories.",
		Collects: `/proc/[pid]/status, /proc/[pid]/cmdline, /proc/[pid]/exe, /proc/[pid]/environ, process start ticks, UID/GID, parent PPID chains.`,
		Indicators: []string{
			"Process executable executing from /tmp, /var/tmp, or /dev/shm",
			"Process binary deleted from disk while still running ('(deleted)' in exe symlink)",
			"Reverse shell or download-and-pipe syntax (e.g. curl ... | bash, wget ... | sh)",
			"Web server account (www-data, apache, nginx) spawning an interactive shell (/bin/bash, /bin/sh)",
			"Masquerading process names disguised as kernel threads (e.g. '[kworker]' with user UID)",
		},
		Verification: []string{
			"ls -la /proc/<PID>/exe && readlink -f /proc/<PID>/exe      # Verify true disk location",
			"tr '\\0' ' ' < /proc/<PID>/cmdline && echo \"\"             # Inspect full execution arguments",
			"tr '\\0' '\\n' < /proc/<PID>/environ | head -25           # Review process environment variables",
			"ps -ef --forest | grep -B 2 -A 3 <PID>                    # Examine process ancestor hierarchy",
			"ss -tulpn | grep <PID>                                    # Check listening or active sockets for PID",
			"sha256sum /proc/<PID>/exe                                 # Hash running executable for threat intel",
		},
		Remediation: []string{
			"1. Suspend process to freeze memory before kill: kill -STOP <PID>",
			"2. If evidentiary core dump needed: gcore -o /tmp/proc_<PID>.core <PID>",
			"3. Terminate process after evidence captured: kill -9 <PID>",
			"4. Verify process did not respawn: ps -p <PID>",
			"5. Inspect parent process to confirm no supervisor restarts it",
		},
		Cautions: "Do not terminate critical system daemons (systemd, journald, sshd). Always preserve process evidence and hashes before killing.",
	},
	"files": {
		Name:    "files",
		Title:   "Filesystem & Temporary Directory Triage",
		Mitre:   "T1105 (Ingress Tool Transfer), T1027 (Obfuscated Files), T1036 (Masquerading)",
		Purpose: "Detect staging of malicious binaries, dropped payload scripts, SUID backdoors, and unauthorized files in world-writable paths.",
		Collects: `Inventory of /tmp, /var/tmp, /dev/shm, executable permissions, size, modification/creation timestamps, SHA-256 hashes.`,
		Indicators: []string{
			"ELF executable binaries or shell scripts located in /tmp, /var/tmp, /dev/shm",
			"Hidden directories or files starting with '.' (e.g. /tmp/.../ or /dev/shm/.cache)",
			"Recently created files with SUID or SGID permissions set",
			"Zero-byte or hidden binaries masquerading as known system utilities",
		},
		Verification: []string{
			"stat <path>                                               # Inspect exact Access/Modify/Change timestamps",
			"file <path>                                               # Identify true file type (ELF, script, archive)",
			"strings -n 10 <path> | head -40                           # Inspect embedded URLs, IPs, and command strings",
			"fuser -v <path> || lsof <path>                            # Check if any running process holds or locks file",
			"sha256sum <path>                                          # Calculate SHA-256 hash for threat lookup",
		},
		Remediation: []string{
			"1. Copy sample to secure forensic archive: cp -a <path> /root/evidence_quarantine/",
			"2. Strip executable bits to neutralize: chmod 000 <path>",
			"3. Quarantine or remove file: mv <path> /root/evidence_quarantine/<filename>.quarantine",
			"4. Check filesystem for sibling files created around the same timestamp",
		},
		Cautions: "Quarantining files in production can break applications if the file was created by an approved service. Corroborate ownership first.",
	},
	"mounts": {
		Name:    "mounts",
		Title:   "Storage & Mount Point Exposure",
		Mitre:   "T1021.002 (SMB/Windows Admin Shares), T1567 (Exfiltration Over Web Service)",
		Purpose: "Identify mounted shared storage volumes (NFS, CIFS/SMB) that could allow lateral movement, unauthorized access, or data staging.",
		Collects: `/proc/mounts, filesystem types, mount options (rw, ro, nosuid, nodev, noexec), remote server IP endpoints.`,
		Indicators: []string{
			"Remote NFS or CIFS/SMB file shares mounted without business documentation",
			"World-writable filesystems mounted without 'noexec' or 'nosuid' protection",
			"Unusual mount points created under user home directories or /tmp",
		},
		Verification: []string{
			"mount | grep -E '(nfs|cifs|smb|fuse)'                     # Filter for remote network filesystems",
			"findmnt -l                                                # List full hierarchical mount trees",
			"ss -ant '( dport = :2049 or dport = :445 )'               # Check active connections to storage servers",
			"lsof +f -- <mount_point>                                  # Identify all processes accessing the mount",
		},
		Remediation: []string{
			"1. Coordinate with storage and system administrator prior to unmounting",
			"2. Flush buffers and unmount gracefully: umount <mount_point>",
			"3. If busy, perform scoped lazy unmount: umount -l <mount_point>",
			"4. Review and clean /etc/fstab to prevent remounting on system reboot",
		},
		Cautions: "Unmounting active database or shared app volumes abruptly can cause application hangs or corruption. Verify consumers first.",
	},
	"network": {
		Name:    "network",
		Title:   "Network Connections & Socket Triage",
		Mitre:   "T1043 (Commonly Used Port), T1571 (Non-Standard Port), T1071 (Application Layer Protocol)",
		Purpose: "Uncover rogue listening ports, backdoor sockets, command-and-control (C2) beaconing, and anomalous outbound network flows.",
		Collects: `/proc/net/tcp, /proc/net/udp, /proc/net/tcp6, /proc/net/udp6, listening/established socket states, local/remote IPs, socket inodes.`,
		Indicators: []string{
			"Listening TCP/UDP ports outside standard host baseline (e.g. 4444, 1337, 6667, 8888)",
			"Outbound established TCP connection to suspicious or unapproved external IP address",
			"Non-standard service mapping (e.g. SSH on port 443, HTTP on port 22)",
			"Processes with open raw network sockets without packet capture authorization",
		},
		Verification: []string{
			"ss -tulpn                                                 # List all listening sockets with process PID/name",
			"ss -antp '( state established )'                          # List all active established outbound connections",
			"lsof -i :<port>                                           # Correlate specific port directly to running binary",
			"tcpdump -nn -i any -c 25 port <port>                      # Sample live packet metadata for the suspicious port",
		},
		Remediation: []string{
			"1. Block remote destination at host firewall: iptables -I OUTPUT -d <IP> -j DROP",
			"2. Block inbound unauthorized port: iptables -I INPUT -p tcp --dport <port> -j DROP",
			"3. Terminate owning process once socket evidence is captured",
			"4. Check DNS queries in resolver logs to identify resolved domain names",
		},
		Cautions: "Be careful not to block authorized management IPs or VPN tunnels. Verify target endpoint before applying firewall rules.",
	},
	"firewall": {
		Name:    "firewall",
		Title:   "Host Firewall & Policy Review",
		Mitre:   "T1562.004 (Disable or Modify System Firewall)",
		Purpose: "Verify host firewall health, detect disabled security controls, and inspect for rogue ACCEPT rules or port forwarding.",
		Collects: `iptables filter and NAT tables, nftables rulesets, default chain policies, rule counters.`,
		Indicators: []string{
			"Firewall completely inactive or default policy set to ACCEPT on all inbound chains",
			"Broad permissive ACCEPT rules added recently from external IP ranges",
			"Port forwarding or NAT PREROUTING rules diverting traffic",
		},
		Verification: []string{
			"iptables -L -n -v --line-numbers                          # List all IPv4 filter chains with packet counters",
			"iptables -t nat -L -n -v                                  # Inspect NAT table for redirection rules",
			"nft list ruleset                                          # List modern nftables ruleset if installed",
			"diff -u /etc/iptables/rules.v4 <(iptables-save)           # Diff active rules against saved baseline",
		},
		Remediation: []string{
			"1. Export compromised state for audit record: iptables-save > /root/firewall_triage.rules",
			"2. Restore verified infrastructure baseline: iptables-restore < /etc/iptables/rules.v4.approved",
			"3. Re-enable default DROP policy on external interfaces",
		},
		Cautions: "Never flush firewall rules remotely without a safe cron recovery timer; a bad flush can lock you out of SSH.",
	},
	"users": {
		Name:    "users",
		Title:   "User Accounts & Privilege Escalation",
		Mitre:   "T1078 (Valid Accounts), T1136 (Create Account), T1548.003 (Sudo and Sudoers)",
		Purpose: "Detect unauthorized user accounts, secondary UID 0 accounts, service privilege escalation, and insecure sudo configurations.",
		Collects: `/etc/passwd, /etc/group, /etc/sudoers, /etc/sudoers.d/*, UID/GID assignments, supplementary group memberships.`,
		Indicators: []string{
			"Non-root user account assigned UID 0 (secondary superuser backdoor)",
			"Web application service account (www-data, nginx, apache) added to sudo or wheel group",
			"Passwordless unrestricted sudo directive configured ('NOPASSWD: ALL')",
			"User accounts created outside authorized provisioning windows",
		},
		Verification: []string{
			"awk -F: '($3 == 0) {print $1,$3}' /etc/passwd             # Find all accounts with UID 0",
			"grep -E '(sudo|wheel|root)' /etc/group                    # List all members of privileged groups",
			"grep -rn 'NOPASSWD' /etc/sudoers /etc/sudoers.d/          # Audit passwordless sudo permissions",
			"lastlog -b 0 | head -25                                   # Check recent logins for all users",
			"passwd -S <username>                                      # Check account status (L=locked, P=usable)",
		},
		Remediation: []string{
			"1. Lock unauthorized user account immediately: passwd -l <username>",
			"2. Expire account credentials: usermod --expiredate 1 <username>",
			"3. Terminate active sessions for user: pkill -u <username>",
			"4. Remove unauthorized group membership: gpasswd -d <username> sudo",
			"5. Fix sudoers file using 'visudo' to validate syntax before saving",
		},
		Cautions: "Always maintain at least one verified administrative session open when altering sudoers or user authentication configs.",
	},
	"services": {
		Name:    "services",
		Title:   "Systemd Services & Timers Persistence",
		Mitre:   "T1543.002 (Systemd Service Persistence)",
		Purpose: "Detect persistence achieved through rogue systemd unit files, altered service commands, and scheduled systemd timers.",
		Collects: `Systemd unit files in /etc/systemd/system and /lib/systemd/system, ExecStart commands, timer triggers, enabled states.`,
		Indicators: []string{
			"ExecStart command pointing to /tmp, /var/tmp, or user writable locations",
			"Service file created recently without corresponding package manager package",
			"Service configured with Restart=always pointing to unverified binary",
			"Systemd timers configured to execute scripts at high frequencies",
		},
		Verification: []string{
			"systemctl status <unit>                                   # Check unit status and recent logs",
			"systemctl cat <unit>                                      # View unit file definition and drop-in overrides",
			"systemctl list-timers --all                               # View all active systemd timer schedules",
			"journalctl -u <unit> -n 50 --no-pager                     # Review recent execution history for the service",
			"sha256sum <exec_path>                                     # Verify service binary integrity against rpm/dpkg",
		},
		Remediation: []string{
			"1. Stop running service: systemctl stop <unit>",
			"2. Disable and mask unit: systemctl disable --now <unit> && systemctl mask <unit>",
			"3. Backup unit file: cp -a /etc/systemd/system/<unit> /root/evidence_quarantine/",
			"4. Reload systemd daemon: systemctl daemon-reload",
		},
		Cautions: "Do not disable core operating system services (ssh, network, systemd-resolved) without validating their purpose.",
	},
	"cron": {
		Name:    "cron",
		Title:   "Scheduled Tasks & Cron Persistence",
		Mitre:   "T1053.003 (Cron Persistence)",
		Purpose: "Uncover recurring execution mechanisms installed in system crontabs, user cron spools, and hourly/daily periodic jobs.",
		Collects: `/etc/crontab, /etc/cron.d/*, /etc/cron.{hourly,daily,weekly,monthly}/*, /var/spool/cron/crontabs/*.`,
		Indicators: []string{
			"Cron command invoking download tools (curl, wget, nc, python -c, bash -i)",
			"Cron job executing scripts located in /tmp, /var/tmp, or /dev/shm",
			"Obfuscated cron entries (base64 strings, hex notation, environment overrides)",
			"Crontab file modified within the compromise timeline window",
		},
		Verification: []string{
			"crontab -l -u <user>                                      # View crontab for specific user",
			"ls -la /etc/cron.* /etc/cron.d/                           # List system-wide cron files and timestamps",
			"grep -i cron /var/log/syslog | tail -50                   # Review recent cron execution logs in syslog",
			"stat /etc/cron.d/<filename>                               # Check modification timestamps of cron files",
		},
		Remediation: []string{
			"1. Backup cron file before modifying: cp -a /etc/cron.d/<file> /root/evidence_quarantine/",
			"2. Comment out or delete the rogue schedule line",
			"3. If user crontab is compromised: crontab -u <user> -r (or edit with crontab -u <user> -e)",
			"4. Locate and quarantine any scripts referenced by the cron entry",
		},
		Cautions: "Take a backup before editing crontab files. Be careful with file permissions in /etc/cron.d (must be owned by root, 0644).",
	},
	"ssh": {
		Name:    "ssh",
		Title:   "SSH Authorized Keys & Access Policy",
		Mitre:   "T1098.004 (SSH Authorized Keys), T1021.004 (SSH Lateral Movement)",
		Purpose: "Inspect for unauthorized SSH keys backdooring root or user accounts, and verify SSH server security posture.",
		Collects: `~/.ssh/authorized_keys, root authorized keys, key fingerprints, SSH server configuration directives.`,
		Indicators: []string{
			"Unknown or unapproved public key appended to /root/.ssh/authorized_keys",
			"PermitRootLogin enabled in sshd_config without key-only restriction",
			"Authorized key entries configured with embedded forced commands ('command=\"...\"')",
			"authorized_keys file modified within incident timeframe",
		},
		Verification: []string{
			"ssh-keygen -lf /root/.ssh/authorized_keys                 # List fingerprints and comments of all keys",
			"stat /root/.ssh/authorized_keys                           # Inspect file modification timestamp",
			"grep 'Accepted publickey' /var/log/auth.log | tail -25    # Audit recent key-based SSH logins",
			"sshd -T | grep -E '(permitrootlogin|passwordauthentication)' # Verify effective runtime SSH configuration",
		},
		Remediation: []string{
			"1. Backup authorized_keys file: cp -a /root/.ssh/authorized_keys /root/.ssh/authorized_keys.bak",
			"2. Remove unauthorized public key lines from authorized_keys",
			"3. Enforce key-only login: set 'PermitRootLogin prohibit-password' in /etc/ssh/sshd_config",
			"4. Validate config syntax and reload: sshd -t && systemctl reload sshd",
		},
		Cautions: "Always verify you have another working login session or console access before modifying SSH daemon configurations.",
	},
	"profiles": {
		Name:    "profiles",
		Title:   "Shell Initialization & Profile Hijacking",
		Mitre:   "T1546.004 (Unix Shell Configuration Modification)",
		Purpose: "Detect persistence mechanisms and backdoors embedded inside shell startup scripts that execute whenever a user logs in.",
		Collects: `/etc/profile, /etc/profile.d/*, /etc/bash.bashrc, ~/.bashrc, ~/.bash_profile, ~/.profile, ~/.zshrc.`,
		Indicators: []string{
			"Background network calls or scripts spawned on shell initialization",
			"Malicious command aliases hooking standard utilities (alias sudo=..., alias ls=...)",
			"Suspicious environment variables (LD_PRELOAD, altered PATH) injected in profile",
			"Profile files with timestamps inconsistent with base OS installation",
		},
		Verification: []string{
			"diff -u /etc/skel/.bashrc ~/.bashrc                       # Compare user profile against clean default template",
			"ls -la /etc/profile.d/                                    # Check for newly created system-wide profile scripts",
			"grep -E '(curl|wget|nc|/tmp|base64|LD_PRELOAD)' ~/.bashrc # Search for suspicious keywords in profile files",
			"alias                                                     # Inspect active aliases in current shell session",
		},
		Remediation: []string{
			"1. Backup infected profile: cp -a ~/.bashrc ~/.bashrc.infected",
			"2. Remove rogue lines or restore from clean template: cp /etc/skel/.bashrc ~/.bashrc",
			"3. Check all user accounts on system for similar profile modifications",
		},
		Cautions: "Ensure syntax is valid before saving profile files to prevent user login script failures.",
	},
	"logs": {
		Name:    "logs",
		Title:   "Authentication & Audit Log Review",
		Mitre:   "T1070 (Indicator Removal), T1110 (Brute Force)",
		Purpose: "Identify brute force attacks, credential stuffing, privilege escalation, and detect indicators of log tampering or clearing.",
		Collects: `/var/log/auth.log, /var/log/secure, systemd journal entries, failed and successful login events.`,
		Indicators: []string{
			"High frequency bursts of failed password attempts from external IP addresses",
			"Successful authentication immediately following repeated password failures",
			"Gaps in log records or truncated log files indicating log clearing",
			"Sudo execution attempts by unauthorized service or daemon accounts",
		},
		Verification: []string{
			"grep 'Failed password' /var/log/auth.log | awk '{print $(NF-3)}' | sort | uniq -c | sort -nr | head -20",
			"grep 'Accepted' /var/log/auth.log | tail -30              # Review recent successful logins and methods",
			"journalctl --verify                                       # Verify journald forward-secure sealing if enabled",
			"lastb -n 30                                               # Display recent failed login attempts",
		},
		Remediation: []string{
			"1. Archive current logs immediately for evidence preservation: tar -czf /root/logs_evidence.tar.gz /var/log",
			"2. Enforce IP blocking on active attacker IPs: fail2ban-client set sshd banip <IP>",
			"3. Configure remote syslog shipping to ensure tamper-resistant off-host log retention",
		},
		Cautions: "Do not delete or truncate log files during an investigation. Maintain logs in read-only forensic storage.",
	},
	"readiness": {
		Name:    "readiness",
		Title:   "System Readiness & Collector Health",
		Mitre:   "NIST SP 800-61 Preparation Phase",
		Purpose: "Verify host clock synchronization (NTP), audit logging status, collector permissions, and evidentiary readiness.",
		Collects: `Host identity, kernel version, NTP synchronization status, timezone, collector execution capabilities.`,
		Indicators: []string{
			"Host clock desynchronized from NTP reference (invalidates timeline correlation)",
			"Logging daemon (rsyslog or systemd-journald) inactive or misconfigured",
			"Collector executing without sufficient permissions to read process environments",
		},
		Verification: []string{
			"timedatectl status                                        # Check NTP synchronization and timezone",
			"chronyc tracking || ntpq -p                               # Check detailed NTP offset and jitter",
			"systemctl status rsyslog systemd-journald                 # Verify logging service status",
			"id                                                        # Verify collector user privileges and UID",
		},
		Remediation: []string{
			"1. Synchronize host clock: timedatectl set-ntp true && systemctl restart systemd-timesyncd",
			"2. Ensure logging daemon is active: systemctl start rsyslog",
			"3. Execute triage scans with sufficient privilege to ensure complete visibility",
		},
		Cautions: "Accurate timestamps are critical for timeline reconstruction. Never manually set the clock backwards during an active incident.",
	},
}

func normalizeGuideTopic(name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	switch name {
	case "process", "processes", "p", "proc":
		return "processes"
	case "file", "files", "f":
		return "files"
	case "mount", "mounts", "m":
		return "mounts"
	case "network", "net", "n":
		return "network"
	case "firewall", "fw":
		return "firewall"
	case "user", "users", "u":
		return "users"
	case "service", "services", "s":
		return "services"
	case "cron", "crontab", "c":
		return "cron"
	case "ssh", "k":
		return "ssh"
	case "profile", "profiles", "bash", "b":
		return "profiles"
	case "log", "logs", "l":
		return "logs"
	case "readiness", "r", "doctor":
		return "readiness"
	case "workflow", "wf", "ir", "playbook", "":
		return "workflow"
	default:
		return name
	}
}

func printWorkflowGuide() {
	fmt.Printf("\n  %s%s╔═════════════════════════════════════════════════════════════════════════╗%s\n", colorBold, colorCyan, colorReset)
	fmt.Printf("  %s%s║           AEGISIR • NIST SP 800-61 REV 3 IR WORKFLOW PLAYBOOK           ║%s\n", colorBold, colorCyan, colorReset)
	fmt.Printf("  %s%s╚═════════════════════════════════════════════════════════════════════════╝%s\n\n", colorBold, colorCyan, colorReset)

	fmt.Println("  1. PREPARATION")
	fmt.Println("     • Verify clock synchronization (NTP) to guarantee timeline validity")
	fmt.Println("     • Confirm legal authority, asset ownership, and out-of-band communication trees")
	fmt.Println("     • Ensure logging retention and collector execution health")
	fmt.Println()
	fmt.Println("  2. IDENTIFICATION & TRIAGE")
	fmt.Println("     • Validate alert indicators against local host baseline")
	fmt.Println("     • Answer the Three Critical IR Questions:")
	fmt.Println("       [1] Active Malware?          [2] Suspicious Communications?   [3] Persistence?")
	fmt.Println("     • Capture volatile forensic evidence with cryptographic SHA-256 digests")
	fmt.Println()
	fmt.Println("  3. SCOPE & CONTAINMENT")
	fmt.Println("     • Determine affected systems, accounts, and network boundaries")
	fmt.Println("     • Coordinate scoped, reversible containment (host isolation, IP blocking)")
	fmt.Println("     • Never destroy volatile memory before required artifacts are preserved")
	fmt.Println()
	fmt.Println("  4. ERADICATION")
	fmt.Println("     • Identify root cause of initial intrusion")
	fmt.Println("     • Remove persistence mechanisms (cron jobs, systemd units, authorized SSH keys)")
	fmt.Println("     • Rotate compromised credentials and patch vulnerable applications")
	fmt.Println()
	fmt.Println("  5. RECOVERY")
	fmt.Println("     • Restore services from verified, trusted baselines")
	fmt.Println("     • Enforce enhanced monitoring and log review")
	fmt.Println("     • Re-verify cryptographic evidence hashes and integrity")
	fmt.Println()
	fmt.Println("  6. LESSONS LEARNED & AUDIT")
	fmt.Println("     • Reconstruct tamper-evident case timeline from chained audit logs")
	fmt.Println("     • Export executive reports in HTML, Markdown, or SIEM-ready JSON")
	fmt.Println("     • Update detection rules and defensive playbooks")
	fmt.Println()
	fmt.Printf("  %sAVAILABLE MODULE PLAYBOOKS:%s\n", colorBold, colorReset)
	fmt.Println("  Run: aegisir -guide <module>  for in-depth investigation runbooks")
	fmt.Println("  Modules: processes, files, mounts, network, firewall, users, services, cron, ssh, profiles, logs, readiness")
	fmt.Println()
}

func printGuide(name string) error {
	canonical := normalizeGuideTopic(name)
	if canonical == "workflow" {
		printWorkflowGuide()
		return nil
	}

	g, ok := detailedGuides[canonical]
	if !ok {
		return errors.New("unknown help topic; use 'aegisir modules' or 'aegisir guide workflow'")
	}

	fmt.Printf("\n  %s%s╔═════════════════════════════════════════════════════════════════════════╗%s\n", colorBold, colorCyan, colorReset)
	fmt.Printf("  %s%s║  AEGISIR PLAYBOOK: %-52s ║%s\n", colorBold, colorCyan, strings.ToUpper(g.Title), colorReset)
	fmt.Printf("  %s%s╚═════════════════════════════════════════════════════════════════════════╝%s\n", colorBold, colorCyan, colorReset)

	fmt.Printf("\n  %sMITRE ATT&CK ALIGNMENT:%s\n  %s\n", colorBold, colorReset, g.Mitre)
	fmt.Printf("\n  %sPURPOSE & SCOPE:%s\n  %s\n", colorBold, colorReset, g.Purpose)
	fmt.Printf("\n  %sEVIDENCE COLLECTED:%s\n  %s\n", colorBold, colorReset, g.Collects)

	fmt.Printf("\n  %s%sSUSPICIOUS INDICATORS TO INVESTIGATE:%s\n", colorBold, colorYellow, colorReset)
	for _, ind := range g.Indicators {
		fmt.Printf("   • %s\n", ind)
	}

	fmt.Printf("\n  %s%sSTEP-BY-STEP CROSS-VERIFICATION COMMANDS:%s\n", colorBold, colorGreen, colorReset)
	for _, cmd := range g.Verification {
		fmt.Printf("   $ %s\n", cmd)
	}

	fmt.Printf("\n  %s%sCONTAINMENT & REMEDIATION RUNBOOK:%s\n", colorBold, colorMagenta, colorReset)
	for _, rem := range g.Remediation {
		fmt.Printf("   %s\n", rem)
	}

	fmt.Printf("\n  %s%sFORENSIC CAVEAT:%s\n  %s%s%s\n\n", colorBold, colorDim, colorReset, colorDim, g.Cautions, colorReset)
	return nil
}
