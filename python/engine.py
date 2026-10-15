#!/usr/bin/env python3
"""AegisIR Python analysis and persistence engine (stdlib-only).

Protocol: one JSON request on stdin, one JSON response on stdout. No shell execution.
Threat classifications are analyst-facing heuristics, never proof of compromise.
"""
from __future__ import annotations
import datetime as dt
import hashlib
import html
import json
import os
from pathlib import Path
import re
import secrets
import sqlite3
import sys
import time

SCHEMA_VERSION = 1
PHASES = ("preparation", "identification", "scope", "eradication", "recovery", "lessons")
MODULES = ("readiness", "users", "processes", "files", "mounts", "network", "firewall", "services", "cron", "ssh", "profiles", "logs")
CHECKLIST = {
 "preparation": ["asset_owner", "contact_plan", "logging_ntp", "legal_authority", "baseline_inventory"],
 "identification": ["alert_validated", "lead_assigned", "attack_window", "three_questions"],
 "scope": ["affected_hosts", "affected_accounts", "network_scope", "volatile_evidence", "containment_decision"],
 "eradication": ["root_cause", "persistence_removed", "credentials_rotated", "vulnerabilities_addressed"],
 "recovery": ["restore_verified", "service_owner_signoff", "enhanced_monitoring", "recurrence_checks"],
 "lessons": ["timeline_review", "evidence_review", "report_approved", "control_improvements"],
}
CASE_RE = re.compile(r"^IR-[A-Z0-9-]{8,50}$")
FIND_RE = re.compile(r"^FD-[A-Z0-9-]{6,50}$")
SUS_PATTERN = re.compile(r"(?i)(/tmp/|/dev/shm/|/var/tmp/|curl\s+.{0,100}\|\s*(?:ba)?sh|wget\s+.{0,100}\|\s*(?:ba)?sh|/dev/tcp/|base64\s+-d)")

def utc() -> str: return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
def hbytes(b: bytes) -> str: return hashlib.sha256(b).hexdigest()
def canonical(v) -> bytes: return json.dumps(v, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
def ident(prefix): return prefix + secrets.token_hex(5).upper()
def home():
    d = Path(os.environ.get("AEGISIR_HOME", str(Path.home() / ".local/share/aegisir"))).expanduser()
    if not d.is_absolute(): raise ValueError("AEGISIR_HOME must be an absolute path")
    d.mkdir(parents=True, exist_ok=True, mode=0o700)
    if d.is_symlink(): raise ValueError("data directory may not be a symlink")
    os.chmod(d, 0o700)
    return d

def db():
    conn = sqlite3.connect(home() / "cases.sqlite3", timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=10000")
    conn.execute("PRAGMA journal_mode=WAL")
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS cases(id TEXT PRIMARY KEY,title TEXT NOT NULL,asset TEXT NOT NULL,analyst TEXT NOT NULL,severity TEXT NOT NULL,phase TEXT NOT NULL,status TEXT NOT NULL,synthetic INTEGER NOT NULL,created_at TEXT NOT NULL,updated_at TEXT NOT NULL,closed_reason TEXT DEFAULT '');
    CREATE TABLE IF NOT EXISTS scans(id TEXT PRIMARY KEY,case_id TEXT NOT NULL REFERENCES cases(id),captured_at TEXT NOT NULL,module TEXT NOT NULL,status TEXT NOT NULL,evidence_path TEXT NOT NULL,evidence_sha256 TEXT NOT NULL,item_count INTEGER NOT NULL,warnings TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS findings(id TEXT PRIMARY KEY,case_id TEXT NOT NULL REFERENCES cases(id),scan_id TEXT NOT NULL REFERENCES scans(id),module TEXT NOT NULL,rule TEXT NOT NULL,severity TEXT NOT NULL,title TEXT NOT NULL,detail TEXT NOT NULL,confidence TEXT NOT NULL,recommendation TEXT NOT NULL,mitre TEXT NOT NULL,decision TEXT NOT NULL DEFAULT 'pending',decision_reason TEXT NOT NULL DEFAULT '',action_type TEXT NOT NULL DEFAULT '',action_json TEXT NOT NULL DEFAULT '{}',action_status TEXT NOT NULL DEFAULT 'not_requested',created_at TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS checklist(case_id TEXT NOT NULL REFERENCES cases(id),phase TEXT NOT NULL,item TEXT NOT NULL,done INTEGER NOT NULL DEFAULT 0,note TEXT NOT NULL DEFAULT '',PRIMARY KEY(case_id,phase,item));
    CREATE TABLE IF NOT EXISTS audits(id INTEGER PRIMARY KEY AUTOINCREMENT,case_id TEXT NOT NULL,created_at TEXT NOT NULL,kind TEXT NOT NULL,detail TEXT NOT NULL,previous_hash TEXT NOT NULL,hash TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS actions(id INTEGER PRIMARY KEY AUTOINCREMENT,case_id TEXT NOT NULL,finding_id TEXT NOT NULL,action_type TEXT NOT NULL,success INTEGER NOT NULL,detail TEXT NOT NULL,executed_at TEXT NOT NULL);
    CREATE INDEX IF NOT EXISTS idx_find_case ON findings(case_id);
    CREATE INDEX IF NOT EXISTS idx_scan_case ON scans(case_id);
    CREATE INDEX IF NOT EXISTS idx_audit_case ON audits(case_id,id);
    """)
    return conn

def row(conn, sql, args=()):
    r = conn.execute(sql, args).fetchone()
    if not r: raise ValueError("case/finding/scan not found")
    return dict(r)

def audit(conn, cid, kind, detail):
    prev = conn.execute("SELECT hash FROM audits WHERE case_id=? ORDER BY id DESC LIMIT 1", (cid,)).fetchone()
    ph = prev[0] if prev else "0" * 64
    created = utc()
    payload = {"case_id":cid,"created_at":created,"kind":kind,"detail":detail,"previous_hash":ph}
    digest = hbytes(canonical(payload))
    conn.execute("INSERT INTO audits(case_id,created_at,kind,detail,previous_hash,hash) VALUES(?,?,?,?,?,?)", (cid,created,kind,detail,ph,digest))

def check_case(conn,cid):
    if not CASE_RE.fullmatch(cid): raise ValueError("invalid case ID")
    return row(conn,"SELECT * FROM cases WHERE id=?",(cid,))

def check_finding(conn,cid,fid):
    if not FIND_RE.fullmatch(fid): raise ValueError("invalid finding ID")
    check_case(conn,cid)
    return row(conn,"SELECT * FROM findings WHERE case_id=? AND id=?",(cid,fid))

def create(conn,r,synthetic=False):
    title=str(r.get("title", "New incident")).strip()[:150]
    asset=str(r.get("asset", "unknown")).strip()[:100]
    analyst=str(r.get("analyst", "unassigned")).strip()[:100]
    sev=r.get("severity","medium")
    if sev not in ("low","medium","high","critical"): raise ValueError("severity must be low|medium|high|critical")
    if not all((title,asset,analyst)): raise ValueError("title, asset and analyst required")
    cid=ident("IR-");now=utc()
    conn.execute("INSERT INTO cases(id,title,asset,analyst,severity,phase,status,synthetic,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)",(cid,title,asset,analyst,sev,"preparation","open",int(synthetic),now,now))
    for phase,items in CHECKLIST.items():
        conn.executemany("INSERT INTO checklist(case_id,phase,item) VALUES(?,?,?)",[(cid,phase,k) for k in items])
    audit(conn,cid,"case_created",json.dumps({"title":title,"asset":asset,"synthetic":synthetic}))
    conn.commit();return {"case_id":cid,"title":title,"synthetic":synthetic}

def finding(module,rule,severity,title,detail,recommendation,mitre="",action=None,confidence="low"):
    return {"module":module,"rule":rule,"severity":severity,"title":title,"detail":detail[:1000],"recommendation":recommendation,"mitre":mitre,"action":action or {},"confidence":confidence}

def detect(m):
    module=m.get("module"); items=m.get("items",[])
    found=[]
    def add(*a,**kw): found.append(finding(module,*a,**kw))
    if module=="readiness":
        if m.get("status")!="ok":
            add("READINESS-GAP","medium","Preparation data incomplete","; ".join(m.get("warnings",[])),
                "1. Verify host clock: timedatectl status && chronyc tracking\n2. Check logging daemons: systemctl status rsyslog systemd-journald\n3. Confirm collector permissions (UID 0 required for full /proc/*/environ)\n4. Verify asset owner and out-of-band communication channel.")
    elif module=="users":
        for u in items:
            if u.get("kind")=="sudo_policy":
                directive=u.get("directive", "")
                if "NOPASSWD:" in directive.upper() and re.search(r"(?i)NOPASSWD:\s*ALL\b",directive):
                    add("SUDO-NOPASSWD-ALL","medium","Passwordless unrestricted sudo rule needs approval review",f"{u.get('source')}: {directive[:170]}",
                        "1. Verify sudoers syntax: visudo -c\n2. Locate exact rule: grep -rn 'NOPASSWD' /etc/sudoers /etc/sudoers.d/\n3. Check account benefiting from this rule: id <user>\n4. Replace unrestricted NOPASSWD: ALL with specific command paths after owner sign-off.","T1548.003",confidence="low")
                continue
            if int(u.get("uid",-1))==0 and u.get("username")!="root":
                add("SECONDARY-UID0","high","Additional UID 0 account",f"Account {u.get('username')} has UID 0.",
                    "1. Cross-verify user in /etc/passwd: grep ':0:' /etc/passwd\n2. Check login history: lastlog -u <username> && last -n 10 <username>\n3. Check crontabs and home files: ls -la /home/<username> 2>/dev/null; crontab -u <username> -l 2>/dev/null\n4. If unauthorized, lock account immediately: passwd -l <username> or usermod -L <username>","T1136.001",confidence="medium")
            groups=set(u.get("supplementary_groups") or [])
            if u.get("username") in ("www-data","nginx","apache","nobody") and groups.intersection({"sudo","wheel","root"}):
                add("PRIVILEGED-SERVICE","high","Service account belongs to privileged group",f"{u.get('username')} groups: {sorted(groups)}",
                    "1. Cross-verify group memberships: id <username> && grep -E '(sudo|wheel|root)' /etc/group\n2. Audit sudoers for service account: grep -rn '<username>' /etc/sudoers /etc/sudoers.d/\n3. Check service journal for exploitation indicators: journalctl -u <service> -n 100 --no-pager\n4. Remove unauthorized membership: gpasswd -d <username> sudo","T1098",confidence="medium")
    elif module=="processes":
        for p in items:
            exe=p.get("exe","");cmd=p.get("cmdline","")
            if str(exe).startswith(("/tmp/","/var/tmp/","/dev/shm/")):
                act={"type":"terminate_process","pid":p.get("pid"),"start_ticks":p.get("start_ticks"),"owner_uid":p.get("uid")}
                add("TEMP-EXECUTABLE","high","Process executing from writable temporary location",f"PID {p.get('pid')} user={p.get('uid')} executable={exe} cmd={cmd[:170]}",
                    f"1. Cross-verify binary path: ls -la /proc/{p.get('pid')}/exe && readlink -f /proc/{p.get('pid')}/exe\n2. Inspect execution arguments: tr '\\0' ' ' < /proc/{p.get('pid')}/cmdline\n3. Check active sockets: ss -tulpn | grep {p.get('pid')}\n4. Calculate running binary SHA-256: sha256sum /proc/{p.get('pid')}/exe\n5. If confirmed rogue, approve scoped termination and verify: ps -p {p.get('pid')}","T1059",act,confidence="medium")
            elif re.search(r"(?i)(curl|wget).{0,140}\|\s*(?:ba)?sh\b",cmd):
                add("PIPE-TO-SHELL","medium","Process command downloads and pipes to shell",f"PID {p.get('pid')}: {cmd[:200]}",
                    f"1. Inspect process hierarchy tree: ps -ef --forest | grep -B 2 -A 2 {p.get('pid')}\n2. Check environment variables: tr '\\0' '\\n' < /proc/{p.get('pid')}/environ\n3. Check open network sockets: ss -antp | grep {p.get('pid')}\n4. Review web/application access logs around execution time.","T1059",confidence="medium")
    elif module=="files":
        for f in items:
            path=str(f.get("path",""))
            if path.startswith(("/tmp/","/var/tmp/")) and (f.get("mode","" ).find("x")>=0 or path.endswith((".sh",".elf",".py"))):
                add("TEMP-EXECUTABLE-FILE","medium","Executable/script in temporary directory",f"{path}, size={f.get('size')} SHA256={f.get('sha256') or 'not collected'}",
                    f"1. Inspect file metadata and timestamp: stat {path}\n2. Check file type and embedded strings: file {path} && strings -n 10 {path} | head -30\n3. Calculate SHA-256 digest: sha256sum {path}\n4. Check if currently executing: fuser -v {path} || lsof {path}\n5. Preserve sample copy to forensic storage before quarantining.","T1105",{"type":"quarantine_file","path":path,"sha256":f.get("sha256"),"owner_uid":f.get("uid")},confidence="low")
    elif module=="mounts":
        for x in items:
            if x.get("filesystem") in ("nfs","nfs4","cifs","smb3"):
                add("REMOTE-MOUNT","info","Remote file share mounted",f"{x.get('source')} -> {x.get('target')} ({x.get('filesystem')})",
                    f"1. Cross-verify mount points: mount | grep -E '(nfs|cifs|smb)' && grep {x.get('target')} /proc/mounts\n2. Check active connections to storage host: ss -ant '( dport = :2049 or dport = :445 )'\n3. Confirm whether shared volume is in incident scope; coordinate with storage admin before unmounting.","T1021",confidence="low")
    elif module=="network":
        seen=set()
        for x in items:
            if x.get("protocol")=="tcp" and x.get("state")=="0A":
                local=str(x.get("local",""));port=local.rsplit(":",1)[-1]
                if port not in {"22","53","80","443","631","3306","5432","6379","8080","8443"} and local not in seen:
                    seen.add(local)
                    if len(seen)<=12:
                        add("LISTENING-PORT-REVIEW","info","Listening TCP port requires baseline review",f"Listener {local}",
                            f"1. Find owning process and PID: ss -tulpn | grep ':{port}' or lsof -i :{port}\n2. Verify binary path: ls -la /proc/<PID>/exe\n3. Inspect listening socket binding: ss -tlpn src :{port}\n4. If unauthorized or external exposure is not needed, restrict with firewall or bind to 127.0.0.1.","T1571",confidence="low")
    elif module=="firewall":
        if not items:
            add("FIREWALL-VISIBILITY-GAP","info","Firewall policy could not be inventoried","No accessible nftables/iptables rules collected.",
                "1. Check firewall utilities: which nft iptables\n2. Verify current user permissions: sudo iptables -L -n -v\n3. Obtain approved firewall baseline from infrastructure/security group for review.")
    elif module=="services":
        for x in items:
            v=str(x.get("exec_start", ""))
            if v and SUS_PATTERN.search(v):
                add("SUSPICIOUS-SERVICE-EXEC","high","Systemd unit starts command from suspicious location",f"Unit {x.get('unit')} {v[:250]}",
                    f"1. Inspect systemd unit definition: systemctl cat {x.get('unit')}\n2. Check unit status and logs: systemctl status {x.get('unit')} && journalctl -u {x.get('unit')} -n 50 --no-pager\n3. Verify binary path and calculate SHA-256\n4. Contain service safely: systemctl stop {x.get('unit')} && systemctl disable --now {x.get('unit')}","T1543.002",confidence="medium")
    elif module=="cron":
        for x in items:
            s=str(x.get("entry",""))
            if SUS_PATTERN.search(s):
                add("SUSPICIOUS-CRON","high","Cron persistence candidate",f"{x.get('source')}: {s[:240]}",
                    f"1. Cross-verify cron file: ls -la {x.get('source')} && stat {x.get('source')}\n2. Inspect referenced script/command content\n3. Check execution logs in syslog: grep -i cron /var/log/syslog\n4. Compute SHA-256 before modifying: sha256sum {x.get('source')}\n5. Backup cron file and comment out unauthorized schedule entry.","T1053.003",confidence="medium")
    elif module=="ssh":
        for x in items:
            if x.get("kind")=="ssh_config":
                if x.get("setting")=="permitrootlogin" and x.get("value", "").lower()=="yes":
                    add("SSH-ROOT-LOGIN-SETTING","medium","Configuration permits root SSH login (effective config unverified)",f"{x.get('source')}: PermitRootLogin yes",
                        "1. Check effective sshd configuration: sshd -T | grep -i permitrootlogin\n2. Inspect config files: grep -rn 'PermitRootLogin' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/\n3. Remediate to key-only or disabled: set 'PermitRootLogin prohibit-password' or 'no'\n4. Test syntax before reload: sshd -t && systemctl reload sshd","T1021.004",confidence="low")
                continue
            if x.get("path","").startswith("/root/"):
                add("ROOT-SSH-KEY-REVIEW","info","Root authorized SSH key present",f"{x.get('path')}: {x.get('fingerprint')}",
                    "1. Inspect root authorized keys file: ls -la /root/.ssh/authorized_keys\n2. Cross-verify key fingerprint against approved admin public key directory\n3. Check authentication logs for recent key usage: grep 'Accepted publickey for root' /var/log/auth.log\n4. If unauthorized, backup file and comment out rogue key line.","T1098.004",confidence="low")
    elif module=="profiles":
        for x in items:
            add("SUSPICIOUS-SHELL-INIT","medium","Shell initialization includes command requiring review",f"{x.get('path')}: {str(x.get('suspicious_lines'))[:280]}",
                f"1. Inspect profile file metadata: ls -la {x.get('path')} && stat {x.get('path')}\n2. Compare against clean template: diff -u /etc/skel/.bashrc {x.get('path')}\n3. Check recent login history: last -n 15\n4. Backup file before edit: cp -a {x.get('path')} {x.get('path')}.ir-backup, then remove malicious command.","T1546.004",confidence="medium")
    elif module=="logs":
        failures=[x for x in items if "failed password" in x.get("line","").lower()]
        if len(failures)>=5:
            add("SSH-FAILED-BURST","medium","Repeated SSH authentication failures",f"Found {len(failures)} matching log lines in bounded log sample.",
                "1. Extract top attacking IP addresses: grep 'Failed password' /var/log/auth.log | awk '{print $(NF-3)}' | sort | uniq -c | sort -nr | head -15\n2. Verify if any attempts succeeded: grep 'Accepted' /var/log/auth.log\n3. Enforce rate limiting or IP block: fail2ban-client set sshd banip <IP> or iptables -I INPUT -s <IP> -j DROP","T1110",confidence="medium")
    return found[:160]

def ingest(conn,cid,r):
    case=check_case(conn,cid)
    if case["status"]!="open":raise ValueError("closed case cannot receive new scan")
    mods=r.get("modules")
    if not isinstance(mods,list) or not mods or len(mods)>12:raise ValueError("expected 1–12 modules")
    details=[]
    evidence_dir=home()/"evidence"/cid;evidence_dir.mkdir(parents=True,exist_ok=True,mode=0o700)
    for m in mods:
        name=m.get("module")
        if name not in MODULES:raise ValueError("unknown module")
        if len(m.get("items",[]))>4000:raise ValueError("oversized module result")
        sid=ident("SC-");b=canonical(m)
        if len(b)>8_000_000:raise ValueError("module exceeds 8MB")
        target=evidence_dir/(sid+".json")
        with target.open("xb") as f:os.chmod(target,0o600);f.write(b);f.flush();os.fsync(f.fileno())
        digest=hbytes(b);fs=detect(m)
        conn.execute("INSERT INTO scans(id,case_id,captured_at,module,status,evidence_path,evidence_sha256,item_count,warnings) VALUES(?,?,?,?,?,?,?,?,?)",(sid,cid,str(m.get("captured_at",utc())),name,str(m.get("status","partial")),str(target),digest,len(m.get("items",[])),json.dumps(m.get("warnings",[]))))
        for f in fs:
            conn.execute("INSERT INTO findings(id,case_id,scan_id,module,rule,severity,title,detail,confidence,recommendation,mitre,action_type,action_json,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",(ident("FD-"),cid,sid,name,f["rule"],f["severity"],f["title"],f["detail"],f["confidence"],f["recommendation"],f["mitre"],f["action"].get("type",""),json.dumps(f["action"]),utc()))
        details.append({"module":name,"items":len(m.get("items",[])),"findings":len(fs),"status":m.get("status","partial"),"warnings":m.get("warnings",[]),"evidence_sha256":digest})
        audit(conn,cid,"evidence_collected",json.dumps({"scan_id":sid,"module":name,"sha256":digest,"findings":len(fs)}))
    conn.execute("UPDATE cases SET phase='identification',updated_at=? WHERE id=?",(utc(),cid))
    conn.commit()
    return {"case_id":cid,"modules":details,"total_findings":sum(x["findings"] for x in details)}

def decisions(conn,cid,fid,choice,reason):
    f=check_finding(conn,cid,fid)
    if choice not in ("approve","skip","defer"):raise ValueError("choice must be approve|skip|defer")
    reason=reason.strip()
    if len(reason)<8:raise ValueError("reason must contain at least 8 characters")
    if f["action_status"]=="executed":raise ValueError("action already executed")
    conn.execute("UPDATE findings SET decision=?,decision_reason=? WHERE id=?",(choice,reason[:500],fid))
    audit(conn,cid,"analyst_decision",json.dumps({"finding_id":fid,"choice":choice,"reason":reason[:500]}))
    conn.commit();return {"finding_id":fid,"decision":choice,"action_available":bool(f["action_type"]),"note":"Skipping one mitigation does not close or resolve the incident."}

def action_plan(conn,cid,fid):
    f=check_finding(conn,cid,fid)
    return {"finding_id":fid,"decision":f["decision"],"action_type":f["action_type"] or "manual_only","action":json.loads(f["action_json"]),"synthetic":bool(check_case(conn,cid)["synthetic"]),"recommendation":f["recommendation"],"risk":"Experimental live actions can alter evidence; use only on an authorized disposable lab host."}

def prepare_action(conn,cid,fid):
    f=check_finding(conn,cid,fid)
    if check_case(conn,cid)["synthetic"]:raise ValueError("live actions prohibited in synthetic case")
    if f["decision"]!="approve":raise ValueError("explicit analyst approval required")
    if f["action_status"]=="executed":raise ValueError("already executed")
    if f["action_type"] not in ("terminate_process","quarantine_file"):raise ValueError("this finding has no implemented live action")
    return action_plan(conn,cid,fid)

def action_result(conn,cid,fid,p):
    f=check_finding(conn,cid,fid)
    # Only invoked by local Go CLI; trusted local operator, not a privileged service API.
    success=bool(p.get("success"));detail=str(p.get("detail",""))[:800]
    conn.execute("INSERT INTO actions(case_id,finding_id,action_type,success,detail,executed_at) VALUES(?,?,?,?,?,?)",(cid,fid,f["action_type"],int(success),detail,utc()))
    conn.execute("UPDATE findings SET action_status=? WHERE id=?",("executed" if success else "failed",fid))
    audit(conn,cid,"action_result",json.dumps({"finding_id":fid,"success":success,"detail":detail}))
    conn.commit();return {"success":success,"detail":detail}

def add_note(conn,cid,body):
    check_case(conn,cid)
    if not body.strip() or len(body)>3000:raise ValueError("note must be 1–3000 characters")
    audit(conn,cid,"analyst_note",body.strip())
    conn.commit()
    return {"case_id":cid,"note_saved":True,"note":"Note recorded in local hash-chained case history."}

def timeline(conn,cid):
    check_case(conn,cid)
    return [dict(x) for x in conn.execute("SELECT id,created_at,kind,detail,hash FROM audits WHERE case_id=? ORDER BY id",(cid,))]

def workflow(conn,cid):
    check_case(conn,cid)
    rows=[dict(x) for x in conn.execute("SELECT phase,item,done,note FROM checklist WHERE case_id=? ORDER BY rowid",(cid,))]
    return {"case_id":cid,"checklist":rows,"phases":list(PHASES),"principle":"Containment is part of scoping/response and can be expedited before full investigation."}

def checklist_set(conn,cid,phase,item,note):
    check_case(conn,cid)
    if phase not in CHECKLIST or item not in CHECKLIST[phase]:raise ValueError("invalid checklist item")
    if not note.strip():raise ValueError("evidence or justification note required")
    conn.execute("UPDATE checklist SET done=1,note=? WHERE case_id=? AND phase=? AND item=?",(note[:500],cid,phase,item))
    audit(conn,cid,"checklist_completed",json.dumps({"phase":phase,"item":item,"note":note[:500]}))
    conn.commit();return {"phase":phase,"item":item,"done":True}

def phase_set(conn,cid,phase,note):
    check_case(conn,cid)
    if phase not in PHASES:raise ValueError("invalid phase")
    if len(note.strip())<8:raise ValueError("phase change requires a reason (8+ chars)")
    conn.execute("UPDATE cases SET phase=?,updated_at=? WHERE id=?",(phase,utc(),cid))
    audit(conn,cid,"phase_changed",json.dumps({"phase":phase,"reason":note[:500]}))
    conn.commit();return {"phase":phase,"note":note[:500]}

def triad(conn,cid):
    fs=[dict(x) for x in conn.execute("SELECT module,rule,title FROM findings WHERE case_id=?",(cid,))]
    # Positive result means an indicator needs validation. Negative means UNVERIFIED, not clean.
    q={"active_malware":{"status":"unverified","evidence":[]},"suspicious_communications":{"status":"unverified","evidence":[]},"persistence":{"status":"unverified","evidence":[]}}
    for f in fs:
        rule=f["rule"]
        targets=[]
        if rule in ("TEMP-EXECUTABLE","PIPE-TO-SHELL","TEMP-EXECUTABLE-FILE"):targets=["active_malware"]
        if rule in ("LISTENING-PORT-REVIEW",):targets=["suspicious_communications"]
        if rule in ("SUSPICIOUS-CRON","SUSPICIOUS-SERVICE-EXEC","ROOT-SSH-KEY-REVIEW","SUSPICIOUS-SHELL-INIT"):targets.append("persistence")
        for t in targets:q[t]["status"]="review_indicators";q[t]["evidence"].append(f["title"])
    return q

def report_text(conn,cid):
    c=check_case(conn,cid)
    esc=lambda s:str(s or "").replace("\n"," ").replace("\r"," ").replace("|","/")
    sc=[dict(r) for r in conn.execute("SELECT * FROM scans WHERE case_id=? ORDER BY captured_at",(cid,))]
    fs=[dict(r) for r in conn.execute("SELECT * FROM findings WHERE case_id=? ORDER BY created_at",(cid,))]
    checklist=[dict(x) for x in conn.execute("SELECT * FROM checklist WHERE case_id=? ORDER BY rowid",(cid,))]
    actions=[dict(x) for x in conn.execute("SELECT * FROM actions WHERE case_id=?",(cid,))]
    lines=[f"# AegisIR Incident Report — {c['id']}","",f"Generated: {utc()}  ","**Live-host triage observations are not a substitute for a full forensic acquisition.**", "", "## Case", f"- Title: {esc(c['title'])}", f"- Asset: {esc(c['asset'])}", f"- Analyst: {esc(c['analyst'])}", f"- Severity: {c['severity']}", f"- Status: {c['status']}",f"- Current workflow phase: {c['phase']}",f"- Synthetic demonstration: {bool(c['synthetic'])}","", "## Three critical IR questions"]
    for name,val in triad(conn,cid).items():lines.append(f"- **{name.replace('_',' ').title()}**: {val['status']} (not proof of malware/compromise)")
    lines.extend(["","## Collection coverage", "| Module | Status | Observations | Evidence SHA-256 |", "|---|---|---:|---|"])
    for x in sc:lines.append(f"| {esc(x['module'])} | {esc(x['status'])} | {x['item_count']} | `{x['evidence_sha256']}` |")
    lines.extend(["", "## Findings", "| ID | Severity | Rule | Decision | Action status |", "|---|---|---|---|---|"])
    for f in fs:lines.append(f"| {f['id']} | {f['severity']} | {esc(f['rule'])} | {f['decision']} | {f['action_status']} |")
    for f in fs:
        rec_lines = "\n  ".join(esc(line) for line in f["recommendation"].split("\n"))
        lines.extend(["",f"### {f['id']} — {esc(f['title'])}",f"- Module: {esc(f['module'])}; MITRE: {esc(f['mitre']) or 'unmapped'}; Confidence: {f['confidence']}",f"- **Observed:** {esc(f['detail'])}",f"- **Interpretation:** Review indicator; detection is heuristic and unconfirmed.",f"- **Recommended Cross-Verification & Mitigation:**\n  {rec_lines}",f"- **Decision:** {f['decision']} — {esc(f['decision_reason'])}"])
    lines.extend(["","## Workflow checklist"])
    for x in checklist:lines.append(f"- [{'x' if x['done'] else ' '}] {x['phase']}: {x['item']} — {esc(x['note'])}")
    lines.extend(["","## Action attempts"])
    for a in actions:lines.append(f"- {a['executed_at']}: {a['finding_id']} {a['action_type']} success={bool(a['success'])} — {esc(a['detail'])}")
    lines.extend(["","## Case activity timeline"])
    for a in conn.execute("SELECT created_at,kind,detail FROM audits WHERE case_id=? ORDER BY id",(cid,)):
        lines.append(f"- {a['created_at']} — {esc(a['kind'])}: {esc(a['detail'])[:250]}")
    lines.extend(["","## Collection and evidentiary limitations", "- Volatile state can change during collection; use external acquisition for evidentiary work.","- Sources may be unreadable or truncated. Verify coverage before concluding absence of activity.","- Local SHA-256 and chained audit hashes help detect changes but are not tamper-proof custody.","- No automatic threat attribution, business impact conclusion, or claim of full eradication."])
    return "\n".join(lines)+"\n"

def report_data(conn,cid):
    c=check_case(conn,cid)
    sc=[dict(r) for r in conn.execute("SELECT * FROM scans WHERE case_id=? ORDER BY captured_at",(cid,))]
    fs=[dict(r) for r in conn.execute("SELECT * FROM findings WHERE case_id=? ORDER BY created_at",(cid,))]
    checklist=[dict(x) for x in conn.execute("SELECT * FROM checklist WHERE case_id=? ORDER BY rowid",(cid,))]
    actions=[dict(x) for x in conn.execute("SELECT * FROM actions WHERE case_id=?",(cid,))]
    audits=[dict(x) for x in conn.execute("SELECT created_at,kind,detail FROM audits WHERE case_id=? ORDER BY id",(cid,))]
    return {
        "report_version":"1.0",
        "generated_at":utc(),
        "case":{"id":c["id"],"title":c["title"],"asset":c["asset"],"analyst":c["analyst"],"severity":c["severity"],"phase":c["phase"],"status":c["status"],"synthetic":bool(c["synthetic"]),"created_at":c["created_at"],"updated_at":c["updated_at"]},
        "three_critical_questions":triad(conn,cid),
        "coverage":sc,
        "findings":fs,
        "checklist":checklist,
        "actions":actions,
        "timeline":audits,
        "limitations":["Volatile state can change during collection; use external acquisition for evidentiary work.","Sources may be unreadable or truncated. Verify coverage before concluding absence of activity.","Local SHA-256 and chained audit hashes help detect changes but are not tamper-proof custody.","No automatic threat attribution, business impact conclusion, or claim of full eradication."]
    }

def report_html(conn,cid):
    d=report_data(conn,cid)
    c=d["case"]
    esc=html.escape
    sev_colors={"critical":"#ef4444","high":"#f97316","medium":"#eab308","low":"#38bdf8","info":"#94a3b8"}
    sev_color=sev_colors.get(c["severity"].lower(),"#38bdf8")

    findings_html=[]
    for f in d["findings"]:
        f_sev_color=sev_colors.get(f["severity"].lower(),"#94a3b8")
        mitre_tag=f'<span class="badge" style="background:#1e293b;border:1px solid #475569;color:#94a3b8;">MITRE: {esc(f["mitre"])}</span>' if f.get("mitre") else ''
        findings_html.append(f"""
        <div class="card finding-card">
            <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;">
                <h3 style="margin:0;font-size:1.1rem;color:#f8fafc;">{esc(f["title"])}</h3>
                <div>
                    <span class="badge" style="background:{f_sev_color}22;border:1px solid {f_sev_color};color:{f_sev_color};">{esc(f["severity"].upper())}</span>
                    {mitre_tag}
                </div>
            </div>
            <div style="font-size:0.85rem;color:#94a3b8;margin-bottom:12px;">
                <span><strong>ID:</strong> {esc(f["id"])}</span> | 
                <span><strong>Module:</strong> {esc(f["module"])}</span> | 
                <span><strong>Rule:</strong> {esc(f["rule"])}</span> | 
                <span><strong>Confidence:</strong> {esc(f["confidence"])}</span>
            </div>
            <div style="background:#090d16;padding:10px 14px;border-radius:6px;font-family:monospace;font-size:0.85rem;color:#cbd5e1;margin-bottom:10px;word-break:break-all;">
                {esc(f["detail"])}
            </div>
            <div style="background:#0f172a;border-left:3px solid #10b981;padding:10px 14px;margin-bottom:8px;font-size:0.9rem;">
                <strong style="color:#10b981;">Recommended Mitigation & Cross-Verification:</strong>
                <div style="margin-top:6px;line-height:1.6;color:#e2e8f0;white-space:pre-wrap;">{esc(f["recommendation"])}</div>
            </div>
            <div style="font-size:0.85rem;color:#94a3b8;">
                <strong>Analyst Decision:</strong> <span style="color:#f8fafc;">{esc(f["decision"])}</span> {('— ' + esc(f['decision_reason'])) if f.get('decision_reason') else ''}
            </div>
        </div>
        """)
    if not findings_html:
        findings_html.append('<div class="card" style="text-align:center;color:#10b981;padding:20px;">✓ No suspicious indicators found during collection.</div>')

    triad_html=[]
    for k,v in d["three_critical_questions"].items():
        q_name=k.replace("_"," ").title()
        is_alert=v["status"]=="review_indicators"
        status_color="#ef4444" if is_alert else "#10b981"
        evidence_list="".join(f"<li>{esc(e)}</li>" for e in v.get("evidence",[]))
        if evidence_list:
            evidence_list=f'<ul style="margin:4px 0 0 0;padding-left:18px;font-size:0.85rem;color:#94a3b8;">{evidence_list}</ul>'
        triad_html.append(f"""
        <div class="triad-box" style="border-left:4px solid {status_color};">
            <div style="display:flex;justify-content:space-between;align-items:center;">
                <span style="font-weight:600;color:#f8fafc;">{q_name}</span>
                <span class="badge" style="background:{status_color}22;color:{status_color};border:1px solid {status_color};">{esc(v["status"].upper())}</span>
            </div>
            {evidence_list}
        </div>
        """)

    scans_html=[]
    for s in d["coverage"]:
        scans_html.append(f"""
        <tr>
            <td style="font-weight:600;color:#f8fafc;">{esc(s["module"])}</td>
            <td><span class="badge" style="background:#10b98122;color:#10b981;border:1px solid #10b981;">{esc(s["status"])}</span></td>
            <td>{s["item_count"]} items</td>
            <td style="font-family:monospace;font-size:0.8rem;color:#94a3b8;">{esc(s["evidence_sha256"])}</td>
        </tr>
        """)

    timeline_html=[]
    for a in d["timeline"]:
        timeline_html.append(f"""
        <div style="display:flex;gap:12px;margin-bottom:10px;font-size:0.85rem;">
            <span style="color:#64748b;font-family:monospace;min-width:170px;">{esc(a["created_at"])}</span>
            <span class="badge" style="background:#1e293b;border:1px solid #334155;color:#38bdf8;align-self:flex-start;">{esc(a["kind"])}</span>
            <span style="color:#cbd5e1;word-break:break-word;">{esc(a["detail"])}</span>
        </div>
        """)

    checklist_html=[]
    current_phase=""
    for item in d["checklist"]:
        if item["phase"]!=current_phase:
            current_phase=item["phase"]
            checklist_html.append(f'<div style="font-weight:700;color:#38bdf8;margin:12px 0 6px 0;text-transform:uppercase;font-size:0.8rem;letter-spacing:1px;">{esc(current_phase)}</div>')
        done_icon="✓" if item["done"] else "○"
        done_color="#10b981" if item["done"] else "#64748b"
        checklist_html.append(f'<div style="font-size:0.85rem;color:#cbd5e1;margin-bottom:4px;"><span style="color:{done_color};font-weight:bold;margin-right:8px;">{done_icon}</span> {esc(item["item"].replace("_"," "))}</div>')

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>AegisIR Forensic Report — {esc(c["id"])}</title>
<style>
    body {{ background:#0a0e17; color:#cbd5e1; font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif; margin:0; padding:24px 16px; line-height:1.5; }}
    .container {{ max-width:1050px; margin:0 auto; }}
    .header {{ background:#111827; border:1px solid #1f2937; border-radius:10px; padding:24px; margin-bottom:20px; }}
    .title-row {{ display:flex; justify-content:space-between; align-items:flex-start; flex-wrap:wrap; gap:12px; margin-bottom:16px; }}
    .grid-4 {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(200px,1fr)); gap:12px; margin-bottom:20px; }}
    .grid-2 {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(320px,1fr)); gap:16px; margin-bottom:20px; }}
    .card {{ background:#111827; border:1px solid #1f2937; border-radius:8px; padding:16px; }}
    .kpi {{ text-align:center; padding:16px; }}
    .kpi-num {{ font-size:1.8rem; font-weight:700; color:#f8fafc; margin-bottom:4px; }}
    .kpi-label {{ font-size:0.8rem; color:#94a3b8; text-transform:uppercase; letter-spacing:1px; }}
    .badge {{ display:inline-block; padding:2px 8px; border-radius:4px; font-size:0.75rem; font-weight:600; text-transform:uppercase; }}
    .triad-box {{ background:#141d2e; border:1px solid #1f2937; border-radius:6px; padding:12px; margin-bottom:10px; }}
    .finding-card {{ border-left:4px solid #f59e0b; margin-bottom:12px; }}
    table {{ width:100%; border-collapse:collapse; margin-top:8px; font-size:0.85rem; }}
    th, td {{ padding:10px; text-align:left; border-bottom:1px solid #1f2937; }}
    th {{ color:#94a3b8; font-weight:600; text-transform:uppercase; font-size:0.75rem; letter-spacing:0.5px; }}
    h2 {{ font-size:1.25rem; color:#f8fafc; margin-top:0; border-bottom:1px solid #1f2937; padding-bottom:8px; }}
    .footer {{ font-size:0.8rem; color:#64748b; margin-top:30px; padding-top:16px; border-top:1px solid #1f2937; }}
</style>
</head>
<body>
<div class="container">
    <div class="header">
        <div class="title-row">
            <div>
                <div style="color:#38bdf8;font-weight:700;letter-spacing:1px;font-size:0.85rem;margin-bottom:4px;">AEGISIR FORENSIC INCIDENT REPORT</div>
                <h1 style="margin:0;font-size:1.6rem;color:#f8fafc;">{esc(c["title"])}</h1>
            </div>
            <div>
                <span class="badge" style="background:{sev_color}22;border:1px solid {sev_color};color:{sev_color};font-size:0.9rem;padding:4px 10px;">{esc(c["severity"].upper())} SEVERITY</span>
                <span class="badge" style="background:#10b98122;border:1px solid #10b981;color:#10b981;font-size:0.9rem;padding:4px 10px;margin-left:6px;">{esc(c["status"].upper())}</span>
            </div>
        </div>
        <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:8px;font-size:0.85rem;color:#94a3b8;border-top:1px solid #1f2937;padding-top:12px;">
            <div><strong>Case ID:</strong> <span style="color:#f8fafc;">{esc(c["id"])}</span></div>
            <div><strong>Target Asset:</strong> <span style="color:#f8fafc;">{esc(c["asset"])}</span></div>
            <div><strong>Analyst:</strong> <span style="color:#f8fafc;">{esc(c["analyst"])}</span></div>
            <div><strong>Workflow Phase:</strong> <span style="color:#f8fafc;">{esc(c["phase"])}</span></div>
            <div><strong>Generated:</strong> <span style="color:#f8fafc;">{esc(d["generated_at"])}</span></div>
        </div>
    </div>

    <div class="grid-4">
        <div class="card kpi">
            <div class="kpi-num">{len(d["findings"])}</div>
            <div class="kpi-label">Suspicious Findings</div>
        </div>
        <div class="card kpi">
            <div class="kpi-num">{len(d["coverage"])}</div>
            <div class="kpi-label">Modules Collected</div>
        </div>
        <div class="card kpi">
            <div class="kpi-num">{len(d["actions"])}</div>
            <div class="kpi-label">Mitigation Actions</div>
        </div>
        <div class="card kpi">
            <div class="kpi-num" style="color:#10b981;">VALID</div>
            <div class="kpi-label">Audit Hash Chain</div>
        </div>
    </div>

    <div class="grid-2">
        <div class="card">
            <h2>Three Critical IR Questions</h2>
            {"".join(triad_html)}
        </div>
        <div class="card">
            <h2>Workflow Progress</h2>
            {"".join(checklist_html)}
        </div>
    </div>

    <div class="card" style="margin-bottom:20px;">
        <h2>Suspicious Behavior & Findings ({len(d["findings"])})</h2>
        {"".join(findings_html)}
    </div>

    <div class="card" style="margin-bottom:20px;">
        <h2>Collection Coverage & Evidence Integrity</h2>
        <table>
            <thead>
                <tr><th>Module</th><th>Status</th><th>Observations</th><th>Evidence SHA-256 Digest</th></tr>
            </thead>
            <tbody>
                {"".join(scans_html)}
            </tbody>
        </table>
    </div>

    <div class="card" style="margin-bottom:20px;">
        <h2>Case Activity Timeline</h2>
        {"".join(timeline_html)}
    </div>

    <div class="footer">
        <strong>Forensic & Evidentiary Limitations:</strong>
        <ul style="margin:6px 0 0 0;padding-left:18px;">
            <li>Volatile Linux state can change during collection; external memory/disk acquisition required for evidentiary custody.</li>
            <li>Local SHA-256 and chained audit hashes protect evidence integrity against accidental alteration.</li>
            <li>Findings represent heuristic indicators and response recommendations, not proof of compromise without analyst validation.</li>
        </ul>
    </div>
</div>
</body>
</html>"""

def report(conn,cid,target,format_type=""):
    fmt=(format_type or "").lower().strip()
    if not fmt and target:
        ext=Path(target).suffix.lower()
        if ext==".json":fmt="json"
        elif ext in (".html",".htm"):fmt="html"
        elif ext in (".txt",".text"):fmt="text"
        else:fmt="md"
    if not fmt:fmt="md"

    if fmt=="json":
        data=report_data(conn,cid)
        s=json.dumps(data,indent=2,ensure_ascii=False)
    elif fmt=="html":
        s=report_html(conn,cid)
    else:
        s=report_text(conn,cid)

    if not target:return {"report":s,"format":fmt}
    path=Path(target).expanduser().resolve()
    path.parent.mkdir(parents=True,exist_ok=True)
    if path.exists():raise ValueError("report path exists; refusing overwrite")
    with path.open("x",encoding="utf-8") as f:os.chmod(path,0o600);f.write(s)
    h=hbytes(s.encode("utf-8"))
    audit(conn,cid,"report_exported",json.dumps({"path":str(path),"format":fmt,"sha256":h}))
    conn.commit()
    return {"path":str(path),"format":fmt,"sha256":h,"bytes":len(s.encode("utf-8"))}

def verify(conn,cid):
    check_case(conn,cid)
    chain=[];prev="0"*64
    for x in conn.execute("SELECT * FROM audits WHERE case_id=? ORDER BY id",(cid,)):
        payload={"case_id":cid,"created_at":x["created_at"],"kind":x["kind"],"detail":x["detail"],"previous_hash":x["previous_hash"]}
        valid=(x["previous_hash"]==prev and hbytes(canonical(payload))==x["hash"]);chain.append(valid);prev=x["hash"]
    evidence=[]
    for x in conn.execute("SELECT * FROM scans WHERE case_id=?",(cid,)):
        p=Path(x["evidence_path"])
        valid=p.is_file() and hbytes(p.read_bytes())==x["evidence_sha256"]
        evidence.append({"scan":x["id"],"module":x["module"],"valid":valid})
    return {"audit_entries":len(chain),"audit_chain_valid":all(chain),"evidence":evidence,"integrity_ok":all(chain) and all(x["valid"] for x in evidence),"limitation":"Local integrity checks can be forged by an attacker with write access to the case database and evidence."}

def close(conn,cid,reason):
    c=check_case(conn,cid)
    if c["status"]!="open":raise ValueError("case already closed")
    if len(reason.strip())<15:raise ValueError("closing rationale needs 15+ characters")
    if not conn.execute("SELECT COUNT(*) FROM scans WHERE case_id=?",(cid,)).fetchone()[0]:raise ValueError("no investigation scans available")
    if conn.execute("SELECT COUNT(*) FROM checklist WHERE case_id=? AND done=0",(cid,)).fetchone()[0]:raise ValueError("checklist incomplete; document and complete all items")
    if conn.execute("SELECT COUNT(*) FROM findings WHERE case_id=? AND decision IN ('pending','defer')",(cid,)).fetchone()[0]:raise ValueError("unresolved findings must be explicitly assessed")
    if not verify(conn,cid)["integrity_ok"]:raise ValueError("integrity check failed")
    conn.execute("UPDATE cases SET status='closed',phase='lessons',closed_reason=?,updated_at=? WHERE id=?",(reason[:1000],utc(),cid))
    audit(conn,cid,"case_closed",reason[:1000]);conn.commit()
    return {"case_id":cid,"status":"closed","note":"Closure records analyst decision; not an independent guarantee of eradication."}

def demo_modules():
    now=utc()
    return [
      {"module":"users","captured_at":now,"status":"ok","warnings":[],"items":[{"username":"root","uid":0,"gid":0,"home":"/root","shell":"/bin/bash","supplementary_groups":[]},{"username":"www-data","uid":33,"gid":33,"home":"/var/www","shell":"/usr/sbin/nologin","supplementary_groups":["sudo"]}]},
      {"module":"processes","captured_at":now,"status":"ok","warnings":[],"items":[{"pid":4111,"ppid":100,"uid":1000,"name":"unknown","exe":"/tmp/update-service","cmdline":"/tmp/update-service","start_ticks":"115500"}]},
      {"module":"cron","captured_at":now,"status":"ok","warnings":[],"items":[{"source":"/etc/cron.d/updates","entry":"*/5 * * * * root /tmp/update-service"}]},
      {"module":"ssh","captured_at":now,"status":"ok","warnings":[],"items":[{"path":"/root/.ssh/authorized_keys","fingerprint":"SHA256:SYNTHETIC-NOT-A-REAL-KEY","mode":"-rw-------"}]},
      {"module":"network","captured_at":now,"status":"ok","warnings":[],"items":[{"protocol":"tcp","local":"0.0.0.0:4444","remote":"0.0.0.0:0","state":"0A","socket_inode":"123456"}]},
      {"module":"readiness","captured_at":now,"status":"partial","warnings":["Simulated NTP verification gap"],"items":[]},
    ]

def handle(req):
    op=req.get("op")
    if op=="doctor":return {"python":sys.version.split()[0],"database_path":str(home()/"cases.sqlite3"),"engine":"stdlib", "protocol":SCHEMA_VERSION,"supported_modules":list(MODULES)}
    conn=db()
    try:
        cid=req.get("case_id","")
        if op=="new":return create(conn,req)
        if op=="demo":
            r=create(conn,{"title":"DEMO: Simulated Linux endpoint compromise","asset":"lab-linux-example","analyst":"demo-analyst","severity":"high"},True)
            v=ingest(conn,r["case_id"],{"modules":demo_modules()});return {**r,**v}
        if op=="cases":return [dict(x) for x in conn.execute("SELECT id,title,asset,severity,phase,status,synthetic FROM cases ORDER BY created_at DESC LIMIT 100")]
        if op=="show":
            c=check_case(conn,cid)
            return {"case":c,"summary":{"scans":conn.execute("SELECT COUNT(*) FROM scans WHERE case_id=?",(cid,)).fetchone()[0],"findings":conn.execute("SELECT COUNT(*) FROM findings WHERE case_id=?",(cid,)).fetchone()[0]},"three_questions":triad(conn,cid)}
        if op=="scan":return ingest(conn,cid,req)
        if op=="findings":check_case(conn,cid);return [dict(x) for x in conn.execute("SELECT id,scan_id,module,rule,severity,title,confidence,decision,action_type,action_status FROM findings WHERE case_id=? ORDER BY CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END,created_at DESC",(cid,))]
        if op=="inspect":return check_finding(conn,cid,req["finding_id"])
        if op=="decide":return decisions(conn,cid,req["finding_id"],req["choice"],req.get("reason",""))
        if op=="plan":return action_plan(conn,cid,req["finding_id"])
        if op=="prepare_action":return prepare_action(conn,cid,req["finding_id"])
        if op=="action_result":return action_result(conn,cid,req["finding_id"],req)
        if op=="note":return add_note(conn,cid,req.get("text",""))
        if op=="timeline":return timeline(conn,cid)
        if op=="checklist":return workflow(conn,cid)
        if op=="check":return checklist_set(conn,cid,req["phase"],req["item"],req.get("note",""))
        if op=="phase":return phase_set(conn,cid,req["phase"],req.get("note",""))
        if op=="report":return report(conn,cid,req.get("output",""),req.get("format",""))
        if op=="verify":return verify(conn,cid)
        if op=="close":return close(conn,cid,req.get("reason",""))
        raise ValueError("unknown operation")
    finally:conn.close()

def main():
    os.umask(0o077)
    try:
        req=json.load(sys.stdin)
        if not isinstance(req,dict):raise ValueError("JSON request must be object")
        data=handle(req)
        print(json.dumps({"ok":True,"message":"ok","data":data},ensure_ascii=True))
    except (ValueError,sqlite3.Error,OSError,KeyError,TypeError) as e:
        print(json.dumps({"ok":False,"message":str(e),"data":None}))

if __name__=="__main__":main()
