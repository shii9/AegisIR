package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/shii9/AegisIR/internal/actions"
	"github.com/shii9/AegisIR/internal/bridge"
	"github.com/shii9/AegisIR/internal/collector"
)

const version = "0.2.0"

const banner = `
  ╔═══════════════════════════════════════════════════════════╗
  ║                                                           ║
  ║     █████╗ ███████╗ ██████╗ ██╗███████╗██╗██████╗         ║
  ║    ██╔══██╗██╔════╝██╔════╝ ██║██╔════╝██║██╔══██╗        ║
  ║    ███████║█████╗  ██║  ███╗██║███████╗██║██████╔╝        ║
  ║    ██╔══██║██╔══╝  ██║   ██║██║╚════██║██║██╔══██╗        ║
  ║    ██║  ██║███████╗╚██████╔╝██║███████║██║██║  ██║        ║
  ║    ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝╚══════╝╚═╝╚═╝  ╚═╝        ║
  ║                                                           ║
  ║        Linux Incident Response & Forensic Tool            ║
  ║                     v` + version + `                              ║
  ╚═══════════════════════════════════════════════════════════╝`

const colorReset = "\033[0m"
const colorCyan = "\033[36m"
const colorGreen = "\033[32m"
const colorYellow = "\033[33m"
const colorRed = "\033[31m"
const colorBold = "\033[1m"
const colorDim = "\033[2m"
const colorMagenta = "\033[35m"
const colorWhite = "\033[97m"

// moduleMap maps short and long flags to collector module names
var moduleMap = map[string]string{
	"u": "users", "user": "users", "users": "users",
	"p": "processes", "process": "processes", "processes": "processes",
	"f": "files", "file": "files", "files": "files",
	"m": "mounts", "mount": "mounts", "mounts": "mounts",
	"n": "network", "net": "network", "network": "network",
	"s": "service", "services": "services",
	"c": "cron", "crontab": "cron",
	"k": "ssh", "ssh": "ssh",
	"b": "bash", "profiles": "profiles",
	"l": "log", "logs": "logs",
	"fw": "firewall", "firewall": "firewall",
	"r": "readiness", "readiness": "readiness",
}

// moduleInfo provides user-friendly descriptions for each module
var moduleInfo = map[string][2]string{
	"users":     {"Users & Groups", "Accounts, UID 0, sudo/wheel membership, service accounts"},
	"processes": {"Processes", "Running PIDs, executables, command lines, parent chains"},
	"files":     {"Files & System", "Executables/scripts in /tmp, /var/tmp, /dev/shm"},
	"mounts":    {"Mounts", "Mount points, NFS/CIFS shares, filesystem types"},
	"network":   {"Network", "Listening ports, active connections, socket states"},
	"services":  {"Services", "Systemd units, timers, ExecStart paths"},
	"cron":      {"Crontab", "Scheduled tasks, cron.d, user crontabs"},
	"ssh":       {"SSH Authorized Keys", "Key fingerprints, root keys, config review"},
	"profiles":  {"Bash Profiles", "Shell init persistence, .bashrc, .profile"},
	"logs":      {"Log Files", "Auth logs, journal entries, failed logins"},
	"firewall":  {"Firewall", "iptables/nftables policy rules"},
	"readiness": {"Readiness", "NTP, logging, permissions, collector health"},
}

func printHelp() {
	fmt.Println(colorCyan + banner + colorReset)
	fmt.Println()
	fmt.Println(colorBold + "  USAGE" + colorReset)
	fmt.Println(colorDim + "  ─────────────────────────────────────────────────────────" + colorReset)
	fmt.Println("  aegisir [options] [-o output.txt]")
	fmt.Println()

	fmt.Println(colorBold + "  GENERAL" + colorReset)
	fmt.Println(colorDim + "  ─────────────────────────────────────────────────────────" + colorReset)
	fmt.Printf("  %s-h%s, %s-help%s              Show this help message\n", colorGreen, colorReset, colorGreen, colorReset)
	fmt.Printf("  %s-v%s, %s-version%s           Show version information\n", colorGreen, colorReset, colorGreen, colorReset)
	fmt.Printf("  %s-ui%s                     Interactive terminal menu\n", colorGreen, colorReset)
	fmt.Printf("  %s-doctor%s                 Check system & collector readiness\n", colorGreen, colorReset)
	fmt.Printf("  %s-demo%s                   Run a safe synthetic incident demo\n", colorGreen, colorReset)
	fmt.Printf("  %s-modules%s                List all 12 collection modules\n", colorGreen, colorReset)
	fmt.Println()

	fmt.Println(colorBold + "  SCAN MODULES" + colorReset)
	fmt.Println(colorDim + "  ─────────────────────────────────────────────────────────" + colorReset)
	order := []struct {
		short, long, mod string
	}{
		{"p", "process", "processes"},
		{"f", "file", "files"},
		{"m", "mount", "mounts"},
		{"n", "network", "network"},
		{"u", "user", "users"},
		{"s", "service", "services"},
		{"c", "cron", "cron"},
		{"k", "ssh", "ssh"},
		{"b", "bash", "profiles"},
		{"l", "log", "logs"},
		{"fw", "firewall", "firewall"},
		{"r", "readiness", "readiness"},
	}
	for _, o := range order {
		info := moduleInfo[o.mod]
		fmt.Printf("  %s-%-3s%s  %s-%-12s%s %s\n", colorGreen, o.short, colorReset, colorGreen, o.long, colorReset, info[1])
	}
	fmt.Println()

	fmt.Println(colorBold + "  COMBINED SCAN & OUTPUT" + colorReset)
	fmt.Println(colorDim + "  ─────────────────────────────────────────────────────────" + colorReset)
	fmt.Printf("  %s-all%s                    Scan all 12 modules at once\n", colorGreen, colorReset)
	fmt.Printf("  %s-o%s %sfilename%s             Save forensic report (.md, .json, .html, .txt)\n", colorGreen, colorReset, colorYellow, colorReset)
	fmt.Printf("  %s-fmt%s, %s-format%s %sfmt%s       Report format: md (default), json, html, txt\n", colorGreen, colorReset, colorGreen, colorReset, colorYellow, colorReset)
	fmt.Println()

	fmt.Println(colorBold + "  PAST CASE & INCIDENT MANAGEMENT" + colorReset)
	fmt.Println(colorDim + "  ─────────────────────────────────────────────────────────" + colorReset)
	fmt.Printf("  %s-cases%s                  List all incident cases\n", colorCyan, colorReset)
	fmt.Printf("  %s-show%s %s[case_id]%s         Case dashboard & 3 IR questions\n", colorCyan, colorReset, colorDim, colorReset)
	fmt.Printf("  %s-timeline%s %s[case_id]%s     Chronological case activity & decisions\n", colorCyan, colorReset, colorDim, colorReset)
	fmt.Printf("  %s-verify%s %s[case_id]%s       Cryptographic evidence hash verification\n", colorCyan, colorReset, colorDim, colorReset)
	fmt.Printf("  %s-checklist%s %s[case_id]%s    6-phase NIST incident response checklist\n", colorCyan, colorReset, colorDim, colorReset)
	fmt.Printf("  %s-report%s %s[id] -o file%s    Export report in html, json, or markdown\n", colorCyan, colorReset, colorDim, colorReset)
	fmt.Printf("  %s-guide%s %s[topic]%s          Investigation playbook (e.g. process, cron)\n", colorCyan, colorReset, colorDim, colorReset)
	fmt.Printf("  %s-note%s %s\"note text\"%s       Add an analyst note to latest case\n", colorCyan, colorReset, colorYellow, colorReset)
	fmt.Println()

	fmt.Println(colorBold + "  EXAMPLES" + colorReset)
	fmt.Println(colorDim + "  ─────────────────────────────────────────────────────────" + colorReset)
	fmt.Printf("  %saegisir -process%s                         Scan processes & find suspicious PIDs\n", colorGreen, colorReset)
	fmt.Printf("  %saegisir -all -o full-report.html%s         Scan all modules → save executive HTML report\n", colorGreen, colorReset)
	fmt.Printf("  %saegisir -all -o full-report.json%s         Scan all modules → export SIEM JSON data\n", colorGreen, colorReset)
	fmt.Printf("  %saegisir -file -mount -process -o new.md%s  Multi-target scan → save Markdown report\n", colorGreen, colorReset)
	fmt.Printf("  %saegisir -cases%s                           View list of all past incidents\n", colorGreen, colorReset)
	fmt.Printf("  %saegisir -show%s                            Show 3 IR questions for latest case\n", colorGreen, colorReset)
	fmt.Printf("  %saegisir -verify%s                          Verify evidence integrity & hashes\n", colorGreen, colorReset)
	fmt.Printf("  %saegisir -report -o incident.html%s         Export HTML report from latest case\n", colorGreen, colorReset)
	fmt.Printf("  %saegisir -guide process%s                   Investigation guide for processes\n", colorGreen, colorReset)
	fmt.Println()
}

func printVersion() {
	fmt.Printf("%s%sAegisIR%s %s | Go %s | %s/%s\n", colorBold, colorCyan, colorReset, version, runtime.Version(), runtime.GOOS, runtime.GOARCH)
}

func call(req map[string]any) (json.RawMessage, error) {
	resp, err := bridge.Call(req)
	return resp.Data, err
}

func printData(v json.RawMessage) {
	var result any
	if json.Unmarshal(v, &result) == nil {
		b, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(b))
	} else {
		fmt.Println(string(v))
	}
}

func request(op, cid string) map[string]any { return map[string]any{"op": op, "case_id": cid} }

func askYesNo(reader *bufio.Reader, prompt string) bool {
	for {
		fmt.Printf("\n  %s%s%s [Y/N]: ", colorBold, prompt, colorReset)
		s, _ := reader.ReadString('\n')
		s = strings.TrimSpace(strings.ToLower(s))
		if s == "y" || s == "yes" {
			return true
		}
		if s == "n" || s == "no" {
			return false
		}
		fmt.Printf("  %sPlease enter Y or N%s\n", colorYellow, colorReset)
	}
}

func askInput(reader *bufio.Reader, prompt string) string {
	fmt.Printf("  %s: ", prompt)
	s, _ := reader.ReadString('\n')
	return strings.TrimSpace(s)
}

func severityColor(sev string) string {
	switch strings.ToLower(sev) {
	case "critical":
		return "\033[91m"
	case "high":
		return colorRed
	case "medium":
		return colorYellow
	case "info", "low":
		return colorCyan
	default:
		return colorReset
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Case Management & Investigation Commands
// ──────────────────────────────────────────────────────────────────────────────

func getLatestCaseID() (string, error) {
	v, err := call(map[string]any{"op": "cases"})
	if err != nil {
		return "", err
	}
	var cs []struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(v, &cs); err != nil || len(cs) == 0 {
		return "", errors.New("no incident cases found; run a scan or aegisir -demo to create one")
	}
	return cs[0].ID, nil
}

func showCases() error {
	v, err := call(map[string]any{"op": "cases"})
	if err != nil {
		return err
	}
	var cs []struct {
		ID        string `json:"id"`
		Title     string `json:"title"`
		Asset     string `json:"asset"`
		Severity  string `json:"severity"`
		Phase     string `json:"phase"`
		Status    string `json:"status"`
		Synthetic int    `json:"synthetic"`
	}
	if err := json.Unmarshal(v, &cs); err != nil {
		return err
	}
	fmt.Println(colorCyan + banner + colorReset)
	fmt.Printf("\n  %s%sINCIDENT CASES (%d)%s\n", colorBold, colorWhite, len(cs), colorReset)
	fmt.Printf("  %s────────────────────────────────────────────────────────────────────────────────────────%s\n", colorDim, colorReset)
	fmt.Printf("  %-15s %-10s %-14s %-10s %-15s %s\n", "CASE ID", "SEVERITY", "PHASE", "STATUS", "ASSET", "TITLE")
	fmt.Printf("  %s────────────────────────────────────────────────────────────────────────────────────────%s\n", colorDim, colorReset)
	if len(cs) == 0 {
		fmt.Println("  No incident cases yet. Run aegisir -p or aegisir -demo to create one.")
	}
	for _, c := range cs {
		sc := severityColor(c.Severity)
		statusColor := colorGreen
		if c.Status == "closed" {
			statusColor = colorDim
		}
		syn := ""
		if c.Synthetic == 1 {
			syn = " [DEMO]"
		}
		fmt.Printf("  %-15s %s%-10s%s %-14s %s%-10s%s %-15s %s%s\n",
			c.ID, sc, strings.ToUpper(c.Severity), colorReset, c.Phase, statusColor, c.Status, colorReset, c.Asset, c.Title, syn)
	}
	fmt.Println()
	return nil
}

func showCaseDashboard(caseID string) error {
	if caseID == "" {
		latest, err := getLatestCaseID()
		if err != nil {
			return err
		}
		caseID = latest
	}
	v, err := call(request("show", caseID))
	if err != nil {
		return err
	}
	var d struct {
		Case struct {
			ID        string `json:"id"`
			Title     string `json:"title"`
			Asset     string `json:"asset"`
			Analyst   string `json:"analyst"`
			Severity  string `json:"severity"`
			Phase     string `json:"phase"`
			Status    string `json:"status"`
			Synthetic int    `json:"synthetic"`
			CreatedAt string `json:"created_at"`
		} `json:"case"`
		Summary struct {
			Scans    int `json:"scans"`
			Findings int `json:"findings"`
		} `json:"summary"`
		ThreeQuestions map[string]struct {
			Status   string   `json:"status"`
			Evidence []string `json:"evidence"`
		} `json:"three_questions"`
	}
	if err := json.Unmarshal(v, &d); err != nil {
		return err
	}
	fmt.Println(colorCyan + banner + colorReset)
	fmt.Printf("\n  %s%sCASE DASHBOARD: %s%s\n", colorBold, colorWhite, d.Case.ID, colorReset)
	fmt.Printf("  %s─────────────────────────────────────────────────────────%s\n", colorDim, colorReset)
	fmt.Printf("  Title       : %s\n", d.Case.Title)
	fmt.Printf("  Asset       : %s\n", d.Case.Asset)
	fmt.Printf("  Analyst     : %s\n", d.Case.Analyst)
	fmt.Printf("  Severity    : %s%s%s\n", severityColor(d.Case.Severity), strings.ToUpper(d.Case.Severity), colorReset)
	fmt.Printf("  Phase       : %s\n", d.Case.Phase)
	fmt.Printf("  Status      : %s\n", d.Case.Status)
	fmt.Printf("  Scans       : %d modules collected\n", d.Summary.Scans)
	fmt.Printf("  Findings    : %d suspicious indicators\n", d.Summary.Findings)
	fmt.Println()
	fmt.Printf("  %s%sTHREE CRITICAL IR QUESTIONS:%s\n", colorBold, colorYellow, colorReset)
	for _, k := range []string{"active_malware", "suspicious_communications", "persistence"} {
		q := d.ThreeQuestions[k]
		qTitle := strings.ReplaceAll(k, "_", " ")
		qTitle = strings.ToUpper(qTitle[:1]) + qTitle[1:]
		statusColor := colorGreen
		if q.Status == "review_indicators" {
			statusColor = colorRed
		}
		fmt.Printf("    • %-28s : %s%s%s\n", qTitle, statusColor, q.Status, colorReset)
		for _, ev := range q.Evidence {
			fmt.Printf("      - %s\n", ev)
		}
	}
	fmt.Println()
	return nil
}

func showTimeline(caseID string) error {
	if caseID == "" {
		latest, err := getLatestCaseID()
		if err != nil {
			return err
		}
		caseID = latest
	}
	v, err := call(request("timeline", caseID))
	if err != nil {
		return err
	}
	var audits []struct {
		ID        int    `json:"id"`
		CreatedAt string `json:"created_at"`
		Kind      string `json:"kind"`
		Detail    string `json:"detail"`
		Hash      string `json:"hash"`
	}
	if err := json.Unmarshal(v, &audits); err != nil {
		return err
	}
	fmt.Println(colorCyan + banner + colorReset)
	fmt.Printf("\n  %s%sCASE TIMELINE: %s (%d events)%s\n", colorBold, colorWhite, caseID, len(audits), colorReset)
	fmt.Printf("  %s──────────────────────────────────────────────────────────────────────────%s\n", colorDim, colorReset)
	for _, a := range audits {
		fmt.Printf("  %s%s%s  [%-20s] %s\n", colorDim, a.CreatedAt, colorReset, a.Kind, a.Detail)
	}
	fmt.Println()
	return nil
}

func showVerify(caseID string) error {
	if caseID == "" {
		latest, err := getLatestCaseID()
		if err != nil {
			return err
		}
		caseID = latest
	}
	v, err := call(request("verify", caseID))
	if err != nil {
		return err
	}
	var vr struct {
		AuditEntries    int  `json:"audit_entries"`
		AuditChainValid bool `json:"audit_chain_valid"`
		Evidence        []struct {
			Scan   string `json:"scan"`
			Module string `json:"module"`
			Valid  bool   `json:"valid"`
		} `json:"evidence"`
		IntegrityOK bool   `json:"integrity_ok"`
		Limitation  string `json:"limitation"`
	}
	if err := json.Unmarshal(v, &vr); err != nil {
		return err
	}
	fmt.Println(colorCyan + banner + colorReset)
	fmt.Printf("\n  %s%sCRYPTOGRAPHIC INTEGRITY VERIFICATION: %s%s\n", colorBold, colorWhite, caseID, colorReset)
	fmt.Printf("  %s─────────────────────────────────────────────────────────%s\n", colorDim, colorReset)
	if vr.AuditChainValid {
		fmt.Printf("  Audit Hash Chain     : %s✓ VALID%s (%d chained entries)\n", colorGreen, colorReset, vr.AuditEntries)
	} else {
		fmt.Printf("  Audit Hash Chain     : %s✗ BROKEN / TAMPERED%s\n", colorRed, colorReset)
	}
	fmt.Println("  Evidence File Hashes :")
	for _, ev := range vr.Evidence {
		if ev.Valid {
			fmt.Printf("    • %-14s : %s✓ SHA-256 match%s (scan: %s)\n", ev.Module, colorGreen, colorReset, ev.Scan)
		} else {
			fmt.Printf("    • %-14s : %s✗ Hash mismatch (tampered)%s\n", ev.Module, colorRed, colorReset)
		}
	}
	fmt.Println()
	if vr.IntegrityOK {
		fmt.Printf("  %s✓ OVERALL STATUS: ALL EVIDENCE & AUDIT RECORDS INTACT%s\n", colorGreen, colorReset)
	} else {
		fmt.Printf("  %s✗ OVERALL STATUS: INTEGRITY VIOLATION DETECTED%s\n", colorRed, colorReset)
	}
	fmt.Printf("  %sNote: %s%s\n\n", colorDim, vr.Limitation, colorReset)
	return nil
}

func showChecklist(caseID string) error {
	if caseID == "" {
		latest, err := getLatestCaseID()
		if err != nil {
			return err
		}
		caseID = latest
	}
	v, err := call(request("checklist", caseID))
	if err != nil {
		return err
	}
	var ck struct {
		Checklist []struct {
			Phase string `json:"phase"`
			Item  string `json:"item"`
			Done  int    `json:"done"`
			Note  string `json:"note"`
		} `json:"checklist"`
	}
	if err := json.Unmarshal(v, &ck); err != nil {
		return err
	}
	fmt.Println(colorCyan + banner + colorReset)
	fmt.Printf("\n  %s%sWORKFLOW CHECKLIST (NIST CSF / 800-61 Rev 3): %s%s\n", colorBold, colorWhite, caseID, colorReset)
	fmt.Printf("  %s─────────────────────────────────────────────────────────%s\n", colorDim, colorReset)
	currentPhase := ""
	for _, item := range ck.Checklist {
		if item.Phase != currentPhase {
			currentPhase = item.Phase
			fmt.Printf("\n  %s%s%s\n", colorBold, strings.ToUpper(currentPhase), colorReset)
		}
		mark := " "
		markColor := colorDim
		if item.Done != 0 {
			mark = "✓"
			markColor = colorGreen
		}
		note := ""
		if item.Note != "" {
			note = fmt.Sprintf(" (%s%s%s)", colorDim, item.Note, colorReset)
		}
		fmt.Printf("   [%s%s%s] %-30s%s\n", markColor, mark, colorReset, strings.ReplaceAll(item.Item, "_", " "), note)
	}
	fmt.Println()
	return nil
}

func addCaseNote(caseID, note string) error {
	if caseID == "" {
		latest, err := getLatestCaseID()
		if err != nil {
			return err
		}
		caseID = latest
	}
	r := request("note", caseID)
	r["text"] = note
	v, err := call(r)
	if err != nil {
		return err
	}
	_ = v
	fmt.Printf("\n  %s✓ Note added to case %s%s: %s\n\n", colorGreen, caseID, colorReset, note)
	return nil
}

func showModules() {
	fmt.Println(colorCyan + banner + colorReset)
	fmt.Printf("\n  %s%sSUPPORTED LINUX COLLECTION MODULES (12)%s\n", colorBold, colorWhite, colorReset)
	fmt.Printf("  %s──────────────────────────────────────────────────────────────────────────%s\n", colorDim, colorReset)
	order := []string{"processes", "files", "mounts", "network", "firewall", "users", "services", "cron", "ssh", "profiles", "logs", "readiness"}
	for _, k := range order {
		info := moduleInfo[k]
		fmt.Printf("  %s%-18s%s : %s\n", colorBold, info[0], colorReset, info[1])
	}
	fmt.Printf("\n  %sUsage Examples:%s\n", colorBold, colorReset)
	fmt.Println("    aegisir -p                         Scan processes")
	fmt.Println()
}

func exportReport(caseID, outputFile, format string) error {
	if caseID == "" {
		latest, err := getLatestCaseID()
		if err != nil {
			return err
		}
		caseID = latest
	}
	reportReq := request("report", caseID)
	if format != "" {
		reportReq["format"] = format
	}
	if outputFile != "" {
		reportReq["output"] = outputFile
	}
	reportData, err := call(reportReq)
	if err != nil {
		return fmt.Errorf("report export failed: %w", err)
	}
	if outputFile != "" {
		var rpt struct {
			Path   string `json:"path"`
			Format string `json:"format"`
			SHA256 string `json:"sha256"`
			Bytes  int    `json:"bytes"`
		}
		if json.Unmarshal(reportData, &rpt) == nil && rpt.Path != "" {
			fmt.Println(colorCyan + banner + colorReset)
			fmt.Printf("\n  %s✓ Report exported [%s]: %s%s\n", colorGreen, strings.ToUpper(rpt.Format), rpt.Path, colorReset)
			fmt.Printf("  %s  Case ID: %s | SHA-256: %s%s\n\n", colorDim, caseID, rpt.SHA256, colorReset)
		}
	} else {
		var rpt struct {
			Report string `json:"report"`
		}
		if json.Unmarshal(reportData, &rpt) == nil {
			fmt.Println()
			fmt.Println(rpt.Report)
		}
	}
	return nil
}

// ──────────────────────────────────────────────────────────────────────────────
// Finding Display & Mitigation Flow
// ──────────────────────────────────────────────────────────────────────────────

type findingSummary struct {
	ID             string `json:"id"`
	Module         string `json:"module"`
	Rule           string `json:"rule"`
	Severity       string `json:"severity"`
	Title          string `json:"title"`
	Confidence     string `json:"confidence"`
	Decision       string `json:"decision"`
	ActionType     string `json:"action_type"`
	ActionStatus   string `json:"action_status"`
	Detail         string `json:"detail"`
	Recommendation string `json:"recommendation"`
	Mitre          string `json:"mitre"`
}

func displayFindings(findings []findingSummary) {
	if len(findings) == 0 {
		fmt.Printf("\n  %s✓ No suspicious indicators found%s\n", colorGreen, colorReset)
		fmt.Printf("  %sNote: Absence of findings does NOT prove the host is clean.%s\n", colorDim, colorReset)
		return
	}

	fmt.Printf("\n  %s%s╔═══════════════════════════════════════════════════════╗%s\n", colorBold, colorYellow, colorReset)
	fmt.Printf("  %s%s║  ⚠  SUSPICIOUS FINDINGS DETECTED: %-3d                 ║%s\n", colorBold, colorYellow, len(findings), colorReset)
	fmt.Printf("  %s%s╚═══════════════════════════════════════════════════════╝%s\n", colorBold, colorYellow, colorReset)

	for i, f := range findings {
		sc := severityColor(f.Severity)
		fmt.Printf("\n  %s━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%s\n", colorDim, colorReset)
		fmt.Printf("  %s[%d/%d]%s  %s%s%s\n", colorBold, i+1, len(findings), colorReset, colorBold, f.Title, colorReset)
		fmt.Printf("  %s━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%s\n", colorDim, colorReset)
		fmt.Printf("   Finding ID  : %s%s%s\n", colorCyan, f.ID, colorReset)
		fmt.Printf("   Module      : %s\n", f.Module)
		fmt.Printf("   Severity    : %s%s%s\n", sc, strings.ToUpper(f.Severity), colorReset)
		fmt.Printf("   Confidence  : %s\n", f.Confidence)
		fmt.Printf("   Rule        : %s\n", f.Rule)
		if f.Mitre != "" {
			fmt.Printf("   MITRE ATT&CK: %s\n", f.Mitre)
		}
		fmt.Printf("\n   %sObserved Evidence:%s\n   %s\n", colorBold, colorReset, f.Detail)
		fmt.Printf("\n   %s%sRecommended Cross-Verification & Mitigation:%s\n", colorBold, colorGreen, colorReset)
		for _, recLine := range strings.Split(f.Recommendation, "\n") {
			if strings.TrimSpace(recLine) != "" {
				fmt.Printf("     %s%s%s\n", colorGreen, recLine, colorReset)
			}
		}
	}
}

func runMitigation(reader *bufio.Reader, caseID string, findings []findingSummary) {
	mitigatable := []findingSummary{}
	for _, f := range findings {
		if f.Severity == "high" || f.Severity == "critical" || f.Severity == "medium" {
			mitigatable = append(mitigatable, f)
		}
	}
	if len(mitigatable) == 0 {
		return
	}

	fmt.Printf("\n  %s%s╔═══════════════════════════════════════════════════════╗%s\n", colorBold, colorMagenta, colorReset)
	fmt.Printf("  %s%s║            SUSPICIOUS FINDING MITIGATION              ║%s\n", colorBold, colorMagenta, colorReset)
	fmt.Printf("  %s%s╚═══════════════════════════════════════════════════════╝%s\n", colorBold, colorMagenta, colorReset)

	for _, f := range mitigatable {
		sc := severityColor(f.Severity)
		fmt.Printf("\n  %s──────────────────────────────────────────────────────%s\n", colorDim, colorReset)
		fmt.Printf("  %s%s%s  %s[%s]%s\n", colorBold, f.Title, colorReset, sc, strings.ToUpper(f.Severity), colorReset)
		fmt.Printf("  %sFinding: %s | Rule: %s%s\n", colorDim, f.ID, f.Rule, colorReset)

		if askYesNo(reader, "Do you want to mitigate this suspicious item?") {
			executed := false
			// Check if there is an executable action plan (e.g. terminate_process, quarantine_file)
			if f.ActionType != "" {
				if askYesNo(reader, fmt.Sprintf("Execute live %s now?", f.ActionType)) {
					req := request("prepare_action", caseID)
					req["finding_id"] = f.ID
					v, err := call(req)
					if err == nil {
						var plan struct {
							Action actions.Plan `json:"action"`
						}
						if json.Unmarshal(v, &plan) == nil {
							msg, execErr := actions.Execute(plan.Action, "/tmp/aegisir-quarantine")
							res := request("action_result", caseID)
							res["finding_id"] = f.ID
							res["success"] = execErr == nil
							if execErr == nil {
								res["detail"] = msg
								call(res)
								fmt.Printf("  %s✓ Mitigation executed: %s%s\n", colorGreen, msg, colorReset)
								executed = true
							} else {
								res["detail"] = execErr.Error()
								call(res)
								fmt.Printf("  %s⚠ Action guard: %s%s\n", colorYellow, execErr, colorReset)
							}
						}
					}
				}
			}

			// Record decision
			r := request("decide", caseID)
			r["finding_id"] = f.ID
			r["choice"] = "approve"
			if executed {
				r["reason"] = "mitigation executed by analyst"
			} else {
				r["reason"] = "analyst approved finding for containment plan"
			}
			call(r)
			if !executed {
				fmt.Printf("  %s✓ Finding approved for containment plan — decision recorded%s\n", colorGreen, colorReset)
			}
		} else {
			r := request("decide", caseID)
			r["finding_id"] = f.ID
			r["choice"] = "skip"
			r["reason"] = "analyst reviewed and passed"
			call(r)
			fmt.Printf("  %s→ Skipped — passing back to terminal%s\n", colorYellow, colorReset)
		}
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Scan Execution Flow
// ──────────────────────────────────────────────────────────────────────────────

func runScan(modules []string, outputFile string, format string) error {
	if runtime.GOOS != "linux" {
		return errors.New("AegisIR requires Linux for live collection")
	}
	reader := bufio.NewReader(os.Stdin)

	// Banner
	fmt.Println(colorCyan + banner + colorReset)

	// Step 1: Auto-create case
	fmt.Printf("\n  %s%s[1/5] Initializing Incident Case...%s\n", colorBold, colorCyan, colorReset)
	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "linux-host"
	}
	currentUser := "analyst"
	if u := os.Getenv("USER"); u != "" {
		currentUser = u
	}

	caseData, err := call(map[string]any{
		"op":       "new",
		"title":    "AegisIR Scan - " + time.Now().Format("2006-01-02 15:04"),
		"asset":    hostname,
		"analyst":  currentUser,
		"severity": "medium",
	})
	if err != nil {
		return fmt.Errorf("failed to create case: %w", err)
	}
	var caseInfo struct {
		CaseID string `json:"case_id"`
	}
	if err := json.Unmarshal(caseData, &caseInfo); err != nil {
		return err
	}
	fmt.Printf("  %s✓ Case Initialized: %s%s\n", colorGreen, caseInfo.CaseID, colorReset)

	// Step 2: Collect
	fmt.Printf("\n  %s%s[2/5] Collecting Forensic Evidence...%s\n", colorBold, colorCyan, colorReset)
	fmt.Printf("  %sModules: %s%s\n", colorDim, strings.Join(modules, ", "), colorReset)

	var allResults []any
	for _, mod := range modules {
		fmt.Printf("  %s→ Collecting %-12s", colorDim, mod)
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		results, err := collector.Collect(ctx, mod)
		cancel()
		if err != nil {
			fmt.Printf(" ✗ %s%s\n", err, colorReset)
			continue
		}
		for _, r := range results {
			allResults = append(allResults, r)
		}
		fmt.Printf(" ✓%s\n", colorReset)
	}
	if len(allResults) == 0 {
		return errors.New("no modules collected successfully")
	}

	// Step 3: Analyze
	fmt.Printf("\n  %s%s[3/5] Correlating & Analyzing Suspicious Behavior...%s\n", colorBold, colorCyan, colorReset)
	scanData, err := call(map[string]any{
		"op":      "scan",
		"case_id": caseInfo.CaseID,
		"modules": allResults,
	})
	if err != nil {
		return fmt.Errorf("analysis failed: %w", err)
	}
	var scanResult struct {
		Modules []struct {
			Module   string   `json:"module"`
			Status   string   `json:"status"`
			Items    int      `json:"items"`
			Findings int      `json:"findings"`
			Warnings []string `json:"warnings"`
		} `json:"modules"`
		TotalFindings int `json:"total_findings"`
	}
	if err := json.Unmarshal(scanData, &scanResult); err != nil {
		return err
	}

	// Display scan summary table
	fmt.Printf("\n  %s%-16s %-10s %-8s %-8s%s\n", colorBold, "MODULE", "STATUS", "ITEMS", "FINDINGS", colorReset)
	fmt.Printf("  %s────────────────────────────────────────────────%s\n", colorDim, colorReset)
	for _, m := range scanResult.Modules {
		statusColor := colorGreen
		if m.Status == "partial" {
			statusColor = colorYellow
		}
		findColor := colorGreen
		if m.Findings > 0 {
			findColor = colorRed
		}
		fmt.Printf("  %-16s %s%-10s%s %-8d %s%-8d%s\n", m.Module, statusColor, m.Status, colorReset, m.Items, findColor, m.Findings, colorReset)
		for _, w := range m.Warnings {
			fmt.Printf("  %s  ⚠ %s%s\n", colorYellow, w, colorReset)
		}
	}

	// Step 4: Show findings
	fmt.Printf("\n  %s%s[4/5] Evaluating Suspicious Findings...%s\n", colorBold, colorCyan, colorReset)
	findingsData, err := call(request("findings", caseInfo.CaseID))
	if err != nil {
		return fmt.Errorf("failed to retrieve findings: %w", err)
	}
	var findings []findingSummary
	if err := json.Unmarshal(findingsData, &findings); err != nil {
		return err
	}

	// Populate full inspection details
	for i := range findings {
		detailData, err := call(map[string]any{
			"op":         "inspect",
			"case_id":    caseInfo.CaseID,
			"finding_id": findings[i].ID,
		})
		if err == nil {
			var detail struct {
				Detail         string `json:"detail"`
				Recommendation string `json:"recommendation"`
				Mitre          string `json:"mitre"`
			}
			if json.Unmarshal(detailData, &detail) == nil {
				findings[i].Detail = detail.Detail
				findings[i].Recommendation = detail.Recommendation
				findings[i].Mitre = detail.Mitre
			}
		}
	}

	displayFindings(findings)

	// Interactive mitigation prompt
	if len(findings) > 0 {
		runMitigation(reader, caseInfo.CaseID, findings)
	}

	// Step 5: Generate report
	fmt.Printf("\n  %s%s[5/5] Generating Forensic Incident Report...%s\n", colorBold, colorCyan, colorReset)

	reportReq := request("report", caseInfo.CaseID)
	if format != "" {
		reportReq["format"] = format
	}
	if outputFile != "" {
		reportReq["output"] = outputFile
		reportData, err := call(reportReq)
		if err != nil {
			return fmt.Errorf("report generation failed: %w", err)
		}
		var rpt struct {
			Path   string `json:"path"`
			Format string `json:"format"`
			SHA256 string `json:"sha256"`
			Bytes  int    `json:"bytes"`
		}
		if json.Unmarshal(reportData, &rpt) == nil && rpt.Path != "" {
			fmt.Printf("  %s✓ Report saved [%s]: %s%s\n", colorGreen, strings.ToUpper(rpt.Format), rpt.Path, colorReset)
			fmt.Printf("  %s  SHA-256: %s%s\n", colorDim, rpt.SHA256, colorReset)
		}
	} else {
		reportData, err := call(reportReq)
		if err != nil {
			return fmt.Errorf("report generation failed: %w", err)
		}
		var rpt struct {
			Report string `json:"report"`
		}
		if json.Unmarshal(reportData, &rpt) == nil {
			fmt.Println()
			fmt.Println(rpt.Report)
		}
	}

	// Final summary
	fmt.Printf("\n  %s%s╔═══════════════════════════════════════════════════════╗%s\n", colorBold, colorGreen, colorReset)
	fmt.Printf("  %s%s║                    SCAN COMPLETE                      ║%s\n", colorBold, colorGreen, colorReset)
	fmt.Printf("  %s%s╚═══════════════════════════════════════════════════════╝%s\n", colorBold, colorGreen, colorReset)
	fmt.Printf("  Case ID       : %s%s%s\n", colorCyan, caseInfo.CaseID, colorReset)
	fmt.Printf("  Modules       : %d scanned\n", len(scanResult.Modules))
	fmt.Printf("  Findings      : %d suspicious indicators\n", scanResult.TotalFindings)
	if outputFile != "" {
		fmt.Printf("  Report File   : %s%s%s\n", colorGreen, outputFile, colorReset)
	}
	fmt.Println()
	return nil
}

func runDemo() error {
	fmt.Println(colorCyan + banner + colorReset)
	fmt.Printf("\n  %s%sRunning synthetic demo incident...%s\n\n", colorBold, colorCyan, colorReset)

	demoData, err := call(map[string]any{"op": "demo"})
	if err != nil {
		return err
	}
	var demo struct {
		CaseID  string `json:"case_id"`
		Total   int    `json:"total_findings"`
		Modules []struct {
			Module   string `json:"module"`
			Status   string `json:"status"`
			Items    int    `json:"items"`
			Findings int    `json:"findings"`
		} `json:"modules"`
	}
	if err := json.Unmarshal(demoData, &demo); err != nil {
		return err
	}

	fmt.Printf("  %s✓ Demo case created: %s%s\n\n", colorGreen, demo.CaseID, colorReset)
	fmt.Printf("  %s%-16s %-10s %-8s %-8s%s\n", colorBold, "MODULE", "STATUS", "ITEMS", "FINDINGS", colorReset)
	fmt.Printf("  %s────────────────────────────────────────────────%s\n", colorDim, colorReset)
	for _, m := range demo.Modules {
		fmt.Printf("  %-16s %-10s %-8d %-8d\n", m.Module, m.Status, m.Items, m.Findings)
	}
	fmt.Printf("\n  Total suspicious findings: %s%d%s (synthetic demonstration)\n\n", colorYellow, demo.Total, colorReset)
	return nil
}

func runDoctor() error {
	if runtime.GOOS != "linux" {
		return errors.New("AegisIR requires Linux for live collection")
	}
	p, err := bridge.Locate()
	if err != nil {
		return err
	}
	fmt.Println(colorCyan + banner + colorReset)
	fmt.Printf("\n  %s%sSystem Readiness Check%s\n", colorBold, colorGreen, colorReset)
	fmt.Printf("  %s──────────────────────────────────────────────%s\n", colorDim, colorReset)
	fmt.Printf("  AegisIR  : %s\n", version)
	fmt.Printf("  Go       : %s\n", runtime.Version())
	fmt.Printf("  Engine   : %s\n", p)
	fmt.Printf("  OS/Arch  : %s/%s\n", runtime.GOOS, runtime.GOARCH)

	v, err := call(map[string]any{"op": "doctor"})
	if err != nil {
		return err
	}
	var doc struct {
		Python  string   `json:"python"`
		DB      string   `json:"database_path"`
		Modules []string `json:"supported_modules"`
	}
	if json.Unmarshal(v, &doc) == nil {
		fmt.Printf("  Python   : %s\n", doc.Python)
		fmt.Printf("  Database : %s\n", doc.DB)
		fmt.Printf("  Modules  : %s%d available%s\n", colorGreen, len(doc.Modules), colorReset)
	}
	fmt.Printf("\n  %s✓ System ready for forensic collection%s\n\n", colorGreen, colorReset)
	return nil
}

// ──────────────────────────────────────────────────────────────────────────────
// Interactive Terminal UI
// ──────────────────────────────────────────────────────────────────────────────

func interactiveMenu() {
	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Println(colorCyan + banner + colorReset)
		fmt.Println()
		fmt.Println(colorBold + "  SELECT AN OPTION:" + colorReset)
		fmt.Println(colorDim + "  ─────────────────────────────────────────────────────────" + colorReset)
		fmt.Printf("   %s[1]%s  Scan Processes (-p)          (PIDs, unlinked, hidden binaries)\n", colorGreen, colorReset)
		fmt.Printf("   %s[2]%s  Scan Files (-f)              (Executables in /tmp, /var/tmp)\n", colorGreen, colorReset)
		fmt.Printf("   %s[3]%s  Scan Mounts (-m)             (NFS, CIFS, foreign mounts)\n", colorGreen, colorReset)
		fmt.Printf("   %s[4]%s  Scan Network (-n)            (Open ports, active sockets)\n", colorGreen, colorReset)
		fmt.Printf("   %s[5]%s  Full System Scan (-all)      (All 12 modules swept at once)\n", colorGreen, colorReset)
		fmt.Println(colorDim + "  ─────────────────────────────────────────────────────────" + colorReset)
		fmt.Printf("   %s[6]%s  View Incident Cases (-cases) (Browse past investigation records)\n", colorCyan, colorReset)
		fmt.Printf("   %s[7]%s  Case Dashboard (-show)       (3 IR questions & status overview)\n", colorCyan, colorReset)
		fmt.Printf("   %s[8]%s  Case Timeline (-timeline)    (Chronological event audit log)\n", colorCyan, colorReset)
		fmt.Printf("   %s[9]%s  Verify Case Hashes (-verify) (Evidence SHA-256 integrity check)\n", colorCyan, colorReset)
		fmt.Printf("  %s[10]%s  NIST Checklist (-checklist)  (6-phase incident response items)\n", colorCyan, colorReset)
		fmt.Println(colorDim + "  ─────────────────────────────────────────────────────────" + colorReset)
		fmt.Printf("  %s[11]%s  Run Safe Demo (-demo)        (Simulated endpoint compromise)\n", colorYellow, colorReset)
		fmt.Printf("  %s[12]%s  System Doctor (-doctor)      (Check environment readiness)\n", colorYellow, colorReset)
		fmt.Printf("  %s[13]%s  Show Modules (-modules)      (List all collection modules)\n", colorYellow, colorReset)
		fmt.Printf("  %s[14]%s  Help Reference (-help)       (View all flags and syntax)\n", colorYellow, colorReset)
		fmt.Printf("   %s[0]%s  Exit\n", colorRed, colorReset)
		fmt.Println()

		choice := askInput(reader, "  Select [0-14]")
		switch choice {
		case "1":
			runScan([]string{"processes"}, "", "")
		case "2":
			runScan([]string{"files"}, "", "")
		case "3":
			runScan([]string{"mounts"}, "", "")
		case "4":
			runScan([]string{"network"}, "", "")
		case "5":
			runScan([]string{"readiness", "users", "processes", "files", "mounts", "network", "firewall", "services", "cron", "ssh", "profiles", "logs"}, "", "")
		case "6":
			showCases()
		case "7":
			showCaseDashboard("")
		case "8":
			showTimeline("")
		case "9":
			showVerify("")
		case "10":
			showChecklist("")
		case "11":
			runDemo()
		case "12":
			runDoctor()
		case "13":
			showModules()
		case "14":
			printHelp()
		case "0", "q", "exit":
			fmt.Println("\n  Exiting AegisIR.")
			return
		default:
			fmt.Printf("\n  %sInvalid option: %s%s\n\n", colorYellow, choice, colorReset)
		}
		fmt.Println("\nPress Enter to return to menu...")
		reader.ReadString('\n')
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Advanced subcommands preserved for backward compatibility
// ──────────────────────────────────────────────────────────────────────────────

func advancedUsage() {
	fmt.Println(colorCyan + banner + colorReset)
	fmt.Println()
	fmt.Println(colorBold + "  ADVANCED COMMANDS" + colorReset)
	fmt.Println(colorDim + "  ─────────────────────────────────────────────────────────" + colorReset)
	fmt.Println(`
  aegisir advanced new --title T --asset A --analyst U [--severity high]
  aegisir advanced cases
  aegisir advanced show CASE_ID
  aegisir advanced scan CASE_ID [--module all]
  aegisir advanced findings CASE_ID
  aegisir advanced inspect CASE_ID FINDING_ID
  aegisir advanced decide CASE_ID FINDING_ID --choice approve|skip|defer --reason R
  aegisir advanced plan CASE_ID FINDING_ID
  aegisir advanced checklist CASE_ID
  aegisir advanced timeline CASE_ID
  aegisir advanced note CASE_ID --text NOTE
  aegisir advanced verify CASE_ID
  aegisir advanced report CASE_ID [--output report.md]
  aegisir advanced close CASE_ID --reason R
  aegisir advanced guide [module|workflow]`)
	fmt.Println()
}

func fs(name string) *flag.FlagSet {
	f := flag.NewFlagSet(name, flag.ContinueOnError)
	f.SetOutput(os.Stderr)
	return f
}

func require(a []string, n int) error {
	if len(a) < n {
		return errors.New("missing case or finding ID; see aegisir advanced help")
	}
	return nil
}

func advancedRun(args []string) error {
	if len(args) == 0 {
		advancedUsage()
		return nil
	}
	cmd := args[0]
	a := args[1:]
	switch cmd {
	case "help", "--help", "-h":
		advancedUsage()
		return nil
	case "new":
		f := fs(cmd)
		title := f.String("title", "", "incident title")
		asset := f.String("asset", "", "Linux asset name")
		analyst := f.String("analyst", "", "analyst name")
		severity := f.String("severity", "medium", "low|medium|high|critical")
		if err := f.Parse(a); err != nil {
			return err
		}
		if *title == "" || *asset == "" || *analyst == "" {
			return errors.New("--title, --asset, --analyst required")
		}
		v, err := call(map[string]any{"op": "new", "title": *title, "asset": *asset, "analyst": *analyst, "severity": *severity})
		if err != nil {
			return err
		}
		printData(v)
		return nil
	case "demo", "cases":
		v, err := call(map[string]any{"op": cmd})
		if err != nil {
			return err
		}
		printData(v)
		return nil
	case "show":
		if err := require(a, 1); err != nil {
			return err
		}
		v, err := call(request("show", a[0]))
		if err != nil {
			return err
		}
		printData(v)
		return nil
	case "findings":
		if err := require(a, 1); err != nil {
			return err
		}
		v, err := call(request("findings", a[0]))
		if err != nil {
			return err
		}
		printData(v)
		return nil
	case "inspect":
		if err := require(a, 2); err != nil {
			return err
		}
		r := request("inspect", a[0])
		r["finding_id"] = a[1]
		v, err := call(r)
		if err != nil {
			return err
		}
		printData(v)
		return nil
	case "decide":
		if err := require(a, 2); err != nil {
			return err
		}
		f := fs(cmd)
		choice := f.String("choice", "", "approve|skip|defer")
		reason := f.String("reason", "", "analyst rationale")
		if err := f.Parse(a[2:]); err != nil {
			return err
		}
		r := request("decide", a[0])
		r["finding_id"] = a[1]
		r["choice"] = *choice
		r["reason"] = *reason
		v, err := call(r)
		if err != nil {
			return err
		}
		printData(v)
		return nil
	case "plan":
		if err := require(a, 2); err != nil {
			return err
		}
		r := request("plan", a[0])
		r["finding_id"] = a[1]
		v, err := call(r)
		if err != nil {
			return err
		}
		printData(v)
		return nil
	case "checklist":
		if err := require(a, 1); err != nil {
			return err
		}
		v, err := call(request("checklist", a[0]))
		if err != nil {
			return err
		}
		printData(v)
		return nil
	case "timeline":
		if err := require(a, 1); err != nil {
			return err
		}
		v, err := call(request("timeline", a[0]))
		if err != nil {
			return err
		}
		printData(v)
		return nil
	case "verify":
		if err := require(a, 1); err != nil {
			return err
		}
		v, err := call(request("verify", a[0]))
		if err != nil {
			return err
		}
		printData(v)
		return nil
	case "report":
		if err := require(a, 1); err != nil {
			return err
		}
		f := fs(cmd)
		target := f.String("output", "", "create report at path")
		if err := f.Parse(a[1:]); err != nil {
			return err
		}
		r := request("report", a[0])
		r["output"] = *target
		v, err := call(r)
		if err != nil {
			return err
		}
		if *target == "" {
			var d struct {
				Report string `json:"report"`
			}
			_ = json.Unmarshal(v, &d)
			fmt.Print(d.Report)
		} else {
			printData(v)
		}
		return nil
	case "guide":
		name := "workflow"
		if len(a) > 0 {
			name = a[0]
		}
		return printGuide(name)
	default:
		return fmt.Errorf("unknown advanced command %q; use aegisir advanced help", cmd)
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Main CLI Parser
// ──────────────────────────────────────────────────────────────────────────────

func run(args []string) error {
	// If no arguments, launch interactive terminal interface
	if len(args) == 0 {
		interactiveMenu()
		return nil
	}

	// Handle "advanced" subcommand
	if args[0] == "advanced" {
		return advancedRun(args[1:])
	}

	// First pass: check for standalone commands or flags like "cases", "timeline", "doctor", etc.
	firstClean := strings.TrimLeft(args[0], "-")
	switch firstClean {
	case "h", "help":
		printHelp()
		return nil
	case "v", "version":
		printVersion()
		return nil
	case "ui":
		interactiveMenu()
		return nil
	case "doctor":
		return runDoctor()
	case "demo":
		return runDemo()
	case "modules":
		showModules()
		return nil
	case "cases":
		return showCases()
	case "show":
		target := ""
		if len(args) > 1 {
			target = args[1]
		}
		return showCaseDashboard(target)
	case "timeline":
		target := ""
		if len(args) > 1 {
			target = args[1]
		}
		return showTimeline(target)
	case "verify":
		target := ""
		if len(args) > 1 {
			target = args[1]
		}
		return showVerify(target)
	case "checklist":
		target := ""
		if len(args) > 1 {
			target = args[1]
		}
		return showChecklist(target)
	case "guide":
		topic := "workflow"
		if len(args) > 1 {
			topic = args[1]
		}
		return printGuide(topic)
	case "note":
		if len(args) < 2 {
			return errors.New("note text required: aegisir -note \"your note text\"")
		}
		return addCaseNote("", strings.Join(args[1:], " "))
	case "report":
		targetCase := ""
		targetFile := ""
		targetFormat := ""
		for j := 1; j < len(args); j++ {
			c := strings.TrimLeft(args[j], "-")
			if (c == "o" || c == "output") && j+1 < len(args) {
				j++
				targetFile = args[j]
			} else if strings.HasPrefix(c, "o=") {
				targetFile = c[2:]
			} else if (c == "format" || c == "fmt") && j+1 < len(args) {
				j++
				targetFormat = strings.ToLower(args[j])
			} else if strings.HasPrefix(c, "format=") {
				targetFormat = strings.ToLower(c[7:])
			} else if strings.HasPrefix(c, "fmt=") {
				targetFormat = strings.ToLower(c[4:])
			} else if !strings.HasPrefix(args[j], "-") && targetCase == "" {
				targetCase = args[j]
			}
		}
		return exportReport(targetCase, targetFile, targetFormat)
	}

	// Second pass: parse flag combinations like:
	// aegisir -process
	// aegisir -file -mount -process -o new.txt
	// aegisir -all -o full-report.html
	var selectedModules []string
	var outputFile string
	var format string
	scanAll := false
	seenModules := map[string]bool{}

	for i := 0; i < len(args); i++ {
		arg := args[i]
		cleaned := strings.TrimLeft(arg, "-")
		if cleaned == "" {
			continue
		}

		switch cleaned {
		case "h", "help":
			printHelp()
			return nil
		case "v", "version":
			printVersion()
			return nil
		case "doctor":
			return runDoctor()
		case "demo":
			return runDemo()
		case "ui":
			interactiveMenu()
			return nil
		case "cases":
			return showCases()
		case "modules":
			showModules()
			return nil
		case "all":
			scanAll = true
		case "format", "fmt":
			if i+1 < len(args) {
				i++
				format = strings.ToLower(args[i])
			} else {
				return errors.New("missing format after -fmt / -format (md, json, html, txt)")
			}
		case "o":
			if i+1 < len(args) {
				i++
				outputFile = args[i]
			} else {
				return errors.New("missing filename after -o")
			}
		default:
			if strings.HasPrefix(cleaned, "o=") {
				outputFile = cleaned[2:]
			} else if strings.HasPrefix(cleaned, "format=") {
				format = strings.ToLower(cleaned[7:])
			} else if strings.HasPrefix(cleaned, "fmt=") {
				format = strings.ToLower(cleaned[4:])
			} else if mod, ok := moduleMap[cleaned]; ok {
				if !seenModules[mod] {
					seenModules[mod] = true
					selectedModules = append(selectedModules, mod)
				}
			} else {
				return fmt.Errorf("unknown option '-%s'; use aegisir -help", cleaned)
			}
		}
	}

	if scanAll {
		selectedModules = []string{"readiness", "users", "processes", "files", "mounts", "network", "firewall", "services", "cron", "ssh", "profiles", "logs"}
	}

	if len(selectedModules) > 0 {
		return runScan(selectedModules, outputFile, format)
	}

	printHelp()
	return nil
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "\n  %sAegisIR error:%s %s\n\n", colorRed, colorReset, err)
		os.Exit(1)
	}
}
