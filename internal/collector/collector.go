// Package collector implements bounded, read-only Linux triage collection.
// Every artifact is a point-in-time live observation, not a forensic disk image.
package collector

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

var Modules = []string{"readiness", "users", "processes", "files", "mounts", "network", "firewall", "services", "cron", "ssh", "profiles", "logs"}
var secret = regexp.MustCompile(`(?i)(password|passwd|token|secret|api[_-]?key|authorization)(\s*[=:]\s*|\s+)[^\s]+`)

func Redact(s string) string { return secret.ReplaceAllString(s, "$1=[REDACTED]") }
func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n] + "..."
	}
	return s
}
func read(p string, max int) string {
	f, e := os.Open(p)
	if e != nil {
		return ""
	}
	defer f.Close()
	b, _ := io.ReadAll(io.LimitReader(f, int64(max)))
	return string(b)
}
func lines(p string, maxBytes, maxLines int) []string {
	r := read(p, maxBytes)
	v := strings.Split(r, "\n")
	if len(v) > maxLines {
		v = v[:maxLines]
	}
	return v
}
func execBounded(ctx context.Context, name string, args ...string) (string, error) {
	c, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(c, name, args...)
	b, e := cmd.Output()
	if len(b) > 60000 {
		b = b[:60000]
	}
	return truncate(Redact(string(b)), 60000), e
}
func statOwner(f os.FileInfo) int {
	if s, ok := f.Sys().(*syscall.Stat_t); ok {
		return int(s.Uid)
	}
	return -1
}
func shaFile(p string, max int64) string {
	f, e := os.Open(p)
	if e != nil {
		return ""
	}
	defer f.Close()
	h := sha256.New()
	n, e := io.Copy(h, io.LimitReader(f, max+1))
	if e != nil || n > max {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
}
func record(kv ...any) map[string]any {
	m := map[string]any{}
	for i := 0; i+1 < len(kv); i += 2 {
		m[kv[i].(string)] = kv[i+1]
	}
	return m
}
func capErrors(errs []string, msg string) []string {
	if len(errs) < 10 {
		return append(errs, msg)
	}
	return errs
}

type ModuleResult struct {
	Module     string           `json:"module"`
	Status     string           `json:"status"`
	CapturedAt string           `json:"captured_at"`
	Items      []map[string]any `json:"items"`
	Warnings   []string         `json:"warnings"`
	Truncated  bool             `json:"truncated"`
}

func NewResult(name string) ModuleResult {
	return ModuleResult{Module: name, Status: "ok", CapturedAt: time.Now().UTC().Format(time.RFC3339Nano), Items: []map[string]any{}, Warnings: []string{}}
}
func (r *ModuleResult) warn(s string) { r.Warnings = capErrors(r.Warnings, s); r.Status = "partial" }
func Collect(ctx context.Context, module string) ([]ModuleResult, error) {
	if runtime.GOOS != "linux" {
		return nil, errors.New("Linux required")
	}
	selected := Modules
	if module != "all" {
		found := false
		for _, m := range Modules {
			if m == module {
				found = true
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("unknown module %q", module)
		}
		selected = []string{module}
	}
	results := make([]ModuleResult, len(selected))
	sem := make(chan struct{}, 4)
	var wg sync.WaitGroup
	for i, m := range selected {
		wg.Add(1)
		go func(i int, m string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			c, cancel := context.WithTimeout(ctx, 12*time.Second)
			defer cancel()
			results[i] = collectOne(c, m)
		}(i, m)
	}
	wg.Wait()
	return results, nil
}
func collectOne(ctx context.Context, m string) ModuleResult {
	r := NewResult(m)
	switch m {
	case "readiness":
		readiness(ctx, &r)
	case "users":
		users(&r)
	case "processes":
		processes(&r)
	case "files":
		files(ctx, &r)
	case "mounts":
		mounts(&r)
	case "network":
		network(&r)
	case "firewall":
		firewall(ctx, &r)
	case "services":
		services(ctx, &r)
	case "cron":
		cron(ctx, &r)
	case "ssh":
		ssh(&r)
	case "profiles":
		profiles(&r)
	case "logs":
		logs(ctx, &r)
	}
	return r
}
func readiness(ctx context.Context, r *ModuleResult) {
	host, _ := os.Hostname()
	r.Items = append(r.Items, record("hostname", host, "kernel", truncate(read("/proc/sys/kernel/osrelease", 200), 180), "os_release", truncate(read("/etc/os-release", 500), 480), "effective_uid", os.Geteuid(), "time_utc", time.Now().UTC().Format(time.RFC3339), "timezone", time.Now().Location().String()))
	t, e := execBounded(ctx, "timedatectl", "show", "-p", "NTPSynchronized", "-p", "NTP", "--value")
	if e != nil {
		r.warn("timedatectl unavailable; NTP state unverified")
	} else {
		r.Items = append(r.Items, record("ntp_status", strings.TrimSpace(t)))
	}
	if _, e := os.Stat("/run/systemd/journal"); e != nil {
		r.warn("persistent/current journal visibility not established")
	}
}
func users(r *ModuleResult) {
	groups := map[string][]string{}
	for _, l := range lines("/etc/group", 500000, 4000) {
		f := strings.Split(l, ":")
		if len(f) < 4 {
			continue
		}
		for _, u := range strings.Split(f[3], ",") {
			if u != "" {
				groups[u] = append(groups[u], f[0])
			}
		}
	}
	ls := lines("/etc/passwd", 500000, 4000)
	if len(ls) == 0 {
		r.warn("/etc/passwd not readable")
	}
	for _, l := range ls {
		f := strings.Split(l, ":")
		if len(f) < 7 {
			continue
		}
		uid, _ := strconv.Atoi(f[2])
		gid, _ := strconv.Atoi(f[3])
		r.Items = append(r.Items, record("username", f[0], "uid", uid, "gid", gid, "home", f[5], "shell", f[6], "supplementary_groups", groups[f[0]]))
	}
	if len(ls) >= 4000 {
		r.Truncated = true
	}
	// Snapshot sudo policy directives without shadow/password data. Include files are best-effort.
	sudoPaths := []string{"/etc/sudoers"}
	if entries, e := os.ReadDir("/etc/sudoers.d"); e == nil {
		for _, entry := range entries {
			if entry.Type().IsRegular() && len(sudoPaths) < 40 {
				sudoPaths = append(sudoPaths, filepath.Join("/etc/sudoers.d", entry.Name()))
			}
		}
	}
	for _, p := range sudoPaths {
		content := read(p, 24000)
		if content == "" {
			continue
		}
		for _, line := range strings.Split(content, "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			if len(r.Items) < 4500 {
				r.Items = append(r.Items, record("kind", "sudo_policy", "source", p, "directive", truncate(Redact(line), 300)))
			}
		}
	}
}
func processStat(pid int) (int, string) {
	b := read(fmt.Sprintf("/proc/%d/stat", pid), 10000)
	idx := strings.LastIndex(b, ")")
	if idx < 0 {
		return 0, ""
	}
	v := strings.Fields(b[idx+1:])
	if len(v) < 20 {
		return 0, ""
	}
	ppid, _ := strconv.Atoi(v[1])
	return ppid, v[19]
}
func processes(r *ModuleResult) {
	entries, e := os.ReadDir("/proc")
	if e != nil {
		r.warn(e.Error())
		return
	}
	c := 0
	for _, ent := range entries {
		pid, e := strconv.Atoi(ent.Name())
		if e != nil {
			continue
		}
		if c >= 1800 {
			r.Truncated = true
			break
		}
		c++
		status := read(fmt.Sprintf("/proc/%d/status", pid), 6000)
		if status == "" {
			continue
		}
		uid := -1
		name := ""
		for _, l := range strings.Split(status, "\n") {
			if strings.HasPrefix(l, "Name:") {
				name = strings.TrimSpace(strings.TrimPrefix(l, "Name:"))
			}
			if strings.HasPrefix(l, "Uid:") {
				x := strings.Fields(l)
				if len(x) > 1 {
					uid, _ = strconv.Atoi(x[1])
				}
			}
		}
		b := read(fmt.Sprintf("/proc/%d/cmdline", pid), 1500)
		command := truncate(Redact(strings.Join(strings.Fields(strings.ReplaceAll(b, "\x00", " ")), " ")), 400)
		exe, _ := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
		ppid, ticks := processStat(pid)
		r.Items = append(r.Items, record("pid", pid, "ppid", ppid, "uid", uid, "name", name, "exe", truncate(exe, 350), "cmdline", command, "start_ticks", ticks))
	}
}
func files(ctx context.Context, r *ModuleResult) {
	count := 0
	for _, base := range []string{"/tmp", "/var/tmp"} {
		_ = filepath.WalkDir(base, func(p string, d os.DirEntry, e error) error {
			if ctx.Err() != nil || count >= 650 {
				return filepath.SkipAll
			}
			if e != nil {
				return nil
			}
			if d.IsDir() {
				if p != base && strings.Count(strings.TrimPrefix(p, base), string(os.PathSeparator)) > 3 {
					return filepath.SkipDir
				}
				return nil
			}
			count++
			if !d.Type().IsRegular() {
				return nil
			}
			f, e := d.Info()
			if e != nil {
				return nil
			}
			if f.Size() > 15*1024*1024 {
				return nil
			}
			if f.Mode().Perm()&0111 == 0 && !strings.HasSuffix(p, ".sh") && !strings.HasSuffix(p, ".py") && !strings.HasSuffix(p, ".elf") {
				return nil
			}
			r.Items = append(r.Items, record("path", p, "size", f.Size(), "mode", f.Mode().String(), "uid", statOwner(f), "modified_utc", f.ModTime().UTC().Format(time.RFC3339), "sha256", shaFile(p, 5*1024*1024)))
			return nil
		})
	}
	if count >= 650 {
		r.Truncated = true
		r.warn("temporary-directory scan capped at 650 files")
	}
}
func mounts(r *ModuleResult) {
	l := lines("/proc/mounts", 150000, 1200)
	if len(l) == 0 {
		r.warn("/proc/mounts unavailable")
	}
	for _, line := range l {
		f := strings.Fields(line)
		if len(f) < 4 {
			continue
		}
		r.Items = append(r.Items, record("source", truncate(f[0], 220), "target", truncate(f[1], 220), "filesystem", f[2], "options", truncate(f[3], 180)))
	}
	if len(l) >= 1200 {
		r.Truncated = true
	}
}
func ipPort(h string) string {
	f := strings.Split(h, ":")
	if len(f) != 2 {
		return ""
	}
	v := f[0]
	port, e := strconv.ParseUint(f[1], 16, 16)
	if e != nil {
		return ""
	}
	if len(v) == 8 {
		a := []string{}
		for i := 6; i >= 0; i -= 2 {
			x, _ := strconv.ParseUint(v[i:i+2], 16, 8)
			a = append(a, strconv.FormatUint(x, 10))
		}
		return strings.Join(a, ".") + ":" + strconv.FormatUint(port, 10)
	}
	return truncate(v, 40) + ":" + strconv.FormatUint(port, 10)
}
func socketOwners() map[string]int {
	result := map[string]int{}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return result
	}
	count := 0
	for _, ent := range entries {
		pid, e := strconv.Atoi(ent.Name())
		if e != nil {
			continue
		}
		fds, e := os.ReadDir(fmt.Sprintf("/proc/%d/fd", pid))
		if e != nil {
			continue
		}
		for _, fd := range fds {
			count++
			if count > 12000 {
				return result
			}
			target, e := os.Readlink(fmt.Sprintf("/proc/%d/fd/%s", pid, fd.Name()))
			if e != nil {
				continue
			}
			if strings.HasPrefix(target, "socket:[") && strings.HasSuffix(target, "]") {
				result[strings.TrimSuffix(strings.TrimPrefix(target, "socket:["), "]")] = pid
			}
		}
	}
	return result
}
func network(r *ModuleResult) {
	owners := socketOwners()
	for _, proto := range []string{"tcp", "tcp6", "udp", "udp6"} {
		l := lines("/proc/net/"+proto, 220000, 1500)
		if len(l) == 0 {
			r.warn("unable to read /proc/net/" + proto)
			continue
		}
		for _, x := range l[1:] {
			f := strings.Fields(x)
			if len(f) < 11 {
				continue
			}
			r.Items = append(r.Items, record("protocol", proto, "local", ipPort(f[1]), "remote", ipPort(f[2]), "state", f[3], "socket_inode", f[10], "pid", owners[f[10]]))
		}
		if len(l) >= 1500 {
			r.Truncated = true
		}
	}
}
func firewall(ctx context.Context, r *ModuleResult) {
	for _, spec := range [][]string{{"nft", "-nn", "list", "ruleset"}, {"iptables", "-S"}, {"ip6tables", "-S"}} {
		out, e := execBounded(ctx, spec[0], spec[1:]...)
		if e != nil {
			r.warn(spec[0] + " rules unavailable (may require elevated access)")
			continue
		}
		for _, line := range strings.Split(out, "\n") {
			if strings.TrimSpace(line) != "" && len(r.Items) < 380 {
				r.Items = append(r.Items, record("tool", spec[0], "rule", truncate(line, 450)))
			}
		}
		if len(r.Items) >= 380 {
			r.Truncated = true
			break
		}
	}
}
func services(ctx context.Context, r *ModuleResult) {
	outTimers, eTimers := execBounded(ctx, "systemctl", "list-timers", "--all", "--no-pager", "--no-legend", "--plain")
	if eTimers == nil {
		for _, ln := range strings.Split(outTimers, "\n") {
			if len(r.Items) >= 40 {
				break
			}
			if strings.TrimSpace(ln) != "" {
				r.Items = append(r.Items, record("timer_summary", truncate(ln, 260)))
			}
		}
	}
	out, e := execBounded(ctx, "systemctl", "list-unit-files", "--type=service", "--no-pager", "--no-legend", "--plain")
	if e != nil {
		r.warn("systemctl unavailable or systemd not running")
	} else {
		for _, s := range strings.Split(out, "\n") {
			f := strings.Fields(s)
			if len(f) >= 2 && len(r.Items) < 500 {
				r.Items = append(r.Items, record("unit", f[0], "state", f[1]))
			}
		}
	}
	for _, dir := range []string{"/etc/systemd/system", "/usr/local/lib/systemd/system"} {
		entries, e := os.ReadDir(dir)
		if e != nil {
			continue
		}
		for _, ent := range entries {
			if !strings.HasSuffix(ent.Name(), ".service") || !ent.Type().IsRegular() {
				continue
			}
			p := filepath.Join(dir, ent.Name())
			content := read(p, 5000)
			for _, line := range strings.Split(content, "\n") {
				if strings.HasPrefix(strings.TrimSpace(line), "ExecStart=") {
					r.Items = append(r.Items, record("unit", ent.Name(), "file", p, "exec_start", truncate(Redact(strings.TrimSpace(line)), 350)))
				}
			}
		}
	}
}
func cron(ctx context.Context, r *ModuleResult) {
	paths := []string{"/etc/crontab"}
	for _, dir := range []string{"/etc/cron.d", "/var/spool/cron/crontabs", "/var/spool/cron"} {
		ents, e := os.ReadDir(dir)
		if e != nil {
			continue
		}
		for _, x := range ents {
			if x.Type().IsRegular() && len(paths) < 65 {
				paths = append(paths, filepath.Join(dir, x.Name()))
			}
		}
	}
	for _, p := range paths {
		content := read(p, 20000)
		if content == "" {
			continue
		}
		for _, s := range strings.Split(content, "\n") {
			s = strings.TrimSpace(s)
			if s == "" || strings.HasPrefix(s, "#") || strings.HasPrefix(s, "SHELL=") || strings.HasPrefix(s, "PATH=") {
				continue
			}
			r.Items = append(r.Items, record("source", p, "entry", truncate(Redact(s), 420)))
		}
	}
	out, e := execBounded(ctx, "crontab", "-l")
	if e == nil {
		for _, s := range strings.Split(out, "\n") {
			s = strings.TrimSpace(s)
			if s != "" && !strings.HasPrefix(s, "#") {
				r.Items = append(r.Items, record("source", "current-user-crontab", "entry", truncate(Redact(s), 420)))
			}
		}
	}
}
func homeDirs() []string {
	seen := map[string]bool{}
	a := []string{}
	if u, e := user.Current(); e == nil {
		seen[u.HomeDir] = true
		a = append(a, u.HomeDir)
	}
	for _, l := range lines("/etc/passwd", 500000, 4000) {
		f := strings.Split(l, ":")
		if len(f) < 7 {
			continue
		}
		p := f[5]
		if !(strings.HasPrefix(p, "/home/") || p == "/root") {
			continue
		}
		if !seen[p] && len(a) < 55 {
			a = append(a, p)
			seen[p] = true
		}
	}
	sort.Strings(a)
	return a
}
func ssh(r *ModuleResult) {
	paths := []string{"/etc/ssh/sshd_config"}
	if entries, e := os.ReadDir("/etc/ssh/sshd_config.d"); e == nil {
		for _, entry := range entries {
			if entry.Type().IsRegular() && len(paths) < 35 {
				paths = append(paths, filepath.Join("/etc/ssh/sshd_config.d", entry.Name()))
			}
		}
	}
	for _, p := range paths {
		content := read(p, 18000)
		if content == "" {
			continue
		}
		for _, line := range strings.Split(content, "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			f := strings.Fields(line)
			if len(f) >= 2 {
				setting := strings.ToLower(f[0])
				switch setting {
				case "permitrootlogin", "passwordauthentication", "pubkeyauthentication", "allowusers", "allowgroups", "denyusers", "denygroups", "authorizedkeysfile":
					r.Items = append(r.Items, record("kind", "ssh_config", "source", p, "setting", setting, "value", truncate(Redact(strings.Join(f[1:], " ")), 180)))
				}
			}
		}
	}
	for _, home := range homeDirs() {
		p := filepath.Join(home, ".ssh/authorized_keys")
		b := read(p, 50000)
		if b == "" {
			continue
		}
		f, err := os.Stat(p)
		if err != nil {
			continue
		}
		n := 0
		for _, l := range strings.Split(b, "\n") {
			if strings.HasPrefix(strings.TrimSpace(l), "#") || strings.TrimSpace(l) == "" {
				continue
			}
			fields := strings.Fields(l)
			for i := 0; i+1 < len(fields); i++ {
				if strings.HasPrefix(fields[i], "ssh-") || strings.HasPrefix(fields[i], "ecdsa-") {
					raw, e := base64.StdEncoding.DecodeString(fields[i+1])
					if e == nil {
						sum := sha256.Sum256(raw)
						r.Items = append(r.Items, record("path", p, "key_type", fields[i], "fingerprint", "SHA256:"+base64.RawStdEncoding.EncodeToString(sum[:]), "modified_utc", f.ModTime().UTC().Format(time.RFC3339), "mode", f.Mode().Perm().String()))
						n++
						break
					}
				}
			}
			if n >= 120 {
				r.Truncated = true
				break
			}
		}
	}
}
func profiles(r *ModuleResult) {
	for _, home := range homeDirs() {
		for _, name := range []string{".bashrc", ".bash_profile", ".profile", ".zshrc"} {
			p := filepath.Join(home, name)
			b := read(p, 20000)
			if b == "" {
				continue
			}
			f, e := os.Stat(p)
			if e != nil {
				continue
			}
			matched := []string{}
			for _, l := range strings.Split(b, "\n") {
				low := strings.ToLower(l)
				if strings.Contains(low, "curl ") || strings.Contains(low, "wget ") || strings.Contains(low, "/dev/tcp/") || strings.Contains(low, "nc -") || strings.Contains(low, "base64 -d") || strings.Contains(low, "/tmp/") {
					matched = append(matched, truncate(Redact(strings.TrimSpace(l)), 300))
				}
			}
			if len(matched) > 0 {
				r.Items = append(r.Items, record("path", p, "modified_utc", f.ModTime().UTC().Format(time.RFC3339), "suspicious_lines", matched))
			}
		}
	}
}
func logs(ctx context.Context, r *ModuleResult) {
	out, e := execBounded(ctx, "journalctl", "--no-pager", "-n", "250", "-o", "short-iso")
	if e == nil {
		for _, l := range strings.Split(out, "\n") {
			if l != "" {
				r.Items = append(r.Items, record("source", "journalctl", "line", truncate(Redact(l), 600)))
			}
		}
	} else {
		r.warn("journalctl unavailable or inaccessible")
	}
	for _, p := range []string{"/var/log/auth.log", "/var/log/secure"} {
		f, e := os.Open(p)
		if e != nil {
			continue
		}
		fi, _ := f.Stat()
		if fi.Size() > 120000 {
			_, _ = f.Seek(-120000, io.SeekEnd)
		}
		sc := bufio.NewScanner(io.LimitReader(f, 125000))
		sc.Buffer(make([]byte, 4096), 20000)
		lines := []string{}
		for sc.Scan() {
			lines = append(lines, truncate(Redact(sc.Text()), 600))
		}
		_ = f.Close()
		if len(lines) > 120 {
			lines = lines[len(lines)-120:]
		}
		for _, l := range lines {
			r.Items = append(r.Items, record("source", p, "line", l))
		}
	}
	if len(r.Items) == 0 {
		r.warn("no readable recent security logs; absence of evidence is not proof of safety")
	}
}
