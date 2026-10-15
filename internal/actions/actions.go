// Package actions enforces conservative, explicit, narrowly scoped local response controls.
// Do not treat these experimental actions as forensically safe or suitable for production.
package actions

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

type Plan struct {
	Type       string `json:"type"`
	PID        int    `json:"pid,omitempty"`
	StartTicks string `json:"start_ticks,omitempty"`
	Path       string `json:"path,omitempty"`
	SHA256     string `json:"sha256,omitempty"`
	OwnerUID   int    `json:"owner_uid,omitempty"`
}

func processIdentity(pid int) (uid int, ticks string, err error) {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return 0, "", err
	}
	uid = -1
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "Uid:") {
			f := strings.Fields(line)
			if len(f) > 1 {
				uid, _ = strconv.Atoi(f[1])
			}
		}
	}
	b, err = os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0, "", err
	}
	i := strings.LastIndexByte(string(b), ')')
	if i < 0 {
		return 0, "", errors.New("malformed proc stat")
	}
	fields := strings.Fields(string(b)[i+1:])
	if len(fields) < 20 {
		return 0, "", errors.New("short proc stat")
	}
	return uid, fields[19], nil
}
func Validate(p Plan) error {
	if os.Geteuid() == 0 {
		return errors.New("live action denied for root operator; use an unprivileged lab account")
	}
	if p.Type == "terminate_process" {
		if p.PID < 100 || p.PID == os.Getpid() || p.PID == os.Getppid() {
			return errors.New("protected PID")
		}
		uid, ticks, err := processIdentity(p.PID)
		if err != nil {
			return err
		}
		if uid != os.Geteuid() || p.OwnerUID != uid || ticks != p.StartTicks || ticks == "" {
			return errors.New("process identity/ownership changed or mismatch")
		}
		exe, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", p.PID))
		if err != nil {
			return err
		}
		if !(strings.HasPrefix(exe, "/tmp/") || strings.HasPrefix(exe, "/var/tmp/")) {
			return errors.New("process executable is not in a permitted temporary directory")
		}
		return nil
	}
	if p.Type == "quarantine_file" {
		if !filepath.IsAbs(p.Path) {
			return errors.New("absolute path required")
		}
		clean := filepath.Clean(p.Path)
		if !(strings.HasPrefix(clean, "/tmp/") || strings.HasPrefix(clean, "/var/tmp/")) {
			return errors.New("file outside bounded temporary paths")
		}
		if strings.HasPrefix(clean, "/tmp/aegisir-") || strings.Contains(clean, "/aegisir-quarantine/") {
			return errors.New("cannot re-quarantine evidence")
		}
		fi, err := os.Lstat(clean)
		if err != nil {
			return err
		}
		if !fi.Mode().IsRegular() {
			return errors.New("only regular files allowed")
		}
		st, ok := fi.Sys().(*syscall.Stat_t)
		if !ok || int(st.Uid) != os.Geteuid() || p.OwnerUID != os.Geteuid() {
			return errors.New("file not owned by operator")
		}
		f, err := os.OpenFile(clean, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
		if err != nil {
			return err
		}
		defer f.Close()
		h := sha256.New()
		if _, err = io.Copy(h, f); err != nil {
			return err
		}
		if hex.EncodeToString(h.Sum(nil)) != p.SHA256 || p.SHA256 == "" {
			return errors.New("file content/hash mismatch")
		}
		return nil
	}
	return errors.New("unsupported action type")
}

// Execute revalidates immediately before the change; no shell expansion or command injection.
func Execute(p Plan, quarantineDir string) (string, error) {
	if err := Validate(p); err != nil {
		return "", err
	}
	if p.Type == "terminate_process" {
		// PID reuse between validation and signal remains possible; do not use on sensitive hosts.
		pr, err := os.FindProcess(p.PID)
		if err != nil {
			return "", err
		}
		if err = pr.Signal(syscall.SIGTERM); err != nil {
			return "", err
		}
		return fmt.Sprintf("SIGTERM sent to PID %d; verify exit independently", p.PID), nil
	}
	if p.Type == "quarantine_file" {
		// Only a same-filesystem atomic rename is supported. No automatic deletion.
		if err := os.MkdirAll(quarantineDir, 0700); err != nil {
			return "", err
		}
		qinfo, err := os.Lstat(quarantineDir)
		if err != nil {
			return "", err
		}
		qowner, ok := qinfo.Sys().(*syscall.Stat_t)
		if !ok || !qinfo.IsDir() || qinfo.Mode().Perm() != 0700 || int(qowner.Uid) != os.Geteuid() {
			return "", errors.New("quarantine directory must be operator-owned with mode 0700")
		}
		src, err := os.Stat(p.Path)
		if err != nil {
			return "", err
		}
		dst, err := os.Stat(quarantineDir)
		if err != nil {
			return "", err
		}
		if src.Sys().(*syscall.Stat_t).Dev != dst.Sys().(*syscall.Stat_t).Dev {
			return "", errors.New("cross-device quarantine refused")
		}
		target := filepath.Join(quarantineDir, fmt.Sprintf("%s-%s", strconv.FormatInt(src.ModTime().UnixNano(), 10), filepath.Base(p.Path)))
		if _, err := os.Lstat(target); err == nil {
			return "", errors.New("quarantine destination exists")
		}
		if err := os.Rename(p.Path, target); err != nil {
			return "", err
		}
		return "quarantined to " + target, nil
	}
	return "", errors.New("unsupported action")
}
