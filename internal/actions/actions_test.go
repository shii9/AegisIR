package actions

import "testing"

func TestRejectsCriticalActions(t *testing.T) {
	plans := []Plan{{Type: "unknown"}, {Type: "terminate_process", PID: 1}, {Type: "quarantine_file", Path: "/etc/passwd"}, {Type: "quarantine_file", Path: "relative"}}
	for _, p := range plans {
		if err := Validate(p); err == nil {
			t.Errorf("should reject %+v", p)
		}
	}
}
