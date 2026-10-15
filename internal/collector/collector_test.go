package collector

import (
	"context"
	"runtime"
	"strings"
	"testing"
)

func TestRedact(t *testing.T) {
	s := Redact("x password=abc token=xyz")
	if strings.Contains(s, "abc") || strings.Contains(s, "xyz") {
		t.Fatalf("secret remains: %s", s)
	}
}
func TestCollection(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux only")
	}
	res, err := Collect(context.Background(), "users")
	if err != nil || len(res) != 1 || len(res[0].Items) == 0 {
		t.Fatalf("bad collector %v %+v", err, res)
	}
}
func TestRejectUnknownModule(t *testing.T) {
	if _, err := Collect(context.Background(), "danger"); err == nil {
		t.Fatal("unknown module accepted")
	}
}
func TestIPPort(t *testing.T) {
	if got := ipPort("0100007F:0016"); got != "127.0.0.1:22" {
		t.Fatalf("got %s", got)
	}
}
