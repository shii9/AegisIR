package bridge

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

type Response struct {
	OK      bool            `json:"ok"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data"`
}

func Locate() (string, error) {
	if s := os.Getenv("AEGISIR_ENGINE"); s != "" {
		return s, nil
	}
	candidates := []string{"python/engine.py", "../python/engine.py"}
	if ex, err := os.Executable(); err == nil {
		if realEx, err := filepath.EvalSymlinks(ex); err == nil {
			d := filepath.Dir(realEx)
			candidates = append(candidates, filepath.Join(d, "python/engine.py"), filepath.Join(d, "../python/engine.py"))
		}
		d := filepath.Dir(ex)
		candidates = append(candidates, filepath.Join(d, "python/engine.py"), filepath.Join(d, "../python/engine.py"))
	}
	if home, err := os.UserHomeDir(); err == nil {
		candidates = append(candidates,
			filepath.Join(home, ".local/opt/aegisir/python/engine.py"),
			filepath.Join(home, ".local/share/aegisir/python/engine.py"),
		)
	}
	candidates = append(candidates, "/usr/local/share/aegisir/python/engine.py", "/opt/aegisir/python/engine.py")
	for _, p := range candidates {
		if info, err := os.Stat(p); err == nil && !info.IsDir() {
			return p, nil
		}
	}
	return "", errors.New("Python engine not found; run from project root or set AEGISIR_ENGINE")
}
func Call(req map[string]any) (Response, error) {
	p, err := Locate()
	if err != nil {
		return Response{}, err
	}
	b, err := json.Marshal(req)
	if err != nil {
		return Response{}, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "python3", p)
	cmd.Stdin = bytes.NewReader(b)
	cmd.Env = append(os.Environ(), "PYTHONDONTWRITEBYTECODE=1")
	var out, errs bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errs
	err = cmd.Run()
	if ctx.Err() != nil {
		return Response{}, ctx.Err()
	}
	if err != nil {
		return Response{}, fmt.Errorf("engine: %w: %s", err, errs.String())
	}
	var resp Response
	if err := json.Unmarshal(out.Bytes(), &resp); err != nil {
		return Response{}, fmt.Errorf("bad engine response: %w: %s", err, out.String())
	}
	if !resp.OK {
		return resp, fmt.Errorf("%s", resp.Message)
	}
	return resp, nil
}
