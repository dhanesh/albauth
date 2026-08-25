//go:build e2e

// Package e2e drives the real albauth binary end to end.
//
// Unlike the unit tests, nothing here reaches inside the program: the binary is
// compiled, launched as a subprocess, and spoken to over stdio exactly as an
// MCP client would. Only the interactive browser step is replaced, by an
// imported cookie — the one part of the flow that genuinely needs a human.
package e2e

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"albauth/test/albfake"
)

// binaryOnce builds the binary once for the whole suite.
var binaryOnce = sync.OnceValues(func() (string, error) {
	dir, err := os.MkdirTemp("", "albauth-e2e-bin")
	if err != nil {
		return "", err
	}
	path := filepath.Join(dir, "albauth")
	cmd := exec.Command("go", "build", "-o", path, "albauth/cmd/albauth")
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("build albauth: %v\n%s", err, out)
	}
	return path, nil
})

func binary(t *testing.T) string {
	t.Helper()
	path, err := binaryOnce()
	if err != nil {
		t.Fatalf("%v", err)
	}
	return path
}

// env is one isolated albauth installation: its own config, state directory and
// fake load balancer.
type env struct {
	t          *testing.T
	alb        *albfake.ALB
	configPath string
	stateDir   string
	binary     string
}

func newEnv(t *testing.T, settings string) *env {
	t.Helper()
	alb := albfake.New()
	t.Cleanup(alb.Close)

	dir := t.TempDir()
	stateDir := filepath.Join(dir, "state")
	configPath := filepath.Join(dir, "config.toml")

	toml := fmt.Sprintf(`
[[domain]]
name = "internal-api"
base_url = %q
match = [%q]
idp_hostnames = [%q]
allow_methods = ["GET", "POST"]
login_probe_path = "/healthz"

[[domain]]
name = "admin-console"
base_url = "https://admin.example.com"
allow_methods = ["GET"]

[settings]
storage = "file"
log_level = "debug"
%s`, alb.URL(), alb.Host(), albfake.IDPHost, settings)

	if err := os.WriteFile(configPath, []byte(toml), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return &env{t: t, alb: alb, configPath: configPath, stateDir: stateDir, binary: binary(t)}
}

// environ is the process environment every albauth invocation runs with, pinned
// so a test never reads or writes the developer's real state.
func (e *env) environ() []string {
	return append(os.Environ(),
		"ALBAUTH_CONFIG="+e.configPath,
		"XDG_STATE_HOME="+e.stateDir,
		"XDG_CONFIG_HOME="+filepath.Dir(e.configPath),
		"HOME="+e.stateDir,
		"LOCALAPPDATA="+e.stateDir,
	)
}

// run executes a subcommand and returns stdout, stderr and the exit code.
func (e *env) run(stdin string, args ...string) (string, string, int) {
	e.t.Helper()
	cmd := exec.Command(e.binary, args...)
	cmd.Env = e.environ()
	cmd.Stdin = strings.NewReader(stdin)
	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	code := 0
	if exitErr, ok := err.(*exec.ExitError); ok {
		code = exitErr.ExitCode()
	} else if err != nil {
		e.t.Fatalf("run %v: %v", args, err)
	}
	return stdout.String(), stderr.String(), code
}

// authenticate imports a valid session, standing in for the browser flow.
func (e *env) authenticate(label string) map[string]string {
	e.t.Helper()
	cookies := e.alb.IssueSession(label)
	var input strings.Builder
	for name, value := range cookies {
		fmt.Fprintf(&input, "%s=%s\n", name, value)
	}
	input.WriteString("\n")

	stdout, stderr, code := e.run(input.String(), "auth", "import", "internal-api")
	if code != 0 {
		e.t.Fatalf("auth import failed (%d)\nstdout: %s\nstderr: %s", code, stdout, stderr)
	}
	return cookies
}

// --- MCP client ------------------------------------------------------------

// client is a minimal MCP client speaking JSON-RPC over the server's stdio.
type client struct {
	t      *testing.T
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	lines  *bufio.Scanner
	stderr *strings.Builder
	nextID int

	// stdoutLines records every line the server wrote to stdout, so the suite
	// can assert that the protocol channel carries nothing else.
	stdoutLines []string
}

func (e *env) serve() *client {
	e.t.Helper()
	cmd := exec.Command(e.binary, "serve")
	cmd.Env = e.environ()

	stdin, err := cmd.StdinPipe()
	if err != nil {
		e.t.Fatalf("stdin pipe: %v", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		e.t.Fatalf("stdout pipe: %v", err)
	}
	stderr := &strings.Builder{}
	cmd.Stderr = stderr
	if err := cmd.Start(); err != nil {
		e.t.Fatalf("start server: %v", err)
	}

	c := &client{t: e.t, cmd: cmd, stdin: stdin, lines: bufio.NewScanner(stdout), stderr: stderr, nextID: 1}
	c.lines.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	e.t.Cleanup(c.close)
	c.initialize()
	return c
}

func (c *client) close() {
	_ = c.stdin.Close()
	done := make(chan struct{})
	go func() { _, _ = c.cmd.Process.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		_ = c.cmd.Process.Kill()
	}
}

func (c *client) send(method string, params any) map[string]any {
	c.t.Helper()
	id := c.nextID
	c.nextID++

	request := map[string]any{"jsonrpc": "2.0", "id": id, "method": method, "params": params}
	encoded, err := json.Marshal(request)
	if err != nil {
		c.t.Fatalf("marshal: %v", err)
	}
	if _, err := c.stdin.Write(append(encoded, '\n')); err != nil {
		c.t.Fatalf("write: %v", err)
	}

	for {
		if !c.lines.Scan() {
			c.t.Fatalf("no response to %s: %v\nserver stderr:\n%s", method, c.lines.Err(), c.stderr)
		}
		line := c.lines.Text()
		c.stdoutLines = append(c.stdoutLines, line)

		var envelope map[string]any
		if err := json.Unmarshal([]byte(line), &envelope); err != nil {
			c.t.Fatalf("stdout carried a non-JSON-RPC line: %q", line)
		}
		// Skip notifications and responses to other ids.
		if gotID, ok := envelope["id"].(float64); !ok || int(gotID) != id {
			continue
		}
		return envelope
	}
}

func (c *client) initialize() {
	c.t.Helper()
	c.send("initialize", map[string]any{
		"protocolVersion": "2024-11-05",
		"capabilities":    map[string]any{},
		"clientInfo":      map[string]any{"name": "albauth-e2e", "version": "1"},
	})
}

// callTool invokes a tool and returns its decoded text payload plus whether the
// server flagged the result as an error.
func (c *client) callTool(name string, args map[string]any) (string, bool) {
	c.t.Helper()
	envelope := c.send("tools/call", map[string]any{"name": name, "arguments": args})
	if errObj, present := envelope["error"]; present {
		c.t.Fatalf("%s returned a protocol error: %v", name, errObj)
	}
	result, ok := envelope["result"].(map[string]any)
	if !ok {
		c.t.Fatalf("%s: no result in %v", name, envelope)
	}
	isError, _ := result["isError"].(bool)

	content, ok := result["content"].([]any)
	if !ok || len(content) == 0 {
		c.t.Fatalf("%s: no content in %v", name, result)
	}
	block, ok := content[0].(map[string]any)
	if !ok {
		c.t.Fatalf("%s: unexpected content shape %T", name, content[0])
	}
	text, _ := block["text"].(string)
	return text, isError
}

// callToolJSON decodes a successful tool result into v.
func (c *client) callToolJSON(name string, args map[string]any, v any) {
	c.t.Helper()
	text, isError := c.callTool(name, args)
	if isError {
		c.t.Fatalf("%s failed: %s", name, text)
	}
	if err := json.Unmarshal([]byte(text), v); err != nil {
		c.t.Fatalf("%s result is not JSON: %v\n%s", name, err, text)
	}
}

// callToolError expects a failure and returns the decoded error payload.
func (c *client) callToolError(name string, args map[string]any) map[string]string {
	c.t.Helper()
	text, isError := c.callTool(name, args)
	if !isError {
		c.t.Fatalf("%s should have failed, got: %s", name, text)
	}
	var payload map[string]string
	if err := json.Unmarshal([]byte(text), &payload); err != nil {
		c.t.Fatalf("%s error payload is not JSON: %v\n%s", name, err, text)
	}
	return payload
}

type httpResponse struct {
	Status           int               `json:"status"`
	Headers          map[string]string `json:"headers"`
	Body             string            `json:"body"`
	Truncated        bool              `json:"truncated"`
	Authenticated    bool              `json:"authenticated"`
	ReloginPerformed bool              `json:"relogin_performed"`
}
