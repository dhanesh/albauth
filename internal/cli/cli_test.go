package cli

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"albauth/internal/auth"
	"albauth/internal/config"
	"albauth/internal/mcpserver"
	"albauth/internal/session"
	"albauth/test/albfake"
)

var now = time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)

// fixture is a self-contained CLI environment: a temp state directory, a
// generated config pointed at a fake load balancer, and a stub login.
type fixture struct {
	env        Env
	alb        *albfake.ALB
	configPath string
	stateDir   string
	stdout     *strings.Builder
	stderr     *strings.Builder
	logins     *int
}

func newFixture(t *testing.T, extraTOML string) *fixture {
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

[settings]
storage = "file"
log_level = "debug"
%s`, alb.URL(), alb.Host(), albfake.IDPHost, extraTOML)

	if err := os.WriteFile(configPath, []byte(toml), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	origState, origSession := stateDirPath, sessionFilePath
	t.Cleanup(func() { stateDirPath, sessionFilePath = origState, origSession })
	stateDirPath = func(func(string) string) (string, error) { return stateDir, nil }
	sessionFilePath = func(func(string) string) (string, error) {
		return filepath.Join(stateDir, "sessions.json"), nil
	}

	logins := 0
	stdout, stderr := &strings.Builder{}, &strings.Builder{}
	f := &fixture{
		alb: alb, configPath: configPath, stateDir: stateDir,
		stdout: stdout, stderr: stderr, logins: &logins,
	}
	f.env = Env{
		Stdin:  strings.NewReader(""),
		Stdout: stdout,
		Stderr: stderr,
		Getenv: func(k string) string {
			switch k {
			case "XDG_STATE_HOME", "LOCALAPPDATA":
				return stateDir
			case "ALBAUTH_CONFIG":
				return configPath
			}
			return ""
		},
		Now:     func() time.Time { return now },
		Version: "1.2.3-test",
		Loginer: auth.LoginerFunc(func(context.Context, *config.Domain, string) ([]session.Cookie, error) {
			logins++
			var cookies []session.Cookie
			for name, value := range alb.IssueSession(fmt.Sprintf("cli-%d", logins)) {
				cookies = append(cookies, session.Cookie{
					Name: name, Value: value, Path: "/", Expires: now.Add(time.Hour),
				})
			}
			return cookies, nil
		}),
	}
	return f
}

func (f *fixture) run(t *testing.T, args ...string) int {
	t.Helper()
	env := f.env
	env.Args = args
	return Run(t.Context(), env)
}

func (f *fixture) out() string { return f.stdout.String() }
func (f *fixture) err() string { return f.stderr.String() }

func TestVersion(t *testing.T) {
	f := newFixture(t, "")
	if code := f.run(t, "version"); code != 0 {
		t.Fatalf("exit code = %d", code)
	}
	if strings.TrimSpace(f.out()) != "1.2.3-test" {
		t.Fatalf("stdout = %q", f.out())
	}
}

func TestConfigPath(t *testing.T) {
	f := newFixture(t, "")
	if code := f.run(t, "config", "path"); code != 0 {
		t.Fatalf("exit code = %d: %s", code, f.err())
	}
	if strings.TrimSpace(f.out()) != f.configPath {
		t.Fatalf("stdout = %q, want %q", f.out(), f.configPath)
	}
}

// A config path that cannot be resolved fails the same way whether it is asked
// for directly or needed to run a command.
func TestConfigPathReportsAResolutionFailure(t *testing.T) {
	for _, args := range [][]string{{"config", "path"}, {"config", "validate"}, {"auth", "status"}} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			f := newFixture(t, "")
			f.env.Getenv = func(string) string { return "" }
			orig := configResolvePath
			t.Cleanup(func() { configResolvePath = orig })
			configResolvePath = func(string, func(string) string) (string, error) {
				return "", fmt.Errorf("cannot determine config directory")
			}
			if code := f.run(t, args...); code != 1 {
				t.Fatalf("exit code = %d, want 1", code)
			}
		})
	}
}

func TestConfigValidate(t *testing.T) {
	f := newFixture(t, "")
	if code := f.run(t, "config", "validate"); code != 0 {
		t.Fatalf("exit code = %d: %s", code, f.err())
	}
	if !strings.Contains(f.out(), "is valid: 1 domain(s) configured") {
		t.Fatalf("stdout = %q", f.out())
	}
}

// Acceptance criterion: every config error is reported at once.
func TestConfigValidateReportsEveryProblem(t *testing.T) {
	f := newFixture(t, "")
	bad := `
[[domain]]
name = "BAD NAME"
base_url = "ftp://api.example.com/"
allow_methods = ["TRACE"]

[settings]
storage = "magic"
log_level = "chatty"
`
	if err := os.WriteFile(f.configPath, []byte(bad), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if code := f.run(t, "config", "validate"); code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	for _, needle := range []string{"name must match", "scheme must be https", "trailing slash",
		"not a supported HTTP method", "is not one of auto, keyring, file", "unknown log level"} {
		if !strings.Contains(f.err(), needle) {
			t.Fatalf("stderr should mention %q, got:\n%s", needle, f.err())
		}
	}
}

func TestConfigValidateReportsAMissingFile(t *testing.T) {
	f := newFixture(t, "")
	if err := os.Remove(f.configPath); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if code := f.run(t, "config", "validate"); code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
}

func TestAuthLoginThenStatusThenLogout(t *testing.T) {
	f := newFixture(t, "")

	if code := f.run(t, "auth", "login", "internal-api"); code != 0 {
		t.Fatalf("login exit code = %d: %s", code, f.err())
	}
	if !strings.Contains(f.out(), "internal-api: authenticated, 2 cookie(s)") {
		t.Fatalf("login stdout = %q", f.out())
	}
	if *f.logins != 1 {
		t.Fatalf("performed %d logins", *f.logins)
	}

	f.stdout.Reset()
	if code := f.run(t, "auth", "status"); code != 0 {
		t.Fatalf("status exit code = %d: %s", code, f.err())
	}
	if !strings.Contains(f.out(), "authenticated") || !strings.Contains(f.out(), "DOMAIN") {
		t.Fatalf("status stdout = %q", f.out())
	}

	f.stdout.Reset()
	if code := f.run(t, "auth", "logout", "internal-api"); code != 0 {
		t.Fatalf("logout exit code = %d: %s", code, f.err())
	}
	if !strings.Contains(f.out(), "session deleted") {
		t.Fatalf("logout stdout = %q", f.out())
	}

	f.stdout.Reset()
	f.run(t, "auth", "status")
	if !strings.Contains(f.out(), "logged out") {
		t.Fatalf("status after logout = %q", f.out())
	}
}

func TestAuthLoginForce(t *testing.T) {
	f := newFixture(t, "")
	f.run(t, "auth", "login", "internal-api")
	f.run(t, "auth", "login", "internal-api")
	if *f.logins != 1 {
		t.Fatalf("a valid session should be reused, performed %d logins", *f.logins)
	}
	if code := f.run(t, "auth", "login", "--force", "internal-api"); code != 0 {
		t.Fatalf("exit code = %d: %s", code, f.err())
	}
	if *f.logins != 2 {
		t.Fatalf("--force should re-authenticate, performed %d logins", *f.logins)
	}
}

func TestAuthStatusForOneDomain(t *testing.T) {
	f := newFixture(t, "")
	f.run(t, "auth", "login", "internal-api")
	f.stdout.Reset()

	if code := f.run(t, "auth", "status", "internal-api"); code != 0 {
		t.Fatalf("exit code = %d: %s", code, f.err())
	}
	if strings.Count(f.out(), "internal-api") != 1 {
		t.Fatalf("stdout = %q", f.out())
	}
}

func TestAuthStatusShowsAnExpiredSession(t *testing.T) {
	f := newFixture(t, "")
	f.run(t, "auth", "login", "internal-api")

	// Rewind the clock forward past the cookie's expiry.
	f.env.Now = func() time.Time { return now.Add(2 * time.Hour) }
	f.stdout.Reset()
	f.run(t, "auth", "status", "internal-api")
	if !strings.Contains(f.out(), "expired") {
		t.Fatalf("stdout = %q, want the session reported as expired", f.out())
	}
}

func TestAuthStatusReportsAStorageError(t *testing.T) {
	f := newFixture(t, "")
	f.run(t, "auth", "login", "internal-api")

	sessionPath := filepath.Join(f.stateDir, "sessions.json")
	if err := os.Chmod(sessionPath, 0o644); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	f.stdout.Reset()
	f.run(t, "auth", "status", "internal-api")
	if !strings.Contains(f.out(), "error:") {
		t.Fatalf("stdout = %q, want the storage error surfaced", f.out())
	}
}

func TestAuthLogoutClearsTheBrowserProfile(t *testing.T) {
	f := newFixture(t, "")
	profile := filepath.Join(f.stateDir, "browser", "internal-api")
	if err := os.MkdirAll(profile, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	if code := f.run(t, "auth", "logout", "--clear-browser-profile", "internal-api"); code != 0 {
		t.Fatalf("exit code = %d: %s", code, f.err())
	}
	if !strings.Contains(f.out(), "browser profile deleted") {
		t.Fatalf("stdout = %q", f.out())
	}
	if _, err := os.Stat(profile); !os.IsNotExist(err) {
		t.Fatal("the browser profile directory should be gone")
	}
}

func TestAuthImport(t *testing.T) {
	f := newFixture(t, "")
	f.env.Stdin = strings.NewReader(
		albfake.CookiePrefix + "-0=pasted.0\n" + albfake.CookiePrefix + "-1=pasted.1\n\n")

	if code := f.run(t, "auth", "import", "internal-api"); code != 0 {
		t.Fatalf("exit code = %d: %s", code, f.err())
	}
	if !strings.Contains(f.out(), "DevTools") {
		t.Fatalf("the instructions should be printed, got %q", f.out())
	}
	if !strings.Contains(f.out(), "imported 2 cookie(s)") {
		t.Fatalf("stdout = %q", f.out())
	}

	// The imported session is usable: the fake accepts it.
	f.stdout.Reset()
	f.run(t, "auth", "status", "internal-api")
	if !strings.Contains(f.out(), "authenticated") {
		t.Fatalf("status = %q", f.out())
	}
	// Cookie values must not be echoed back.
	if strings.Contains(f.out()+f.err(), "pasted.0") {
		t.Fatal("a pasted cookie value was echoed")
	}
}

func TestAuthImportRejectsCookiesThatDoNotMatchThePrefix(t *testing.T) {
	f := newFixture(t, "")
	f.env.Stdin = strings.NewReader("session_id=abc\n\n")
	if code := f.run(t, "auth", "import", "internal-api"); code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	if !strings.Contains(f.err(), "prefix") {
		t.Fatalf("stderr = %q", f.err())
	}
}

func TestUsageErrors(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{"an unknown command", []string{"frobnicate"}},
		{"auth with no subcommand", []string{"auth"}},
		{"an unknown auth subcommand", []string{"auth", "frobnicate"}},
		{"config with no subcommand", []string{"config"}},
		{"an unknown config subcommand", []string{"config", "frobnicate"}},
		{"auth login with no domain", []string{"auth", "login"}},
		{"auth login with two domains", []string{"auth", "login", "a", "b"}},
		{"auth logout with no domain", []string{"auth", "logout"}},
		{"auth import with no domain", []string{"auth", "import"}},
		{"auth status with two domains", []string{"auth", "status", "a", "b"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t, "")
			if code := f.run(t, tc.args...); code == 0 {
				t.Fatalf("%v should not succeed", tc.args)
			}
		})
	}
}

func TestHelp(t *testing.T) {
	for _, arg := range []string{"help", "-h", "--help"} {
		f := newFixture(t, "")
		if code := f.run(t, arg); code != 0 {
			t.Fatalf("%q exit code = %d", arg, code)
		}
		if !strings.Contains(f.err(), "albauth [flags] <command>") {
			t.Fatalf("%q did not print usage: %q", arg, f.err())
		}
	}
}

func TestUnparseableFlags(t *testing.T) {
	f := newFixture(t, "")
	if code := f.run(t, "--nonexistent-flag"); code != 2 {
		t.Fatalf("exit code = %d, want 2", code)
	}
}

func TestSubcommandFlagParseErrors(t *testing.T) {
	for _, args := range [][]string{
		{"auth", "login", "--nope"},
		{"auth", "logout", "--nope"},
	} {
		f := newFixture(t, "")
		if code := f.run(t, args...); code == 0 {
			t.Fatalf("%v should not succeed", args)
		}
	}
}

func TestUnknownDomain(t *testing.T) {
	for _, args := range [][]string{
		{"auth", "login", "nope"},
		{"auth", "logout", "nope"},
		{"auth", "import", "nope"},
		{"auth", "status", "nope"},
	} {
		f := newFixture(t, "")
		if code := f.run(t, args...); code != 1 {
			t.Fatalf("%v exit code = %d, want 1", args, code)
		}
		if !strings.Contains(f.err(), "unknown domain") {
			t.Fatalf("%v stderr = %q", args, f.err())
		}
	}
}

func TestTheConfigFlagOverridesTheEnvironment(t *testing.T) {
	f := newFixture(t, "")
	other := filepath.Join(t.TempDir(), "other.toml")
	if err := os.WriteFile(other, []byte(`
[[domain]]
name = "other-api"
base_url = "https://other.example.com"
`), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if code := f.run(t, "--config", other, "config", "validate"); code != 0 {
		t.Fatalf("exit code = %d: %s", code, f.err())
	}
	f.stdout.Reset()
	f.run(t, "--config", other, "auth", "status")
	if !strings.Contains(f.out(), "other-api") {
		t.Fatalf("stdout = %q", f.out())
	}
}

func TestTheLogLevelFlagOverridesTheConfig(t *testing.T) {
	f := newFixture(t, "")
	if code := f.run(t, "--log-level", "error", "auth", "login", "internal-api"); code != 0 {
		t.Fatalf("exit code = %d: %s", code, f.err())
	}
	// At error level the informational login lines are suppressed.
	if strings.Contains(f.err(), "opening browser") {
		t.Fatalf("stderr should be quiet at error level: %q", f.err())
	}

	other := newFixture(t, "")
	if code := other.run(t, "--log-level", "chatty", "auth", "status"); code != 1 {
		t.Fatalf("an invalid level should fail, exit code = %d", code)
	}
}

func TestBuildReportsAStateDirectoryFailure(t *testing.T) {
	f := newFixture(t, "")
	f.env.Getenv = func(k string) string {
		if k == "ALBAUTH_CONFIG" {
			return f.configPath
		}
		return ""
	}
	orig := stateDirPath
	t.Cleanup(func() { stateDirPath = orig })
	stateDirPath = func(func(string) string) (string, error) { return "", fmt.Errorf("no HOME") }

	if code := f.run(t, "auth", "status"); code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
}

// storage = "keyring" is a hard failure when no OS keychain is reachable,
// which is the state of most build machines.
func TestBuildReportsAKeyringFailure(t *testing.T) {
	f := newFixture(t, "")
	body, err := os.ReadFile(f.configPath)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	fixed := strings.Replace(string(body), `storage = "file"`, `storage = "keyring"`, 1)
	if err := os.WriteFile(f.configPath, []byte(fixed), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	orig := openStore
	t.Cleanup(func() { openStore = orig })
	openStore = func(string, string, session.Warner) (session.Store, error) {
		return nil, session.ErrKeyringUnavailable
	}
	if code := f.run(t, "auth", "status"); code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
}

// serve is the default when no subcommand is given, and speaks JSON-RPC on the
// streams it is handed.
func TestServeIsTheDefaultCommand(t *testing.T) {
	f := newFixture(t, "")
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	inReader, inWriter := io.Pipe()
	outReader, outWriter := io.Pipe()
	env := f.env
	env.Args = nil
	env.Stdin = inReader
	env.Stdout = outWriter

	done := make(chan int, 1)
	go func() { done <- Run(ctx, env) }()

	if _, err := io.WriteString(inWriter, `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`+"\n"); err != nil {
		t.Fatalf("write: %v", err)
	}
	lines := bufio.NewScanner(outReader)
	if !lines.Scan() {
		t.Fatalf("no response: %v", lines.Err())
	}
	var envelope map[string]any
	if err := json.Unmarshal(lines.Bytes(), &envelope); err != nil {
		t.Fatalf("stdout is not JSON-RPC: %v (%s)", err, lines.Text())
	}
	if !strings.Contains(lines.Text(), mcpserver.ToolHTTPRequest) {
		t.Fatalf("tools/list = %s", lines.Text())
	}

	cancel()
	_ = inWriter.Close()
	_ = outWriter.Close()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("serve did not return after its context was cancelled")
	}
}

func TestServeReportsAConfigFailure(t *testing.T) {
	f := newFixture(t, "")
	if err := os.Remove(f.configPath); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if code := f.run(t, "serve"); code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
}

func TestRunFillsInMissingEnvironmentPieces(t *testing.T) {
	// Every stream and hook is optional; Run must not panic without them.
	if code := Run(context.Background(), Env{Args: []string{"version"}}); code != 0 {
		t.Fatalf("exit code = %d", code)
	}
}

func TestExpiryText(t *testing.T) {
	if got := expiryText(time.Time{}); got != "unknown" {
		t.Fatalf("expiryText(zero) = %q", got)
	}
	if got := expiryText(now); got != "2026-08-26T12:00:00Z" {
		t.Fatalf("expiryText = %q", got)
	}
}

func TestClearProfileReportsAFailure(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	dir := t.TempDir()
	browser := filepath.Join(dir, "browser")
	if err := os.MkdirAll(filepath.Join(browser, "api"), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.Chmod(browser, 0o500); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(browser, 0o700) })

	rt := &runtime{stateDir: dir}
	if err := rt.clearProfile("api"); err == nil {
		t.Fatal("clearProfile should report a removal failure")
	}
}

// Every command routes through build, so a broken config fails the same way
// everywhere rather than partway through the command's own work.
func TestEveryCommandReportsAConfigFailure(t *testing.T) {
	for _, args := range [][]string{
		{"auth", "login", "internal-api"},
		{"auth", "status"},
		{"auth", "logout", "internal-api"},
		{"auth", "import", "internal-api"},
		{"config", "validate"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			f := newFixture(t, "")
			if err := os.Remove(f.configPath); err != nil {
				t.Fatalf("remove: %v", err)
			}
			if code := f.run(t, args...); code != 1 {
				t.Fatalf("exit code = %d, want 1", code)
			}
		})
	}
}

// An unwritable session store must surface on every command that writes one.
func TestCommandsReportAStorageFailure(t *testing.T) {
	tests := []struct {
		name string
		args []string
		in   string
	}{
		{"login", []string{"auth", "login", "internal-api"}, ""},
		{"logout", []string{"auth", "logout", "internal-api"}, ""},
		{"import", []string{"auth", "import", "internal-api"},
			albfake.CookiePrefix + "-0=abc\n\n"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t, "")
			f.env.Stdin = strings.NewReader(tc.in)
			orig := openStore
			t.Cleanup(func() { openStore = orig })
			openStore = func(string, string, session.Warner) (session.Store, error) {
				return readOnlyStore{}, nil
			}
			if code := f.run(t, tc.args...); code != 1 {
				t.Fatalf("exit code = %d, want 1", code)
			}
		})
	}
}

func TestAuthLogoutReportsAProfileRemovalFailure(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	f := newFixture(t, "")
	browserDir := filepath.Join(f.stateDir, "browser")
	if err := os.MkdirAll(filepath.Join(browserDir, "internal-api"), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.Chmod(browserDir, 0o500); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(browserDir, 0o700) })

	if code := f.run(t, "auth", "logout", "--clear-browser-profile", "internal-api"); code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
}

func TestBuildReportsASessionPathFailure(t *testing.T) {
	f := newFixture(t, "")
	orig := sessionFilePath
	t.Cleanup(func() { sessionFilePath = orig })
	sessionFilePath = func(func(string) string) (string, error) { return "", fmt.Errorf("no HOME") }

	if code := f.run(t, "auth", "status"); code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
}

// With no Loginer supplied, build wires the real browser-driven one. This
// exercises that wiring without launching a browser: no login is attempted.
func TestBuildWiresTheRealBrowserLoginerByDefault(t *testing.T) {
	f := newFixture(t, "")
	f.env.Loginer = nil
	if code := f.run(t, "auth", "status"); code != 0 {
		t.Fatalf("exit code = %d: %s", code, f.err())
	}
}

// readOnlyStore accepts reads and refuses every write.
type readOnlyStore struct{}

func (readOnlyStore) Get(string) (*session.Session, error) { return nil, session.ErrNotFound }
func (readOnlyStore) Set(string, *session.Session) error   { return fmt.Errorf("read-only store") }
func (readOnlyStore) Delete(string) error                  { return fmt.Errorf("read-only store") }
func (readOnlyStore) Backend() string                      { return "read-only" }

// `albauth config path` printing a path to a file that is not there reads as a
// bug unless it says so.
func TestConfigPathSaysWhenThereIsNoConfigYet(t *testing.T) {
	f := newFixture(t, "")
	if err := os.Remove(f.configPath); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if code := f.run(t, "config", "path"); code != 0 {
		t.Fatalf("exit code = %d", code)
	}
	if strings.TrimSpace(f.out()) != f.configPath {
		t.Fatalf("stdout must be the bare path so scripts can use it, got %q", f.out())
	}
	if !strings.Contains(f.err(), "no config there yet") {
		t.Fatalf("stderr should say the file is absent: %q", f.err())
	}
}

func TestConfigPathWarnsAboutASpaceInThePath(t *testing.T) {
	f := newFixture(t, "")
	spacey := filepath.Join(t.TempDir(), "Application Support", "albauth", "config.toml")
	if err := os.MkdirAll(filepath.Dir(spacey), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(spacey, []byte("[[domain]]\nname=\"a\"\nbase_url=\"https://a.example.com\"\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	f.configPath = spacey
	f.env.Getenv = func(k string) string {
		if k == "ALBAUTH_CONFIG" {
			return spacey
		}
		return ""
	}
	if code := f.run(t, "config", "path"); code != 0 {
		t.Fatalf("exit code = %d", code)
	}
	if !strings.Contains(f.err(), "contains a space") {
		t.Fatalf("stderr should warn about the space: %q", f.err())
	}
}

func TestConfigPathIsQuietWhenTheConfigIsFine(t *testing.T) {
	f := newFixture(t, "")
	if code := f.run(t, "config", "path"); code != 0 {
		t.Fatalf("exit code = %d", code)
	}
	if f.err() != "" {
		t.Fatalf("no note is due for a present, space-free path: %q", f.err())
	}
}
