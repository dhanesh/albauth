package config

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestRenderDomainOmitsDefaults(t *testing.T) {
	// A generated file that spells out every default is harder to read, and
	// freezes today's defaults into the user's config.
	got := RenderDomain(&Domain{
		Name:                "api",
		BaseURL:             "https://api.example.com",
		Match:               []string{"api.example.com"}, // same as the default
		LoginProbePath:      DefaultLoginProbePath,
		CookieNamePrefix:    DefaultCookieNamePrefix,
		AllowMethods:        []string{"GET"},
		TimeoutSeconds:      DefaultTimeoutSeconds,
		LoginTimeoutSeconds: DefaultLoginTimeoutSecs,
	})

	want := "\n[[domain]]\nname = \"api\"\nbase_url = \"https://api.example.com\"\n"
	if got != want {
		t.Fatalf("RenderDomain() = %q, want %q", got, want)
	}
}

func TestRenderDomainWritesEveryNonDefault(t *testing.T) {
	got := RenderDomain(&Domain{
		Name:                "api",
		BaseURL:             "https://api.example.com",
		Match:               []string{"api.example.com", "*.internal.example.com"},
		LoginProbePath:      "/healthz",
		CookieNamePrefix:    "CustomCookie",
		IDPHostnames:        []string{"login.example.net"},
		AllowMethods:        []string{"GET", "POST"},
		TimeoutSeconds:      45,
		LoginTimeoutSeconds: 300,
		Headers:             map[string]string{"X-Tenant": "eng", "X-Client": "albauth"},
	})

	for _, want := range []string{
		`match = ["api.example.com", "*.internal.example.com"]`,
		`login_probe_path = "/healthz"`,
		`cookie_name_prefix = "CustomCookie"`,
		`idp_hostnames = ["login.example.net"]`,
		`allow_methods = ["GET", "POST"]`,
		"timeout_seconds = 45",
		"login_timeout_seconds = 300",
		"[domain.headers]",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("RenderDomain() is missing %q:\n%s", want, got)
		}
	}
	// Headers are emitted in a stable order so re-running produces the same file.
	client := strings.Index(got, "X-Client")
	tenant := strings.Index(got, "X-Tenant")
	if client > tenant {
		t.Fatalf("headers are not sorted:\n%s", got)
	}
}

// Whatever RenderDomain writes must survive a parse, or `config add-domain`
// could produce a file the tool then refuses to read.
func TestRenderDomainRoundTrips(t *testing.T) {
	original := &Domain{
		Name: "api", BaseURL: "https://api.example.com",
		Match: []string{"*.example.com"}, LoginProbePath: "/healthz",
		CookieNamePrefix: "CustomCookie", IDPHostnames: []string{"login.example.net"},
		AllowMethods: []string{"GET", "POST"}, TimeoutSeconds: 45,
		LoginTimeoutSeconds: 300, Headers: map[string]string{"X-Client": "albauth"},
	}
	cfg, err := Parse([]byte(RenderDomain(original)), "generated.toml")
	if err != nil {
		t.Fatalf("the rendered domain does not parse: %v", err)
	}
	got := cfg.Domains[0]
	if got.Name != original.Name || got.BaseURL != original.BaseURL ||
		got.LoginProbePath != original.LoginProbePath ||
		got.CookieNamePrefix != original.CookieNamePrefix ||
		got.TimeoutSeconds != original.TimeoutSeconds ||
		got.LoginTimeoutSeconds != original.LoginTimeoutSeconds ||
		got.Headers["X-Client"] != "albauth" ||
		len(got.Match) != 1 || len(got.IDPHostnames) != 1 || len(got.AllowMethods) != 2 {
		t.Fatalf("round trip changed the domain: %+v", got)
	}
}

func TestAddDomainCreatesTheFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "config.toml")
	if err := AddDomain(path, &Domain{Name: "api", BaseURL: "https://api.example.com"}); err != nil {
		t.Fatalf("AddDomain: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if strings.HasPrefix(string(data), "\n") {
		t.Fatalf("a new file should not open with a blank line: %q", string(data))
	}
	if _, err := Parse(data, path); err != nil {
		t.Fatalf("the written config does not parse: %v", err)
	}

	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat: %v", err)
		}
		if perm := info.Mode().Perm(); perm != configFileMode {
			t.Fatalf("config mode = %#o, want %#o", perm, configFileMode)
		}
	}
}

// Appending must not disturb what a user wrote by hand above it.
func TestAddDomainPreservesExistingContent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	original := `# My notes about this file.

[[domain]]
name = "first"
base_url = "https://first.example.com"

[settings]
log_level = "debug"
`
	if err := os.WriteFile(path, []byte(original), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := AddDomain(path, &Domain{Name: "second", BaseURL: "https://second.example.com"}); err != nil {
		t.Fatalf("AddDomain: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	got := string(data)
	if !strings.Contains(got, "# My notes about this file.") {
		t.Fatalf("the comment was lost:\n%s", got)
	}
	if !strings.Contains(got, `log_level = "debug"`) {
		t.Fatalf("the settings block was lost:\n%s", got)
	}
	cfg, err := Parse(data, path)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(cfg.Domains) != 2 {
		t.Fatalf("got %d domains, want 2", len(cfg.Domains))
	}
}

// A change that would produce an unusable config must leave the file alone.
func TestAddDomainRefusesToWriteAnInvalidResult(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := AddDomain(path, &Domain{Name: "api", BaseURL: "https://api.example.com"}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}

	tests := []struct {
		name   string
		domain *Domain
		wantIn string
	}{
		{"duplicate name", &Domain{Name: "api", BaseURL: "https://other.example.com"}, "duplicate name"},
		{"overlapping match", &Domain{Name: "other", BaseURL: "https://other.example.com",
			Match: []string{"*.example.com"}}, "ambiguous routing"},
		{"bad scheme", &Domain{Name: "ftp", BaseURL: "ftp://x.example.com"}, "scheme must be https"},
		{"no base_url", &Domain{Name: "empty"}, "base_url is required"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := AddDomain(path, tc.domain)
			if err == nil {
				t.Fatal("AddDomain should have refused")
			}
			if !strings.Contains(err.Error(), tc.wantIn) {
				t.Fatalf("error = %v, want it to mention %q", err, tc.wantIn)
			}
			after, readErr := os.ReadFile(path)
			if readErr != nil {
				t.Fatalf("read: %v", readErr)
			}
			if string(after) != string(before) {
				t.Fatalf("the file was modified despite the failure:\n%s", after)
			}
		})
	}
}

func TestAddDomainReportsAnUnreadableFile(t *testing.T) {
	// A path whose parent is a regular file cannot be read as one.
	dir := t.TempDir()
	notADir := filepath.Join(dir, "file")
	if err := os.WriteFile(notADir, []byte("x"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	err := AddDomain(filepath.Join(notADir, "config.toml"),
		&Domain{Name: "api", BaseURL: "https://api.example.com"})
	if err == nil {
		t.Fatal("AddDomain should fail when the config cannot be read")
	}
}

func TestAddDomainReportsAnUncreatableDirectory(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX directory permissions are not meaningful on Windows")
	}
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	dir := t.TempDir()
	readOnly := filepath.Join(dir, "readonly")
	if err := os.Mkdir(readOnly, 0o500); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(readOnly, 0o700) })

	err := AddDomain(filepath.Join(readOnly, "nested", "config.toml"),
		&Domain{Name: "api", BaseURL: "https://api.example.com"})
	if err == nil {
		t.Fatal("AddDomain should fail when the directory cannot be created")
	}
}

func TestAddDomainReportsAWriteFailure(t *testing.T) {
	boom := errors.New("disk full")
	orig := writeFileAtomic
	t.Cleanup(func() { writeFileAtomic = orig })
	writeFileAtomic = func(string, []byte, os.FileMode) error { return boom }

	err := AddDomain(filepath.Join(t.TempDir(), "config.toml"),
		&Domain{Name: "api", BaseURL: "https://api.example.com"})
	if !errors.Is(err, boom) {
		t.Fatalf("AddDomain = %v, want the write error", err)
	}
}

func TestWriteFileAtomicLeavesNoTempFileOnRenameFailure(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "config.toml") // the parent does not exist
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	// Renaming onto a directory fails, which drives the cleanup branch.
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := writeFileAtomic(path, []byte("x"), 0o600); err == nil {
		t.Fatal("expected the rename to fail")
	}
	if _, err := os.Stat(path + ".tmp"); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("the temp file should have been cleaned up")
	}
}

func TestWriteFileAtomicReportsACreateFailure(t *testing.T) {
	err := writeFileAtomic(filepath.Join(t.TempDir(), "no-such-dir", "f"), []byte("x"), 0o600)
	if err == nil {
		t.Fatal("expected a create failure")
	}
}
