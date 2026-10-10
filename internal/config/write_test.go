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

func TestRenderDomainWritesTreat401AsExpired(t *testing.T) {
	off := RenderDomain(&Domain{Name: "api", BaseURL: "https://api.example.com"})
	if strings.Contains(off, "treat_401_as_expired") {
		t.Fatalf("the default should not be written out:\n%s", off)
	}
	on := RenderDomain(&Domain{Name: "api", BaseURL: "https://api.example.com",
		Treat401AsExpired: true})
	if !strings.Contains(on, "treat_401_as_expired = true") {
		t.Fatalf("the opt-in must be written out:\n%s", on)
	}
	cfg, err := Parse([]byte(on), "generated.toml")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !cfg.Domains[0].Treat401AsExpired {
		t.Fatal("the flag did not survive a round trip")
	}
}

func TestRemoveDomain(t *testing.T) {
	write := func(t *testing.T, body string) string {
		t.Helper()
		path := filepath.Join(t.TempDir(), "config.toml")
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
		return path
	}

	t.Run("takes the headers sub-table with it and keeps everything else", func(t *testing.T) {
		path := write(t, `# A note that must survive.

[[domain]]
name = "keep"
base_url = "https://keep.example.com"

[[domain]]
name = "drop"
base_url = "https://drop.example.com"

[domain.headers]
"X-API-KEY" = "secret"

[settings]
log_level = "debug"
`)
		if err := RemoveDomain(path, "drop"); err != nil {
			t.Fatalf("RemoveDomain: %v", err)
		}
		data, _ := os.ReadFile(path)
		got := string(data)
		for _, gone := range []string{"drop", "X-API-KEY", "secret"} {
			if strings.Contains(got, gone) {
				t.Fatalf("%q survived removal:\n%s", gone, got)
			}
		}
		for _, kept := range []string{"# A note that must survive.", "keep", `log_level = "debug"`} {
			if !strings.Contains(got, kept) {
				t.Fatalf("%q was lost:\n%s", kept, got)
			}
		}
		cfg, err := Parse(data, path)
		if err != nil {
			t.Fatalf("result does not parse: %v", err)
		}
		if len(cfg.Domains) != 1 || cfg.Domains[0].Name != "keep" {
			t.Fatalf("domains = %+v", cfg.Domains)
		}
	})

	t.Run("removes a block followed directly by another domain", func(t *testing.T) {
		path := write(t, `[[domain]]
name = "first"
base_url = "https://a.example.com"

[[domain]]
name = "middle"
base_url = "https://b.example.com"

[[domain]]
name = "third"
base_url = "https://c.example.com"
`)
		if err := RemoveDomain(path, "first"); err != nil {
			t.Fatalf("RemoveDomain: %v", err)
		}
		data, _ := os.ReadFile(path)
		cfg, err := Parse(data, path)
		if err != nil {
			t.Fatalf("result does not parse: %v\n%s", err, data)
		}
		if len(cfg.Domains) != 2 || cfg.Domains[0].Name != "middle" || cfg.Domains[1].Name != "third" {
			t.Fatalf("domains = %+v", cfg.Domains)
		}
	})

	t.Run("removes the last block when it is last in the file", func(t *testing.T) {
		path := write(t, `[[domain]]
name = "first"
base_url = "https://a.example.com"

[[domain]]
name = "last"
base_url = "https://b.example.com"
`)
		if err := RemoveDomain(path, "last"); err != nil {
			t.Fatalf("RemoveDomain: %v", err)
		}
		data, _ := os.ReadFile(path)
		if strings.Contains(string(data), "last") {
			t.Fatalf("not removed:\n%s", data)
		}
	})

	t.Run("reports an unknown name without touching the file", func(t *testing.T) {
		path := write(t, "[[domain]]\nname = \"a\"\nbase_url = \"https://a.example.com\"\n")
		before, _ := os.ReadFile(path)
		err := RemoveDomain(path, "nope")
		if err == nil || !strings.Contains(err.Error(), `no domain named "nope"`) {
			t.Fatalf("err = %v", err)
		}
		after, _ := os.ReadFile(path)
		if string(after) != string(before) {
			t.Fatal("the file was modified")
		}
	})

	t.Run("refuses to leave a config with no domains", func(t *testing.T) {
		path := write(t, "[[domain]]\nname = \"only\"\nbase_url = \"https://a.example.com\"\n")
		before, _ := os.ReadFile(path)
		if err := RemoveDomain(path, "only"); err == nil {
			t.Fatal("removing the only domain should fail")
		}
		after, _ := os.ReadFile(path)
		if string(after) != string(before) {
			t.Fatal("the file was modified despite the failure")
		}
	})

	t.Run("reports a missing file", func(t *testing.T) {
		if err := RemoveDomain(filepath.Join(t.TempDir(), "absent.toml"), "a"); err == nil {
			t.Fatal("expected a read failure")
		}
	})

	t.Run("reports a write failure", func(t *testing.T) {
		path := write(t, `[[domain]]
name = "a"
base_url = "https://a.example.com"

[[domain]]
name = "b"
base_url = "https://b.example.com"
`)
		boom := errors.New("disk full")
		orig := writeFileAtomic
		t.Cleanup(func() { writeFileAtomic = orig })
		writeFileAtomic = func(string, []byte, os.FileMode) error { return boom }
		if err := RemoveDomain(path, "b"); !errors.Is(err, boom) {
			t.Fatalf("err = %v", err)
		}
	})
}

func TestBlockNameStopsAtTheBlockBoundary(t *testing.T) {
	// A block with no name of its own must not borrow the next block's.
	if got := blockName([]string{"[[domain]]", "base_url = \"x\"", "[[domain]]", `name = "next"`}); got != "" {
		t.Fatalf("blockName = %q, want empty", got)
	}
	if got := blockName([]string{"[[domain]]", "base_url = \"x\"", "[settings]", `name = "no"`}); got != "" {
		t.Fatalf("blockName = %q, want empty", got)
	}
	if got := blockName([]string{"[[domain]]", `  name = "spaced"  `}); got != "spaced" {
		t.Fatalf("blockName = %q", got)
	}
	if got := blockName([]string{"[[domain]]", "namespace = \"not-name\"", `name = 'single'`}); got != "single" {
		t.Fatalf("blockName = %q", got)
	}
	if got := blockName([]string{"[[domain]]", "name"}); got != "" {
		t.Fatalf("blockName on a malformed line = %q", got)
	}
}

func TestRenderDomainWritesSessionCheckPath(t *testing.T) {
	off := RenderDomain(&Domain{Name: "api", BaseURL: "https://api.example.com"})
	if strings.Contains(off, "session_check_path") {
		t.Fatalf("an unset session_check_path should not be written out:\n%s", off)
	}
	on := RenderDomain(&Domain{Name: "api", BaseURL: "https://api.example.com",
		SessionCheckPath: "/oauth2/auth"})
	if !strings.Contains(on, `session_check_path = "/oauth2/auth"`) {
		t.Fatalf("session_check_path must be written out:\n%s", on)
	}
	cfg, err := Parse([]byte(on), "generated.toml")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if cfg.Domains[0].SessionCheckPath != "/oauth2/auth" {
		t.Fatalf("session_check_path did not survive a round trip: %+v", cfg.Domains[0])
	}
}
