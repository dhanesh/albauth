package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const validConfig = `
[[domain]]
name = "internal-api"
base_url = "https://api.example.com"
match = ["api.example.com", "*.internal.example.com"]
login_probe_path = "/healthz"
idp_hostnames = ["login.example.net"]
allow_methods = ["GET", "post"]
timeout_seconds = 15
login_timeout_seconds = 60

[domain.headers]
"X-Client" = "albmcp"

[[domain]]
name = "admin-console"
base_url = "https://admin.example.com"

[settings]
storage = "file"
max_response_bytes = 2048
log_level = "debug"
`

func TestParseAppliesDocumentedValues(t *testing.T) {
	cfg, err := Parse([]byte(validConfig), "test.toml")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cfg.Path != "test.toml" {
		t.Fatalf("Path = %q", cfg.Path)
	}
	if len(cfg.Domains) != 2 {
		t.Fatalf("got %d domains, want 2", len(cfg.Domains))
	}

	api := cfg.Domains[0]
	if api.LoginProbePath != "/healthz" || api.TimeoutSeconds != 15 || api.LoginTimeoutSeconds != 60 {
		t.Fatalf("explicit values were not preserved: %+v", api)
	}
	if api.Headers["X-Client"] != "albmcp" {
		t.Fatalf("headers = %v", api.Headers)
	}
	// allow_methods is normalised to upper case so comparisons are exact.
	if api.AllowMethods[1] != "POST" {
		t.Fatalf("allow_methods = %v, want POST to be upper-cased", api.AllowMethods)
	}
	if cfg.Settings.Storage != "file" || cfg.Settings.MaxResponseBytes != 2048 || cfg.Settings.LogLevel != "debug" {
		t.Fatalf("settings = %+v", cfg.Settings)
	}
}

func TestParseAppliesDefaults(t *testing.T) {
	cfg, err := Parse([]byte(`
[[domain]]
name = "api"
base_url = "https://api.example.com"
`), "test.toml")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	d := cfg.Domains[0]
	if d.LoginProbePath != DefaultLoginProbePath {
		t.Fatalf("login_probe_path = %q, want %q", d.LoginProbePath, DefaultLoginProbePath)
	}
	if d.CookieNamePrefix != DefaultCookieNamePrefix {
		t.Fatalf("cookie_name_prefix = %q", d.CookieNamePrefix)
	}
	if d.TimeoutSeconds != DefaultTimeoutSeconds || d.LoginTimeoutSeconds != DefaultLoginTimeoutSecs {
		t.Fatalf("timeouts = %d, %d", d.TimeoutSeconds, d.LoginTimeoutSeconds)
	}
	// Writes must be opted into explicitly: the default fails closed at GET.
	if len(d.AllowMethods) != 1 || d.AllowMethods[0] != "GET" {
		t.Fatalf("allow_methods = %v, want [GET]", d.AllowMethods)
	}
	// match defaults to the base_url host.
	if len(d.Match) != 1 || d.Match[0] != "api.example.com" {
		t.Fatalf("match = %v", d.Match)
	}
	if cfg.Settings.Storage != DefaultStorage ||
		cfg.Settings.MaxResponseBytes != DefaultMaxResponseBytes ||
		cfg.Settings.LogLevel != DefaultLogLevel {
		t.Fatalf("settings defaults = %+v", cfg.Settings)
	}
}

func TestParseRejectsMalformedTOML(t *testing.T) {
	_, err := Parse([]byte("[[domain]\nname = "), "bad.toml")
	cfgErr, ok := configError(err)
	if !ok {
		t.Fatalf("Parse = %v, want a *config.Error", err)
	}
	if len(cfgErr.Problems) != 1 || !strings.Contains(cfgErr.Problems[0], "parse error") {
		t.Fatalf("problems = %v", cfgErr.Problems)
	}
}

func TestLoad(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, []byte(validConfig), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(cfg.Domains) != 2 {
		t.Fatalf("got %d domains", len(cfg.Domains))
	}

	if _, err := Load(filepath.Join(t.TempDir(), "absent.toml")); err == nil {
		t.Fatal("Load should fail for a missing file")
	}
}

func TestLookupAndDomainNames(t *testing.T) {
	cfg, err := Parse([]byte(validConfig), "test.toml")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if d, ok := cfg.Lookup("admin-console"); !ok || d.BaseURL != "https://admin.example.com" {
		t.Fatalf("Lookup(admin-console) = %v, %v", d, ok)
	}
	if _, ok := cfg.Lookup("nope"); ok {
		t.Fatal("Lookup should report a miss")
	}
	names := cfg.DomainNames()
	if len(names) != 2 || names[0] != "internal-api" || names[1] != "admin-console" {
		t.Fatalf("DomainNames() = %v, want file order", names)
	}
	empty := &Config{}
	if got := empty.DomainNames(); len(got) != 0 {
		t.Fatalf("DomainNames() on an empty config = %v", got)
	}
}

func TestErrorMessageListsEveryProblem(t *testing.T) {
	err := &Error{Path: "c.toml", Problems: []string{"first thing", "second thing"}}
	msg := err.Error()
	for _, needle := range []string{"c.toml", "2 problem(s)", "first thing", "second thing"} {
		if !strings.Contains(msg, needle) {
			t.Fatalf("error message is missing %q: %s", needle, msg)
		}
	}
}
