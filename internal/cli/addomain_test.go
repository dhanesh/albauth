package cli

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"albauth/internal/config"
)

// stubProbe replaces the network probe for the duration of a test.
func stubProbe(t *testing.T, host string, err error) *int {
	t.Helper()
	calls := 0
	orig := probeIDPHost
	t.Cleanup(func() { probeIDPHost = orig })
	probeIDPHost = func(string, string, time.Duration) (string, error) {
		calls++
		return host, err
	}
	return &calls
}

// addFixture is a CLI fixture whose config file starts absent.
func addFixture(t *testing.T) (*fixture, string) {
	t.Helper()
	f := newFixture(t, "")
	path := filepath.Join(t.TempDir(), "new-config.toml")
	if err := os.Remove(f.configPath); err != nil {
		t.Fatalf("remove: %v", err)
	}
	f.configPath = path
	base := f.env.Getenv
	f.env.Getenv = func(k string) string {
		if k == "ALBAUTH_CONFIG" {
			return path
		}
		return base(k)
	}
	return f, path
}

func TestConfigAddDomainCreatesAConfig(t *testing.T) {
	f, path := addFixture(t)
	calls := stubProbe(t, "", errors.New("unreachable"))

	code := f.run(t, "config", "add-domain", "internal-api",
		"--base-url", "https://api.example.com", "--no-probe")
	if code != 0 {
		t.Fatalf("exit code = %d: %s", code, f.err())
	}
	if *calls != 0 {
		t.Fatalf("--no-probe should not contact the domain, got %d calls", *calls)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	cfg, err := config.Parse(data, path)
	if err != nil {
		t.Fatalf("the written config does not parse: %v", err)
	}
	if len(cfg.Domains) != 1 || cfg.Domains[0].Name != "internal-api" {
		t.Fatalf("domains = %+v", cfg.Domains)
	}
	if !strings.Contains(f.out(), "added domain \"internal-api\"") {
		t.Fatalf("stdout = %q", f.out())
	}
	// A read-only domain should say so, since that is the default and the
	// most common surprise.
	if !strings.Contains(f.out(), "read-only") {
		t.Fatalf("stdout should mention the domain is read-only: %q", f.out())
	}
}

func TestConfigAddDomainAcceptsEveryFlag(t *testing.T) {
	f, path := addFixture(t)
	stubProbe(t, "", errors.New("not called"))

	code := f.run(t, "config", "add-domain", "admin",
		"--base-url", "https://admin.example.com/",
		"--match", "admin.example.com", "--match", "*.admin.example.com",
		"--idp-hostname", "login.example.net",
		"--login-probe-path", "/healthz",
		"--cookie-prefix", "CustomCookie",
		"--allow-method", "get", "--allow-method", "post",
		"--timeout-seconds", "45", "--login-timeout-seconds", "300",
		"--header", "X-Client=albauth", "--header", "X-Tenant= eng ")
	if code != 0 {
		t.Fatalf("exit code = %d: %s", code, f.err())
	}

	data, _ := os.ReadFile(path)
	cfg, err := config.Parse(data, path)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	d := cfg.Domains[0]
	if d.BaseURL != "https://admin.example.com" {
		t.Fatalf("a trailing slash should be trimmed, got %q", d.BaseURL)
	}
	if len(d.Match) != 2 || d.LoginProbePath != "/healthz" || d.CookieNamePrefix != "CustomCookie" {
		t.Fatalf("domain = %+v", d)
	}
	if len(d.AllowMethods) != 2 || d.AllowMethods[0] != "GET" || d.AllowMethods[1] != "POST" {
		t.Fatalf("methods should be upper-cased: %v", d.AllowMethods)
	}
	if d.TimeoutSeconds != 45 || d.LoginTimeoutSeconds != 300 {
		t.Fatalf("timeouts = %d, %d", d.TimeoutSeconds, d.LoginTimeoutSeconds)
	}
	if d.Headers["X-Client"] != "albauth" || d.Headers["X-Tenant"] != "eng" {
		t.Fatalf("headers = %v (values should be trimmed)", d.Headers)
	}
	// Writes were opted into, so the read-only notice must not appear.
	if strings.Contains(f.out(), "read-only") {
		t.Fatalf("stdout should not call this read-only: %q", f.out())
	}
}

func TestConfigAddDomainProbesForTheIdentityProvider(t *testing.T) {
	f, path := addFixture(t)
	calls := stubProbe(t, "login.example.net", nil)

	if code := f.run(t, "config", "add-domain", "api",
		"--base-url", "https://api.example.com"); code != 0 {
		t.Fatalf("exit code = %d: %s", code, f.err())
	}
	if *calls != 1 {
		t.Fatalf("probe called %d times, want 1", *calls)
	}

	data, _ := os.ReadFile(path)
	cfg, _ := config.Parse(data, path)
	if len(cfg.Domains[0].IDPHostnames) != 1 || cfg.Domains[0].IDPHostnames[0] != "login.example.net" {
		t.Fatalf("the probed host was not recorded: %+v", cfg.Domains[0].IDPHostnames)
	}
	if !strings.Contains(f.err(), "detected identity provider: login.example.net") {
		t.Fatalf("stderr = %q", f.err())
	}
}

// The probe is a convenience, not a requirement: a domain unreachable from
// here must still be addable.
func TestConfigAddDomainSurvivesAFailedProbe(t *testing.T) {
	f, path := addFixture(t)
	stubProbe(t, "", errors.New("dial tcp: connection refused"))

	if code := f.run(t, "config", "add-domain", "api",
		"--base-url", "https://api.example.com"); code != 0 {
		t.Fatalf("a failed probe must not fail the command: %d %s", code, f.err())
	}
	if !strings.Contains(f.err(), "could not detect it") {
		t.Fatalf("stderr should explain the probe failed: %q", f.err())
	}
	data, _ := os.ReadFile(path)
	cfg, err := config.Parse(data, path)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(cfg.Domains[0].IDPHostnames) != 0 {
		t.Fatalf("no identity provider should have been recorded: %+v", cfg.Domains[0])
	}
}

func TestConfigAddDomainSkipsTheProbeWhenTheHostIsGiven(t *testing.T) {
	f, _ := addFixture(t)
	calls := stubProbe(t, "should-not-be-used", nil)

	if code := f.run(t, "config", "add-domain", "api",
		"--base-url", "https://api.example.com",
		"--idp-hostname", "login.example.net"); code != 0 {
		t.Fatalf("exit code = %d: %s", code, f.err())
	}
	if *calls != 0 {
		t.Fatalf("probe ran %d times despite an explicit --idp-hostname", *calls)
	}
}

func TestConfigAddDomainArgumentErrors(t *testing.T) {
	tests := []struct {
		name   string
		args   []string
		wantIn string
	}{
		{"no name", []string{"config", "add-domain"}, "needs a domain name"},
		{"flags before the name", []string{"config", "add-domain", "--base-url", "https://a.example.com"},
			"needs a domain name before its flags"},
		{"no base-url", []string{"config", "add-domain", "api"}, "needs --base-url"},
		{"trailing argument", []string{"config", "add-domain", "api", "--base-url", "https://a.example.com", "extra"},
			"unexpected argument"},
		{"malformed header", []string{"config", "add-domain", "api", "--base-url", "https://a.example.com",
			"--header", "novalue", "--no-probe"}, "is not NAME=VALUE"},
		{"empty header name", []string{"config", "add-domain", "api", "--base-url", "https://a.example.com",
			"--header", "=v", "--no-probe"}, "is not NAME=VALUE"},
		{"unknown flag", []string{"config", "add-domain", "api", "--nope"}, ""},
		{"empty repeatable value", []string{"config", "add-domain", "api",
			"--base-url", "https://a.example.com", "--match", "", "--no-probe"}, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f, _ := addFixture(t)
			stubProbe(t, "", errors.New("not called"))
			code := f.run(t, tc.args...)
			if code == 0 {
				t.Fatalf("%v should not succeed", tc.args)
			}
			if tc.wantIn != "" && !strings.Contains(f.err(), tc.wantIn) {
				t.Fatalf("stderr = %q, want it to mention %q", f.err(), tc.wantIn)
			}
		})
	}
}

func TestConfigAddDomainReportsAnInvalidResult(t *testing.T) {
	f, path := addFixture(t)
	stubProbe(t, "", errors.New("not called"))

	if code := f.run(t, "config", "add-domain", "api",
		"--base-url", "https://api.example.com", "--no-probe"); code != 0 {
		t.Fatalf("seed failed: %s", f.err())
	}
	before, _ := os.ReadFile(path)
	f.stderr.Reset()

	if code := f.run(t, "config", "add-domain", "api",
		"--base-url", "https://other.example.com", "--no-probe"); code != 1 {
		t.Fatalf("a duplicate name should fail, got %d", code)
	}
	if !strings.Contains(f.err(), "duplicate name") {
		t.Fatalf("stderr = %q", f.err())
	}
	after, _ := os.ReadFile(path)
	if string(after) != string(before) {
		t.Fatal("the config was modified despite the failure")
	}
}

func TestConfigAddDomainReportsAPathFailure(t *testing.T) {
	f, _ := addFixture(t)
	stubProbe(t, "", errors.New("not called"))
	orig := configResolvePath
	t.Cleanup(func() { configResolvePath = orig })
	configResolvePath = func(string, func(string) string) (string, error) {
		return "", fmt.Errorf("cannot determine config directory")
	}

	if code := f.run(t, "config", "add-domain", "api",
		"--base-url", "https://api.example.com", "--no-probe"); code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
}

func TestConfigAddDomainReportsAWriteFailure(t *testing.T) {
	f, _ := addFixture(t)
	stubProbe(t, "", errors.New("not called"))
	orig := configAddDomain
	t.Cleanup(func() { configAddDomain = orig })
	configAddDomain = func(string, *config.Domain) error { return errors.New("disk full") }

	if code := f.run(t, "config", "add-domain", "api",
		"--base-url", "https://api.example.com", "--no-probe"); code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	if !strings.Contains(f.err(), "disk full") {
		t.Fatalf("stderr = %q", f.err())
	}
}

// --- the probe itself -------------------------------------------------------

func TestDetectIDPHost(t *testing.T) {
	t.Run("reads the host from the redirect", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Location", "https://login.example.net/authorize?client_id=x")
			w.WriteHeader(http.StatusFound)
		}))
		t.Cleanup(srv.Close)

		host, err := detectIDPHost(srv.URL, "/healthz", 5*time.Second)
		if err != nil || host != "login.example.net" {
			t.Fatalf("detectIDPHost = %q, %v", host, err)
		}
	})

	t.Run("accepts a 303 as well", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Location", "https://login.example.net/authorize")
			w.WriteHeader(http.StatusSeeOther)
		}))
		t.Cleanup(srv.Close)
		if host, err := detectIDPHost(srv.URL, "/", 5*time.Second); err != nil || host != "login.example.net" {
			t.Fatalf("detectIDPHost = %q, %v", host, err)
		}
	})

	t.Run("a 200 means the path is not behind the rule", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		t.Cleanup(srv.Close)
		_, err := detectIDPHost(srv.URL, "/healthz", 5*time.Second)
		if err == nil || !strings.Contains(err.Error(), "rather than redirecting") {
			t.Fatalf("err = %v", err)
		}
	})

	t.Run("a redirect with no Location is unusable", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusFound)
		}))
		t.Cleanup(srv.Close)
		if _, err := detectIDPHost(srv.URL, "/", 5*time.Second); err == nil {
			t.Fatal("expected a failure")
		}
	})

	t.Run("a same-host redirect is not an identity provider", func(t *testing.T) {
		var srv *httptest.Server
		srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Location", srv.URL+"/login")
			w.WriteHeader(http.StatusFound)
		}))
		t.Cleanup(srv.Close)
		_, err := detectIDPHost(srv.URL, "/", 5*time.Second)
		if err == nil || !strings.Contains(err.Error(), "redirected to itself") {
			t.Fatalf("err = %v", err)
		}
	})

	t.Run("an unreachable host fails", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
		url := srv.URL
		srv.Close()
		if _, err := detectIDPHost(url, "/", 2*time.Second); err == nil {
			t.Fatal("expected a connection failure")
		}
	})

	t.Run("an unbuildable request fails", func(t *testing.T) {
		if _, err := detectIDPHost("http://exa mple.com", "/", time.Second); err == nil {
			t.Fatal("expected a request-construction failure")
		}
	})
}

func TestHostOf(t *testing.T) {
	if got := hostOf("https://api.example.com:8443/x"); got != "api.example.com:8443" {
		t.Fatalf("hostOf = %q", got)
	}
	if got := hostOf("://nonsense"); got != "" {
		t.Fatalf("hostOf on an invalid URL = %q, want empty", got)
	}
}

func TestStringListFlag(t *testing.T) {
	var list stringList
	if err := list.Set("a"); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if err := list.Set("b"); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if got := list.String(); got != "a,b" {
		t.Fatalf("String() = %q", got)
	}
	if err := list.Set(""); err == nil {
		t.Fatal("an empty value should be rejected")
	}
}

func TestUpperAllAndReadOnlyDetection(t *testing.T) {
	if got := upperAll(nil); got != nil {
		t.Fatalf("upperAll(nil) = %v", got)
	}
	if got := upperAll([]string{" get ", "Post"}); got[0] != "GET" || got[1] != "POST" {
		t.Fatalf("upperAll = %v", got)
	}
	for methods, want := range map[*[]string]bool{
		{}:                         true,
		{"GET"}:                    true,
		{"GET", "HEAD", "OPTIONS"}: true,
		{"GET", "POST"}:            false,
		{"DELETE"}:                 false,
	} {
		if got := allowMethodsAreReadOnly(*methods); got != want {
			t.Fatalf("allowMethodsAreReadOnly(%v) = %v, want %v", *methods, got, want)
		}
	}
}

func TestConfigAddDomainTreat401Flag(t *testing.T) {
	f, path := addFixture(t)
	stubProbe(t, "", errors.New("not called"))

	if code := f.run(t, "config", "add-domain", "api",
		"--base-url", "https://api.example.com", "--no-probe",
		"--treat-401-as-expired"); code != 0 {
		t.Fatalf("exit code = %d: %s", code, f.err())
	}
	data, _ := os.ReadFile(path)
	cfg, err := config.Parse(data, path)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !cfg.Domains[0].Treat401AsExpired {
		t.Fatal("--treat-401-as-expired was not recorded")
	}
}
