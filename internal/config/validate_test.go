package config

import (
	"strings"
	"testing"
)

// problemsFor defaults a config the way Parse does, then validates it, so the
// table below exercises the same path a real file takes.
func problemsFor(t *testing.T, toml string) []string {
	t.Helper()
	var cfg Config
	if _, err := decode(toml, &cfg); err != nil {
		t.Fatalf("decode %q: %v", toml, err)
	}
	cfg.applyDefaults()
	return cfg.Validate()
}

func hasProblemContaining(problems []string, needle string) bool {
	for _, p := range problems {
		if strings.Contains(p, needle) {
			return true
		}
	}
	return false
}

// Every rule in the configuration section has a failing-input case here.
func TestValidateRejectsEveryDocumentedMistake(t *testing.T) {
	tests := []struct {
		name   string
		toml   string
		wantIn string
	}{
		{
			name:   "no domains at all",
			toml:   ``,
			wantIn: "no [[domain]] blocks configured",
		},
		{
			name:   "missing name",
			toml:   "[[domain]]\nbase_url = \"https://api.example.com\"",
			wantIn: "name is required",
		},
		{
			name:   "name with capitals",
			toml:   "[[domain]]\nname = \"Internal-API\"\nbase_url = \"https://api.example.com\"",
			wantIn: "name must match",
		},
		{
			name:   "name starting with a punctuation character",
			toml:   "[[domain]]\nname = \"-api\"\nbase_url = \"https://api.example.com\"",
			wantIn: "name must match",
		},
		{
			name: "duplicate names",
			toml: `
[[domain]]
name = "api"
base_url = "https://a.example.com"
[[domain]]
name = "api"
base_url = "https://b.example.com"`,
			wantIn: "duplicate name",
		},
		{
			name:   "missing base_url",
			toml:   "[[domain]]\nname = \"api\"",
			wantIn: "base_url is required",
		},
		{
			name:   "base_url with a trailing slash",
			toml:   "[[domain]]\nname = \"api\"\nbase_url = \"https://api.example.com/\"",
			wantIn: "must not have a trailing slash",
		},
		{
			name:   "unparseable base_url",
			toml:   "[[domain]]\nname = \"api\"\nbase_url = \"https://exa mple.com\"",
			wantIn: "base_url",
		},
		{
			name:   "base_url with no host",
			toml:   "[[domain]]\nname = \"api\"\nbase_url = \"https:///path\"",
			wantIn: "has no host",
		},
		{
			name:   "plain http against a public host",
			toml:   "[[domain]]\nname = \"api\"\nbase_url = \"http://api.example.com\"",
			wantIn: "only allowed for localhost",
		},
		{
			// ".localhost" is only loopback as a suffix, not embedded anywhere.
			name:   "plain http against a host merely containing localhost",
			toml:   "[[domain]]\nname = \"api\"\nbase_url = \"http://localhost.example.com\"",
			wantIn: "only allowed for localhost",
		},
		{
			name:   "a scheme that is neither http nor https",
			toml:   "[[domain]]\nname = \"api\"\nbase_url = \"ftp://api.example.com\"",
			wantIn: "scheme must be https",
		},
		{
			name:   "login_probe_path without a leading slash",
			toml:   "[[domain]]\nname = \"api\"\nbase_url = \"https://api.example.com\"\nlogin_probe_path = \"healthz\"",
			wantIn: "must start with '/'",
		},
		{
			name:   "empty cookie prefix",
			toml:   "[[domain]]\nname = \"api\"\nbase_url = \"https://api.example.com\"\ncookie_name_prefix = \"\"",
			wantIn: "", // the default fills this in, so no problem is expected
		},
		{
			name:   "negative timeout",
			toml:   "[[domain]]\nname = \"api\"\nbase_url = \"https://api.example.com\"\ntimeout_seconds = -1",
			wantIn: "timeout_seconds must be positive",
		},
		{
			name:   "negative login timeout",
			toml:   "[[domain]]\nname = \"api\"\nbase_url = \"https://api.example.com\"\nlogin_timeout_seconds = -5",
			wantIn: "login_timeout_seconds must be positive",
		},
		{
			name:   "unsupported method",
			toml:   "[[domain]]\nname = \"api\"\nbase_url = \"https://api.example.com\"\nallow_methods = [\"GET\", \"TRACE\"]",
			wantIn: "is not a supported HTTP method",
		},
		{
			name:   "match glob that does not compile",
			toml:   "[[domain]]\nname = \"api\"\nbase_url = \"https://api.example.com\"\nmatch = [\"[unclosed\"]",
			wantIn: "is not a valid glob",
		},
		{
			name: "two domains claiming the same host",
			toml: `
[[domain]]
name = "one"
base_url = "https://api.example.com"
[[domain]]
name = "two"
base_url = "https://other.example.com"
match = ["api.example.com"]`,
			wantIn: "ambiguous routing",
		},
		{
			name: "a wildcard that swallows another domain's host",
			toml: `
[[domain]]
name = "one"
base_url = "https://api.example.com"
[[domain]]
name = "two"
base_url = "https://other.example.org"
match = ["*.example.com"]`,
			wantIn: "ambiguous routing",
		},
		{
			name:   "unknown storage backend",
			toml:   "[[domain]]\nname=\"api\"\nbase_url=\"https://api.example.com\"\n[settings]\nstorage = \"magic\"",
			wantIn: "is not one of auto, keyring, file",
		},
		{
			name:   "negative max_response_bytes",
			toml:   "[[domain]]\nname=\"api\"\nbase_url=\"https://api.example.com\"\n[settings]\nmax_response_bytes = -1",
			wantIn: "must not be negative",
		},
		{
			name:   "unknown log level",
			toml:   "[[domain]]\nname=\"api\"\nbase_url=\"https://api.example.com\"\n[settings]\nlog_level = \"chatty\"",
			wantIn: "unknown log level",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			problems := problemsFor(t, tc.toml)
			if tc.wantIn == "" {
				if len(problems) != 0 {
					t.Fatalf("want no problems, got %v", problems)
				}
				return
			}
			if !hasProblemContaining(problems, tc.wantIn) {
				t.Fatalf("want a problem containing %q, got %v", tc.wantIn, problems)
			}
		})
	}
}

func TestValidateAcceptsLoopbackOverPlainHTTP(t *testing.T) {
	// RFC 6761 reserves the whole ".localhost" TLD, so a per-service subdomain
	// is loopback too — the shape local emulators and dev proxies hand out.
	for _, host := range []string{
		"http://localhost:8080", "http://127.0.0.1:8080", "http://[::1]:8080",
		"http://mylb.alb.localhost:4566", "http://API.LOCALHOST:8080",
	} {
		toml := "[[domain]]\nname = \"api\"\nbase_url = \"" + host + "\""
		if problems := problemsFor(t, toml); len(problems) != 0 {
			t.Fatalf("%s should be allowed for local testing, got %v", host, problems)
		}
	}
}

// Acceptance criterion: config validate reports every error at once.
func TestValidateReportsEveryProblemInOnePass(t *testing.T) {
	problems := problemsFor(t, `
[[domain]]
name = "BAD NAME"
base_url = "ftp://api.example.com/"
allow_methods = ["TRACE"]
timeout_seconds = -1
[settings]
storage = "magic"
log_level = "chatty"`)

	if len(problems) < 6 {
		t.Fatalf("want every problem reported in one pass, got only %d: %v", len(problems), problems)
	}
	for _, needle := range []string{
		"name must match", "scheme must be https", "trailing slash",
		"not a supported HTTP method", "timeout_seconds must be positive",
		"is not one of auto, keyring, file", "unknown log level",
	} {
		if !hasProblemContaining(problems, needle) {
			t.Fatalf("missing a problem about %q in %v", needle, problems)
		}
	}
}

func TestValidateAllowsTheSameDomainToClaimOverlappingPatterns(t *testing.T) {
	// Overlap within one domain is not ambiguous — it still routes one way.
	problems := problemsFor(t, `
[[domain]]
name = "api"
base_url = "https://api.example.com"
match = ["api.example.com", "*.example.com"]`)
	if hasProblemContaining(problems, "ambiguous routing") {
		t.Fatalf("a single domain may claim overlapping patterns, got %v", problems)
	}
}

func TestValidateLabelsAnUnnamedDomainByIndex(t *testing.T) {
	problems := problemsFor(t, "[[domain]]\nbase_url = \"ftp://api.example.com\"")
	if !hasProblemContaining(problems, "domain[0]") {
		t.Fatalf("an unnamed domain should be labelled by index, got %v", problems)
	}
}

func TestPatternsOverlap(t *testing.T) {
	tests := []struct {
		a, b string
		want bool
	}{
		{"api.example.com", "api.example.com", true},
		{"*.example.com", "api.example.com", true},
		{"api.example.com", "*.example.com", true},
		{"*.example.com", "*.example.com", true},
		{"api.example.com", "admin.example.com", false},
		{"*.example.com", "*.example.org", false},
		{"?pi.example.com", "api.example.com", true}, // '?' matches the single leading character
		{"??.example.com", "api.example.com", false}, // two characters cannot cover three
	}
	for _, tc := range tests {
		if got := patternsOverlap(tc.a, tc.b); got != tc.want {
			t.Fatalf("patternsOverlap(%q, %q) = %v, want %v", tc.a, tc.b, got, tc.want)
		}
	}
}

func TestGlobCoversHandlesABadPattern(t *testing.T) {
	if globCovers("[unclosed", "api.example.com") {
		t.Fatal("a pattern that does not compile cannot cover anything")
	}
}

func TestDomainHelpers(t *testing.T) {
	d := &Domain{
		BaseURL:      "https://api.example.com",
		Match:        []string{"api.example.com", "*.internal.example.com"},
		AllowMethods: []string{"GET", "POST"},
		IDPHostnames: []string{"login.example.net"},
	}

	t.Run("MatchHost", func(t *testing.T) {
		for host, want := range map[string]bool{
			"api.example.com":        true,
			"API.EXAMPLE.COM":        true, // hosts are case-insensitive
			"a.internal.example.com": true,
			"admin.example.com":      false,
		} {
			if got := d.MatchHost(host); got != want {
				t.Fatalf("MatchHost(%q) = %v, want %v", host, got, want)
			}
		}
		bad := &Domain{Match: []string{"[unclosed"}}
		if bad.MatchHost("anything") {
			t.Fatal("a pattern that does not compile must not match")
		}
	})

	t.Run("MethodAllowed", func(t *testing.T) {
		for method, want := range map[string]bool{
			"GET": true, "get": true, "POST": true, "DELETE": false,
		} {
			if got := d.MethodAllowed(method); got != want {
				t.Fatalf("MethodAllowed(%q) = %v, want %v", method, got, want)
			}
		}
	})

	t.Run("IsIDPHost", func(t *testing.T) {
		if !d.IsIDPHost("LOGIN.EXAMPLE.NET") {
			t.Fatal("identity provider hosts are compared case-insensitively")
		}
		if d.IsIDPHost("api.example.com") {
			t.Fatal("the API host is not an identity provider")
		}
	})

	t.Run("BaseHost", func(t *testing.T) {
		if got := d.BaseHost(); got != "api.example.com" {
			t.Fatalf("BaseHost() = %q", got)
		}
		bad := &Domain{BaseURL: "https://exa mple.com"}
		if got := bad.BaseHost(); got != "" {
			t.Fatalf("BaseHost() on an invalid URL = %q, want \"\"", got)
		}
	})
}

func TestParseRejectsASemanticallyInvalidConfig(t *testing.T) {
	_, err := Parse([]byte("[[domain]]\nname = \"api\"\nbase_url = \"ftp://api.example.com\""), "bad.toml")
	cfgErr, ok := configError(err)
	if !ok {
		t.Fatalf("Parse = %v, want a *config.Error", err)
	}
	if !hasProblemContaining(cfgErr.Problems, "scheme must be https") {
		t.Fatalf("problems = %v", cfgErr.Problems)
	}
}

// Validate is exported and may be called on a Config assembled in code rather
// than parsed from a file, where the defaults have not been applied.
func TestValidateRejectsAnEmptyCookiePrefixOnAHandBuiltConfig(t *testing.T) {
	cfg := &Config{
		Settings: Settings{Storage: StorageAuto, LogLevel: DefaultLogLevel},
		Domains: []Domain{{
			Name: "api", BaseURL: "https://api.example.com",
			LoginProbePath: "/", CookieNamePrefix: "",
			TimeoutSeconds: 30, LoginTimeoutSeconds: 180,
			AllowMethods: []string{"GET"},
		}},
	}
	if !hasProblemContaining(cfg.Validate(), "cookie_name_prefix must not be empty") {
		t.Fatalf("problems = %v", cfg.Validate())
	}
}
