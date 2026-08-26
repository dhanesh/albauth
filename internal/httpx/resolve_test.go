package httpx

import (
	"errors"
	"strings"
	"testing"

	"albauth/internal/auth"
	"albauth/internal/config"
)

func testConfig() *config.Config {
	return &config.Config{
		Domains: []config.Domain{
			{
				Name: "internal-api", BaseURL: "https://api.example.com",
				Match:        []string{"api.example.com", "*.internal.example.com"},
				AllowMethods: []string{"GET", "POST"},
			},
			{
				Name: "admin-console", BaseURL: "https://admin.example.com",
				Match: []string{"admin.example.com"}, AllowMethods: []string{"GET"},
			},
		},
	}
}

func assertCode(t *testing.T, err error, want string) {
	t.Helper()
	coded, ok := errors.AsType[*auth.Error](err)
	if !ok {
		t.Fatalf("error %v is not a coded *auth.Error", err)
	}
	if coded.Code != want {
		t.Fatalf("error code = %q, want %q (%v)", coded.Code, want, err)
	}
}

func TestResolve(t *testing.T) {
	cfg := testConfig()

	tests := []struct {
		name       string
		url        string
		domain     string
		method     string
		wantDomain string
		wantURL    string
	}{
		{"an absolute URL routes by host", "https://api.example.com/v1/users", "", "GET",
			"internal-api", "https://api.example.com/v1/users"},
		{"a wildcard match pattern routes too", "https://x.internal.example.com/v1/health", "", "GET",
			"internal-api", "https://x.internal.example.com/v1/health"},
		{"a relative URL joins onto base_url", "/v1/users", "internal-api", "GET",
			"internal-api", "https://api.example.com/v1/users"},
		{"a relative URL without a leading slash still joins cleanly", "v1/users", "internal-api", "GET",
			"internal-api", "https://api.example.com/v1/users"},
		{"an absolute URL plus a matching domain is fine", "https://api.example.com/v1/users", "internal-api", "GET",
			"internal-api", "https://api.example.com/v1/users"},
		{"the method defaults to GET", "https://api.example.com/v1/users", "", "",
			"internal-api", "https://api.example.com/v1/users"},
		{"the method is upper-cased before the allow-list check", "https://api.example.com/v1/users", "", "post",
			"internal-api", "https://api.example.com/v1/users"},
		{"query strings on the URL survive", "https://api.example.com/v1/users?a=1", "", "GET",
			"internal-api", "https://api.example.com/v1/users?a=1"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d, target, err := Resolve(cfg, tc.url, tc.domain, tc.method)
			if err != nil {
				t.Fatalf("Resolve: %v", err)
			}
			if d.Name != tc.wantDomain {
				t.Fatalf("domain = %q, want %q", d.Name, tc.wantDomain)
			}
			if target != tc.wantURL {
				t.Fatalf("url = %q, want %q", target, tc.wantURL)
			}
		})
	}
}

func TestResolveErrors(t *testing.T) {
	cfg := testConfig()

	tests := []struct {
		name     string
		url      string
		domain   string
		method   string
		wantCode string
		wantHint string
	}{
		{"no url at all", "", "", "GET", auth.CodeInvalidRequest, ""},
		{"blank url", "   ", "", "GET", auth.CodeInvalidRequest, ""},
		{"a host no domain claims", "https://other.example.org/v1", "", "GET",
			auth.CodeUnknownDomain, "internal-api, admin-console"},
		{"an unparseable absolute url", "https://exa mple.com/x", "", "GET", auth.CodeInvalidRequest, ""},
		{"url and domain disagree", "https://api.example.com/v1", "admin-console", "GET",
			auth.CodeDomainMismatch, ""},
		{"a relative url with no domain", "/v1/users", "", "GET", auth.CodeInvalidRequest, ""},
		{"a relative url naming an unknown domain", "/v1/users", "nope", "GET", auth.CodeUnknownDomain, ""},
		{"a method the domain does not allow", "https://api.example.com/v1", "", "DELETE",
			auth.CodeMethodNotAllowed, "allow_methods"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := Resolve(cfg, tc.url, tc.domain, tc.method)
			assertCode(t, err, tc.wantCode)
			if tc.wantHint != "" && !strings.Contains(err.Error(), tc.wantHint) {
				t.Fatalf("error should mention %q, got: %v", tc.wantHint, err)
			}
		})
	}
}

// Writes must be opted into per domain: a method missing from allow_methods is
// refused before any request is issued.
func TestResolveFailsClosedOnMethods(t *testing.T) {
	cfg := testConfig()
	for _, method := range []string{"PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"} {
		if _, _, err := Resolve(cfg, "https://api.example.com/v1", "", method); err == nil {
			t.Fatalf("%s should be refused for a domain that only allows GET and POST", method)
		}
	}
	if _, _, err := Resolve(cfg, "https://admin.example.com/v1", "", "POST"); err == nil {
		t.Fatal("POST should be refused for a GET-only domain")
	}
}

// With nothing configured, the agent asking for a domain by name is not a typo
// — it is a user who has not set albauth up yet, and the hint has to say so.
func TestResolveGuidesAUserWithNothingConfigured(t *testing.T) {
	empty := &config.Config{}
	_, _, err := Resolve(empty, "/v1/users", "anything", "GET")
	assertCode(t, err, auth.CodeUnknownDomain)
	if !strings.Contains(err.Error(), "config add-domain") {
		t.Fatalf("error should tell the user how to add a domain, got: %v", err)
	}
}
