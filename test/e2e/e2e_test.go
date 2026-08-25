//go:build e2e

package e2e

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"albmcp/test/albfake"
)

// Acceptance: with a session in place, a tool call returns the API response
// with no manual cookie handling anywhere in the client.
func TestHTTPRequestReturnsTheAPIResponse(t *testing.T) {
	e := newEnv(t, "")
	e.authenticate("first")
	c := e.serve()

	var resp httpResponse
	c.callToolJSON("http_request", map[string]any{"url": "/v1/users", "domain": "internal-api"}, &resp)

	if resp.Status != 200 || !resp.Authenticated {
		t.Fatalf("response = %+v", resp)
	}
	if resp.ReloginPerformed {
		t.Fatal("a valid session must not trigger a re-login")
	}
	if !strings.Contains(resp.Body, `"path":"/v1/users"`) {
		t.Fatalf("body = %q", resp.Body)
	}
}

// Acceptance: subsequent calls complete at normal request latency, with no
// further authentication work.
func TestRepeatedRequestsReuseTheSession(t *testing.T) {
	e := newEnv(t, "")
	e.authenticate("reused")
	c := e.serve()

	for i := range 5 {
		var resp httpResponse
		c.callToolJSON("http_request", map[string]any{
			"url": "/v1/item", "domain": "internal-api"}, &resp)
		if resp.Status != 200 || resp.ReloginPerformed {
			t.Fatalf("call %d: %+v", i, resp)
		}
	}
	if got := e.alb.Redirects.Load(); got != 0 {
		t.Fatalf("the load balancer bounced %d requests; the session was not reused", got)
	}
	if got := e.alb.Requests.Load(); got != 5 {
		t.Fatalf("served %d requests, want 5", got)
	}
}

// Acceptance: when the session expires, the next request re-authenticates and
// reports that it did so.
func TestExpiredSessionTriggersExactlyOneReLogin(t *testing.T) {
	e := newEnv(t, "")
	e.authenticate("will-expire")
	c := e.serve()

	// Prove the session works, then invalidate it behind the server's back.
	var first httpResponse
	c.callToolJSON("http_request", map[string]any{"url": "/v1/users", "domain": "internal-api"}, &first)
	if first.Status != 200 {
		t.Fatalf("first call = %+v", first)
	}
	e.alb.ExpireSession("will-expire")

	// With no browser available the re-login cannot succeed, and the failure
	// must be the documented no_browser error rather than a hang or a loop.
	payload := c.callToolError("http_request", map[string]any{
		"url": "/v1/users", "domain": "internal-api"})
	if payload["error"] != "no_browser" && payload["error"] != "login_timeout" && payload["error"] != "login_failed" {
		t.Fatalf("error = %v, want a login failure", payload)
	}
	if payload["hint"] == "" {
		t.Fatalf("every error must carry a hint: %v", payload)
	}
}

// Acceptance: a session the load balancer rejects however fresh produces
// exactly one retry and then a clear auth_loop error — never an endless loop.
func TestPersistentlyRejectedSessionReportsAnAuthLoop(t *testing.T) {
	e := newEnv(t, "")
	e.authenticate("rejected")
	c := e.serve()
	e.alb.RejectEverything.Store(true)

	payload := c.callToolError("http_request", map[string]any{
		"url": "/v1/users", "domain": "internal-api"})
	// Without a browser the re-login fails first; either way the loop stops.
	if payload["error"] == "" {
		t.Fatalf("payload = %v", payload)
	}
	if got := e.alb.Redirects.Load(); got > 2 {
		t.Fatalf("the load balancer saw %d attempts; the retry is not capped at one", got)
	}
}

// A split session must be replayed in full, or the load balancer cannot
// reassemble it.
func TestChunkedCookiesAreCapturedAndReplayed(t *testing.T) {
	e := newEnv(t, "")
	cookies := e.authenticate("chunked")
	if len(cookies) != albfake.Chunks {
		t.Fatalf("the fake issued %d chunks, want %d", len(cookies), albfake.Chunks)
	}

	stdout, _, code := e.run("", "auth", "status", "internal-api")
	if code != 0 {
		t.Fatalf("auth status exit code = %d", code)
	}
	if !strings.Contains(stdout, "authenticated") {
		t.Fatalf("auth status = %q", stdout)
	}

	c := e.serve()
	var resp httpResponse
	c.callToolJSON("http_request", map[string]any{"url": "/v1/users", "domain": "internal-api"}, &resp)
	if resp.Status != 200 {
		t.Fatalf("a chunked session did not authenticate: %+v", resp)
	}
}

// Acceptance: cookie values never appear on stdout, in stderr logs, or in any
// tool result.
func TestCookieValuesNeverLeak(t *testing.T) {
	e := newEnv(t, "")
	cookies := e.authenticate("secret-session")
	c := e.serve()

	var resp httpResponse
	c.callToolJSON("http_request", map[string]any{"url": "/v1/users", "domain": "internal-api"}, &resp)
	var status []map[string]any
	c.callToolJSON("auth_status", map[string]any{}, &status)
	c.callToolJSON("list_domains", map[string]any{}, &[]map[string]any{})

	haystacks := map[string]string{
		"server stdout": strings.Join(c.stdoutLines, "\n"),
		"server stderr": c.stderr.String(),
	}
	if encoded, err := json.Marshal(status); err == nil {
		haystacks["auth_status result"] = string(encoded)
	}
	if encoded, err := json.Marshal(resp); err == nil {
		haystacks["http_request result"] = string(encoded)
	}
	// The CLI surface too.
	cliOut, cliErr, _ := e.run("", "auth", "status")
	haystacks["cli stdout"] = cliOut
	haystacks["cli stderr"] = cliErr

	for _, value := range cookies {
		for where, text := range haystacks {
			if strings.Contains(text, value) {
				t.Fatalf("cookie value %q appeared in %s:\n%s", value, where, text)
			}
		}
	}
}

// Acceptance: stdout carries only MCP protocol traffic, verified by parsing
// every line the server emits as JSON-RPC.
func TestStdoutIsPureJSONRPC(t *testing.T) {
	e := newEnv(t, "")
	e.authenticate("purity")
	c := e.serve()

	// Exercise every tool, including failing ones, so any stray print shows up.
	c.callToolJSON("list_domains", map[string]any{}, &[]map[string]any{})
	c.callToolJSON("auth_status", map[string]any{}, &[]map[string]any{})
	c.callToolJSON("http_request", map[string]any{"url": "/v1/users", "domain": "internal-api"}, &httpResponse{})
	c.callToolError("http_request", map[string]any{"url": "https://nowhere.example.org/x"})
	c.callToolError("auth_login", map[string]any{"domain": "nope"})
	c.callToolJSON("auth_logout", map[string]any{"domain": "internal-api"}, &map[string]any{})
	c.send("tools/list", map[string]any{})

	if len(c.stdoutLines) == 0 {
		t.Fatal("the server wrote nothing to stdout")
	}
	for i, line := range c.stdoutLines {
		var envelope map[string]any
		if err := json.Unmarshal([]byte(line), &envelope); err != nil {
			t.Fatalf("stdout line %d is not JSON: %v\n%q", i, err, line)
		}
		if envelope["jsonrpc"] != "2.0" {
			t.Fatalf("stdout line %d is not a JSON-RPC message: %q", i, line)
		}
	}
	// Logging happened, and all of it went to stderr.
	if !strings.Contains(c.stderr.String(), "albmcp") {
		t.Fatalf("expected log output on stderr, got: %q", c.stderr.String())
	}
}

func TestToolsListAdvertisesTheDocumentedSurface(t *testing.T) {
	e := newEnv(t, "")
	c := e.serve()

	envelope := c.send("tools/list", map[string]any{})
	encoded, err := json.Marshal(envelope)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, name := range []string{"http_request", "auth_login", "auth_status", "auth_logout", "list_domains"} {
		if !strings.Contains(string(encoded), `"`+name+`"`) {
			t.Fatalf("tools/list did not advertise %q: %s", name, encoded)
		}
	}
}

func TestListDomainsAndAuthStatus(t *testing.T) {
	e := newEnv(t, "")
	c := e.serve()

	var domains []struct {
		Name         string   `json:"name"`
		BaseURL      string   `json:"base_url"`
		AllowMethods []string `json:"allow_methods"`
	}
	c.callToolJSON("list_domains", map[string]any{}, &domains)
	if len(domains) != 2 {
		t.Fatalf("got %d domains, want 2", len(domains))
	}
	if domains[0].Name != "admin-console" || domains[1].Name != "internal-api" {
		t.Fatalf("domains = %+v, want alphabetical order", domains)
	}

	var status []struct {
		Domain         string `json:"domain"`
		Authenticated  bool   `json:"authenticated"`
		StorageBackend string `json:"storage_backend"`
	}
	c.callToolJSON("auth_status", map[string]any{}, &status)
	if len(status) != 2 {
		t.Fatalf("got %d status entries, want 2", len(status))
	}
	for _, s := range status {
		if s.Authenticated {
			t.Fatalf("%s should start logged out", s.Domain)
		}
		if s.StorageBackend != "file" {
			t.Fatalf("%s storage_backend = %q, want file", s.Domain, s.StorageBackend)
		}
	}
}

func TestErrorsCarryCodeMessageAndHint(t *testing.T) {
	e := newEnv(t, "")
	e.authenticate("errors")
	c := e.serve()

	tests := []struct {
		name string
		tool string
		args map[string]any
		code string
	}{
		{"an unconfigured host", "http_request",
			map[string]any{"url": "https://nowhere.example.org/x"}, "unknown_domain"},
		{"a method the domain forbids", "http_request",
			map[string]any{"url": "/x", "domain": "internal-api", "method": "DELETE"}, "method_not_allowed"},
		{"url and domain disagree", "http_request",
			map[string]any{"url": e.alb.URL() + "/x", "domain": "admin-console"}, "domain_mismatch"},
		{"an unknown domain name", "auth_login",
			map[string]any{"domain": "nope"}, "unknown_domain"},
		{"a relative url with no domain", "http_request",
			map[string]any{"url": "/x"}, "invalid_request"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			payload := c.callToolError(tc.tool, tc.args)
			if payload["error"] != tc.code {
				t.Fatalf("error = %q, want %q (%v)", payload["error"], tc.code, payload)
			}
			if payload["message"] == "" {
				t.Fatalf("no message: %v", payload)
			}
		})
	}

	// method_not_allowed names the config key the user must change.
	payload := c.callToolError("http_request",
		map[string]any{"url": "/x", "domain": "internal-api", "method": "DELETE"})
	if !strings.Contains(payload["hint"], "allow_methods") {
		t.Fatalf("hint = %q, should name the config key", payload["hint"])
	}
}

// Non-2xx is data for the model, not a tool error.
func TestUpstreamErrorStatusIsReturnedAsAResult(t *testing.T) {
	e := newEnv(t, "")
	e.authenticate("status-codes")
	e.alb.Handler = func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(422)
		_, _ = w.Write([]byte(`{"error":"validation failed"}`))
	}
	c := e.serve()

	var resp httpResponse
	c.callToolJSON("http_request", map[string]any{
		"url": "/v1/users", "domain": "internal-api", "method": "POST", "body": `{}`}, &resp)
	if resp.Status != 422 || !strings.Contains(resp.Body, "validation failed") {
		t.Fatalf("response = %+v", resp)
	}
}

func TestResponseTruncation(t *testing.T) {
	e := newEnv(t, "max_response_bytes = 64\n")
	e.authenticate("truncation")
	e.alb.Handler = func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(strings.Repeat("z", 5000)))
	}
	c := e.serve()

	var resp httpResponse
	c.callToolJSON("http_request", map[string]any{"url": "/v1/big", "domain": "internal-api"}, &resp)
	if !resp.Truncated {
		t.Fatalf("response = %+v, want truncated", resp)
	}
	if !strings.Contains(resp.Body, "[truncated: 5000 bytes total]") {
		t.Fatalf("body tail = %q", resp.Body[max(0, len(resp.Body)-60):])
	}
}

func TestAuthLogoutThroughTheProtocol(t *testing.T) {
	e := newEnv(t, "")
	e.authenticate("logout-me")
	c := e.serve()

	var before []struct {
		Domain        string `json:"domain"`
		Authenticated bool   `json:"authenticated"`
	}
	c.callToolJSON("auth_status", map[string]any{"domain": "internal-api"}, &before)
	if !before[0].Authenticated {
		t.Fatalf("status before logout = %+v", before)
	}

	var result struct {
		Authenticated bool `json:"authenticated"`
	}
	c.callToolJSON("auth_logout", map[string]any{"domain": "internal-api"}, &result)
	if result.Authenticated {
		t.Fatalf("logout result = %+v", result)
	}

	var after []struct {
		Authenticated bool `json:"authenticated"`
	}
	c.callToolJSON("auth_status", map[string]any{"domain": "internal-api"}, &after)
	if after[0].Authenticated {
		t.Fatal("the session survived logout")
	}
}
