package mcpserver

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mark3labs/mcp-go/mcp"

	"albauth/internal/auth"
	"albauth/internal/config"
	"albauth/internal/discover"
)

// probedRequest is what an unconfigured host saw of albauth's probe.
type probedRequest struct {
	method, path, cookie, apiKey, caller string
}

// wallServer stands in for an unconfigured host. handle decides the answer;
// every request is recorded so the test can check what the probe sent.
func wallServer(t *testing.T, handle http.HandlerFunc) (*httptest.Server, func() []probedRequest) {
	t.Helper()
	var mu sync.Mutex
	var seen []probedRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, probedRequest{
			method: r.Method, path: r.URL.Path, cookie: r.Header.Get("Cookie"),
			apiKey: r.Header.Get("X-Api-Key"), caller: r.Header.Get("X-Caller"),
		})
		mu.Unlock()
		handle(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv, func() []probedRequest {
		mu.Lock()
		defer mu.Unlock()
		return append([]probedRequest(nil), seen...)
	}
}

// renderedError is the JSON the MCP client receives for a failed call.
type renderedError struct {
	Error      string      `json:"error"`
	Message    string      `json:"message"`
	Hint       string      `json:"hint"`
	Suggestion *Suggestion `json:"suggestion"`
}

func render(t *testing.T, err error) renderedError {
	t.Helper()
	var out renderedError
	if jsonErr := json.Unmarshal([]byte(RenderError(err)), &out); jsonErr != nil {
		t.Fatalf("RenderError is not JSON: %v", jsonErr)
	}
	return out
}

// R17: an absolute URL on a host no domain matches is probed once, and a login
// wall in front of it turns unknown_domain into a ready suggestion.
func TestUnknownDomainSuggestsLoginWall(t *testing.T) {
	idpHits := 0
	idp := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { idpHits++ }))
	t.Cleanup(idp.Close)

	newProbingHarness := func(t *testing.T) *harness {
		h := newHarness(t)
		h.deps.Probe = discover.DetectIDPHost
		// A configured header must never reach a host it was not configured for.
		h.deps.Config.Domains[0].Headers = map[string]string{"X-Api-Key": "configured-secret"}
		return h
	}
	request := func(t *testing.T, h *harness, target string) error {
		return callErr(t, h, ToolHTTPRequest, map[string]any{
			"url":     target + "/v1/things?page=2",
			"headers": map[string]any{"X-Caller": "from-the-model", "Cookie": "caller=cookie"},
		})
	}
	// S3: GET only, nothing albauth holds or was handed, no redirect followed.
	assertClean := func(t *testing.T, seen []probedRequest) {
		t.Helper()
		for _, r := range seen {
			if r.method != http.MethodGet || r.cookie != "" || r.apiKey != "" || r.caller != "" {
				t.Errorf("probe sent %+v; want a bare GET", r)
			}
			if r.path == "/v1/things" {
				t.Errorf("probe asked the request path; it asks the origin")
			}
		}
		if idpHits != 0 {
			t.Errorf("the identity provider was contacted %d times: the probe followed a redirect", idpHits)
		}
	}

	t.Run("an ALB-style redirect to an identity provider", func(t *testing.T) {
		wall, seen := wallServer(t, func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, idp.URL+"/authorize?client_id=x", http.StatusFound)
		})
		h := newProbingHarness(t)
		err := request(t, h, wall.URL)
		assertCode(t, err, auth.CodeUnknownDomain)

		got := render(t, err)
		s := got.Suggestion
		if s == nil {
			t.Fatalf("no suggestion in %s", RenderError(err))
		}
		u, _ := url.Parse(wall.URL)
		if s.BaseURL != wall.URL || !config.ValidName(s.Name) ||
			s.Name != "127.0.0.1-"+u.Port() || len(s.IDPHostnames) != 1 || s.IDPHostnames[0] != "127.0.0.1" {
			t.Errorf("suggestion = %+v", s)
		}
		if s.LoginProbePath != "" || s.CookieNamePrefix != "" || s.Treat401AsExpired || s.SessionCheckPath != "" {
			t.Errorf("a redirecting proxy needs none of the forward-auth settings: %+v", s)
		}
		if !strings.Contains(s.Note, "add_domain") || !strings.Contains(s.Note, "Ask the user") {
			t.Errorf("note = %q; it must name add_domain and say to ask first", s.Note)
		}
		if !strings.Contains(got.Hint, "add_domain") {
			t.Errorf("hint = %q", got.Hint)
		}
		requests := seen()
		if len(requests) != 1 || requests[0].path != "/" {
			t.Errorf("probe made %+v; want exactly one GET of /", requests)
		}
		assertClean(t, requests)
	})

	t.Run("an oauth2-proxy 401 with its start route", func(t *testing.T) {
		wall, seen := wallServer(t, func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/oauth2/start" {
				http.Redirect(w, r, idp.URL+"/auth", http.StatusFound)
				return
			}
			w.WriteHeader(http.StatusUnauthorized)
		})
		h := newProbingHarness(t)
		s := render(t, request(t, h, wall.URL)).Suggestion
		if s == nil {
			t.Fatal("no suggestion for an oauth2-proxy login wall")
		}
		if s.BaseURL != wall.URL || s.LoginProbePath != "/oauth2/start" ||
			s.CookieNamePrefix != "_oauth2_proxy" || !s.Treat401AsExpired || s.SessionCheckPath != "/oauth2/auth" {
			t.Errorf("suggestion = %+v", s)
		}
		assertClean(t, seen())
	})

	t.Run("a plain 200 host gets no suggestion", func(t *testing.T) {
		wall, seen := wallServer(t, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
		h := newProbingHarness(t)
		err := request(t, h, wall.URL)
		assertCode(t, err, auth.CodeUnknownDomain)
		if strings.Contains(RenderError(err), "suggestion") {
			t.Errorf("a host with no login wall got a suggestion: %s", RenderError(err))
		}
		if len(seen()) != 1 {
			t.Errorf("probe made %d requests, want 1", len(seen()))
		}
		assertClean(t, seen())
	})

	t.Run("a bare 401 is the application refusing, not a login wall", func(t *testing.T) {
		wall, seen := wallServer(t, func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
		})
		h := newProbingHarness(t)
		if got := render(t, request(t, h, wall.URL)); got.Suggestion != nil {
			t.Errorf("suggestion = %+v", got.Suggestion)
		}
		assertClean(t, seen())
	})

	t.Run("a probe that fails leaves the answer as it was", func(t *testing.T) {
		gone := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
		gone.Close()
		h := newProbingHarness(t)
		got := render(t, request(t, h, gone.URL))
		if got.Error != auth.CodeUnknownDomain || got.Suggestion != nil || !strings.Contains(got.Hint, "configured domains") {
			t.Errorf("rendered = %+v", got)
		}
	})

	t.Run("relative URLs and other errors are not probed", func(t *testing.T) {
		h := newProbingHarness(t)
		h.deps.Probe = func(string, string, time.Duration) (string, error) {
			t.Fatal("probed when there was no unconfigured host to ask")
			return "", nil
		}
		for _, args := range []map[string]any{
			{"url": "/v1/users", "domain": "nope"},
			{"url": "%zz", "domain": "nope"},
		} {
			assertCode(t, callErr(t, h, ToolHTTPRequest, args), auth.CodeUnknownDomain)
		}
		assertCode(t, callErr(t, h, ToolHTTPRequest, map[string]any{
			"url": h.alb.URL() + "/x", "method": "DELETE",
		}), auth.CodeMethodNotAllowed)
	})

	t.Run("no probe configured means no request", func(t *testing.T) {
		wall, seen := wallServer(t, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
		h := newHarness(t)
		assertCode(t, request(t, h, wall.URL), auth.CodeUnknownDomain)
		if len(seen()) != 0 {
			t.Errorf("an unprobing server contacted the host: %+v", seen())
		}
	})

	t.Run("the MCP result carries the suggestion", func(t *testing.T) {
		wall, _ := wallServer(t, func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, idp.URL+"/authorize", http.StatusFound)
		})
		h := newProbingHarness(t)
		req := mcp.CallToolRequest{}
		req.Params.Arguments = map[string]any{"url": wall.URL + "/x"}
		result, err := handlerFor(h.deps, ToolHTTPRequest)(t.Context(), req)
		if err != nil || !result.IsError {
			t.Fatalf("result = %+v, %v", result, err)
		}
		text := textOf(t, result)
		if !strings.Contains(text, `"suggestion"`) || !strings.Contains(text, `"base_url":"`+wall.URL+`"`) {
			t.Errorf("tool result = %s", text)
		}
	})
}

func TestProposeName(t *testing.T) {
	cfg := &config.Config{Domains: []config.Domain{{Name: "api.example.com"}, {Name: "api.example.com-2"}}}
	for raw, want := range map[string]string{
		"https://API.Example.org":      "api.example.org",
		"http://127.0.0.1:8080":        "127.0.0.1-8080",
		"http://[::1]:9000":            "1-9000",
		"https://api.example.com/x":    "api.example.com-3",
		"http://_..example.net":        "example.net",
		"http://...":                   "api",
		"https://svc_a.example.net:81": "svc_a.example.net-81",
	} {
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatalf("parse %q: %v", raw, err)
		}
		if got := proposeName(cfg, u); got != want {
			t.Errorf("proposeName(%q) = %q, want %q", raw, got, want)
		}
	}
}

// addHarness is a harness whose config lives in a file in a temp directory.
func addHarness(t *testing.T) (*harness, string, *[]string) {
	t.Helper()
	h := newHarness(t)
	path := filepath.Join(t.TempDir(), "albauth", "config.toml")
	h.deps.Config.Path = path
	var prefixes []string
	h.deps.AddCookiePrefix = func(p string) { prefixes = append(prefixes, p) }
	return h, path, &prefixes
}

// R18: add_domain writes the domain to the config file and the same server can
// use it at once.
func TestAddDomainToolReloadsConfig(t *testing.T) {
	h, path, prefixes := addHarness(t)

	got := call(t, h, ToolAddDomain, map[string]any{
		"name": "found-api", "base_url": "https://found.example.com/",
		"idp_hostnames":    []any{"login.example.net"},
		"login_probe_path": "/oauth2/start", "cookie_name_prefix": "_oauth2_proxy",
		"treat_401_as_expired": true, "session_check_path": "/oauth2/auth",
	}).(DomainEntry)
	if got.Name != "found-api" || got.BaseURL != "https://found.example.com" ||
		len(got.AllowMethods) != 1 || got.AllowMethods[0] != "GET" {
		t.Fatalf("add_domain = %+v", got)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("config not written: %v", err)
	}
	for _, want := range []string{`name = "found-api"`, `login_probe_path = "/oauth2/start"`,
		`cookie_name_prefix = "_oauth2_proxy"`, `treat_401_as_expired = true`, `session_check_path = "/oauth2/auth"`,
		`idp_hostnames = ["login.example.net"]`} {
		if !strings.Contains(string(data), want) {
			t.Errorf("config lacks %s:\n%s", want, data)
		}
	}
	if info, _ := os.Stat(path); info.Mode().Perm() != 0o600 {
		t.Errorf("config mode = %v, want 0600", info.Mode().Perm())
	}
	if len(*prefixes) != 1 || (*prefixes)[0] != "_oauth2_proxy" {
		t.Errorf("registered cookie prefixes %v, want the new domain's", *prefixes)
	}

	// The running server sees it without a restart: listed, resolvable, and
	// held to its read-only methods.
	listed := call(t, h, ToolListDomains, map[string]any{}).([]DomainEntry)
	if len(listed) != 1 || listed[0].Name != "found-api" {
		t.Fatalf("list_domains = %+v", listed)
	}
	assertCode(t, callErr(t, h, ToolHTTPRequest, map[string]any{
		"url": "https://found.example.com/v1", "method": "POST",
	}), auth.CodeMethodNotAllowed)
	status := call(t, h, ToolAuthStatus, map[string]any{"domain": "found-api"}).([]StatusEntry)
	if len(status) != 1 || status[0].Authenticated {
		t.Fatalf("auth_status = %+v", status)
	}

	// A second domain appends to the same file; read-only methods are kept.
	second := call(t, h, ToolAddDomain, map[string]any{
		"name": "second", "base_url": "https://second.example.com", "allow_methods": []any{"head", " OPTIONS "},
	}).(DomainEntry)
	if strings.Join(second.AllowMethods, ",") != "HEAD,OPTIONS" {
		t.Errorf("allow_methods = %v", second.AllowMethods)
	}
	if names := h.deps.config().DomainNames(); strings.Join(names, ",") != "found-api,second" {
		t.Errorf("domains after two adds = %v", names)
	}

	// A duplicate is a config error and leaves the file alone.
	before, _ := os.ReadFile(path)
	err = callErr(t, h, ToolAddDomain, map[string]any{"name": "second", "base_url": "https://third.example.com"})
	assertCode(t, err, auth.CodeConfigInvalid)
	if coded, _ := errors.AsType[*auth.Error](err); !strings.Contains(coded.Hint, "not changed") {
		t.Errorf("hint = %q", coded.Hint)
	}
	if after, _ := os.ReadFile(path); string(after) != string(before) {
		t.Error("a refused add changed the config file")
	}
}

func TestAddDomainToolHandlesConcurrentCalls(t *testing.T) {
	h, _, _ := addHarness(t)
	h.deps.AddCookiePrefix = nil
	var wg sync.WaitGroup
	for _, name := range []string{"a", "b", "c", "d"} {
		wg.Go(func() {
			if _, err := h.deps.Handle(t.Context(), ToolAddDomain, map[string]any{
				"name": name, "base_url": "https://" + name + ".example.com",
			}); err != nil {
				t.Errorf("add %s: %v", name, err)
			}
		})
		wg.Go(func() { _, _ = h.deps.Handle(t.Context(), ToolListDomains, nil) })
	}
	wg.Wait()
	if n := len(h.deps.config().Domains); n != 4 {
		t.Fatalf("%d domains after four concurrent adds, want 4", n)
	}
}

// R19: add_domain grants read-only methods only, and a refusal touches nothing.
func TestAddDomainToolRefusesWriteMethods(t *testing.T) {
	for _, methods := range [][]any{{"POST"}, {"GET", "delete"}, {"PUT"}, {"PATCH"}, {"BREW"}} {
		h, path, prefixes := addHarness(t)
		err := callErr(t, h, ToolAddDomain, map[string]any{
			"name": "api", "base_url": "https://api.example.com", "allow_methods": methods,
		})
		assertCode(t, err, auth.CodeMethodNotAllowed)
		coded, _ := errors.AsType[*auth.Error](err)
		if !strings.Contains(coded.Hint, "allow_methods") || !strings.Contains(coded.Hint, "albauth config add-domain") {
			t.Errorf("hint = %q; it must tell the user how to widen allow_methods", coded.Hint)
		}
		if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
			t.Errorf("%v: the config file was touched", methods)
		}
		if len(*prefixes) != 0 || len(h.deps.config().Domains) != 2 {
			t.Errorf("%v: the running config changed", methods)
		}
	}
}

func TestAddDomainToolArgumentErrors(t *testing.T) {
	h, _, _ := addHarness(t)
	for name, args := range map[string]map[string]any{
		"no name":                 {"base_url": "https://x.example.com"},
		"no base_url":             {"name": "x"},
		"idp_hostnames not array": {"name": "x", "base_url": "https://x.example.com", "idp_hostnames": "h"},
		"idp_hostnames element":   {"name": "x", "base_url": "https://x.example.com", "idp_hostnames": []any{1}},
		"allow_methods not array": {"name": "x", "base_url": "https://x.example.com", "allow_methods": "GET"},
		"probe path not string":   {"name": "x", "base_url": "https://x.example.com", "login_probe_path": 1},
		"treat 401 not bool":      {"name": "x", "base_url": "https://x.example.com", "treat_401_as_expired": "yes"},
	} {
		t.Run(name, func(t *testing.T) {
			assertCode(t, callErr(t, h, ToolAddDomain, args), auth.CodeInvalidRequest)
		})
	}
	assertCode(t, callErr(t, h, ToolAddDomain, map[string]any{"name": "Bad Name", "base_url": "https://x.example.com"}),
		auth.CodeConfigInvalid)
}

func TestAddDomainToolReportsWriteAndReloadFailures(t *testing.T) {
	origWrite, origReload := writeDomain, reloadConfig
	t.Cleanup(func() { writeDomain, reloadConfig = origWrite, origReload })
	args := map[string]any{"name": "x", "base_url": "https://x.example.com"}

	h, _, _ := addHarness(t)
	writeDomain = func(string, *config.Domain) error { return errors.New("disk full") }
	err := callErr(t, h, ToolAddDomain, args)
	assertCode(t, err, auth.CodeConfigInvalid)
	if coded, _ := errors.AsType[*auth.Error](err); !strings.Contains(coded.Hint, "could not be written") {
		t.Errorf("hint = %q", coded.Hint)
	}

	writeDomain = origWrite
	reloadConfig = func(string) (*config.Config, error) { return nil, errors.New("edited meanwhile") }
	err = callErr(t, h, ToolAddDomain, args)
	assertCode(t, err, auth.CodeConfigInvalid)
	if len(h.deps.config().Domains) != 2 {
		t.Error("a failed reload replaced the running config")
	}
}
