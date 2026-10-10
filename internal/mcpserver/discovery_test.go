package mcpserver

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mark3labs/mcp-go/mcp"

	"albauth/internal/auth"
	"albauth/internal/config"
	"albauth/internal/discover"
	"albauth/internal/httpx"
	"albauth/internal/logx"
	"albauth/test/albfake"
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

// R17: an absolute URL on a host no domain matches is probed with exactly one
// GET, and a login wall in front of it turns unknown_domain into a suggestion.
func TestUnknownDomainSuggestsLoginWall(t *testing.T) {
	idpHits := 0
	idp := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { idpHits++ }))
	t.Cleanup(idp.Close)

	probes := 0
	newProbingHarness := func(t *testing.T) *harness {
		h := newHarness(t)
		probes = 0
		h.deps.Probe = func(baseURL, probePath string, timeout time.Duration) (string, error) {
			probes++
			return discover.DetectIDPHost(baseURL, probePath, timeout)
		}
		// A configured header must never reach a host it was not configured for.
		h.deps.Config.Domains[0].Headers = map[string]string{"X-Api-Key": "configured-secret"}
		return h
	}
	request := func(t *testing.T, h *harness, target string) error {
		t.Helper()
		err := callErr(t, h, ToolHTTPRequest, map[string]any{
			"url":     target + "/v1/things?page=2",
			"headers": map[string]any{"X-Caller": "from-the-model", "Cookie": "caller=cookie"},
		})
		assertCode(t, err, auth.CodeUnknownDomain)
		return err
	}
	// S3: one GET of the origin, nothing albauth holds or was handed, no
	// redirect followed.
	assertOneCleanGET := func(t *testing.T, seen []probedRequest) {
		t.Helper()
		if probes != 1 {
			t.Errorf("probed %d times, want exactly once", probes)
		}
		if len(seen) != 1 {
			t.Fatalf("the host saw %d requests %+v, want exactly one", len(seen), seen)
		}
		if r := seen[0]; r.method != http.MethodGet || r.path != "/" || r.cookie != "" || r.apiKey != "" || r.caller != "" {
			t.Errorf("probe sent %+v; want a bare GET of /", r)
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

		got := render(t, err)
		s := got.Suggestion
		if s == nil {
			t.Fatalf("no suggestion in %s", RenderError(err))
		}
		u, _ := url.Parse(wall.URL)
		if s.BaseURL != wall.URL || !config.ValidName(s.Name) || s.Name != "127.0.0.1-"+u.Port() ||
			s.Found != FoundIdentityProviderRedirect || len(s.IDPHostnames) != 1 || s.IDPHostnames[0] != "127.0.0.1" {
			t.Errorf("suggestion = %+v", s)
		}
		if !strings.Contains(s.Note, "add_domain") || !strings.Contains(s.Note, "Ask the user") {
			t.Errorf("note = %q; it must name add_domain and say to ask first", s.Note)
		}
		if !strings.Contains(got.Hint, "add_domain") || !strings.Contains(got.Hint, "internal-api") {
			t.Errorf("hint = %q", got.Hint)
		}
		assertOneCleanGET(t, seen())
	})

	t.Run("an oauth2-style 401 is suggested from the one GET alone", func(t *testing.T) {
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
			t.Fatal("no suggestion for a host answering 401 like a forward-auth proxy")
		}
		if s.BaseURL != wall.URL || s.Found != FoundUnauthorized401 || len(s.IDPHostnames) != 0 {
			t.Errorf("suggestion = %+v", s)
		}
		if !strings.Contains(s.Note, "401") || !strings.Contains(s.Note, "oauth2-proxy") ||
			!strings.Contains(s.Note, "add_domain") || !strings.Contains(s.Note, "Ask the user") {
			t.Errorf("note = %q", s.Note)
		}
		// The login route is add_domain's business, after the user said yes.
		assertOneCleanGET(t, seen())
	})

	for name, status := range map[string]int{"a plain 200": http.StatusOK, "a 500": http.StatusInternalServerError} {
		t.Run(name+" host gets no suggestion", func(t *testing.T) {
			wall, seen := wallServer(t, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(status) })
			h := newProbingHarness(t)
			err := request(t, h, wall.URL)
			if strings.Contains(RenderError(err), "suggestion") {
				t.Errorf("a host with no login wall got a suggestion: %s", RenderError(err))
			}
			assertOneCleanGET(t, seen())
		})
	}

	t.Run("a probe that fails leaves the answer as it was", func(t *testing.T) {
		gone := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
		gone.Close()
		h := newProbingHarness(t)
		got := render(t, request(t, h, gone.URL))
		if got.Suggestion != nil || !strings.Contains(got.Hint, "configured domains") {
			t.Errorf("rendered = %+v", got)
		}
		if probes != 1 {
			t.Errorf("probed %d times, want exactly once", probes)
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
		wall, seen := wallServer(t, func(w http.ResponseWriter, r *http.Request) {
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
		assertOneCleanGET(t, seen())
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
// use it at once — listed, routed, reachable, redacted — without a restart.
// Every step runs against one Deps, as one server process would.
func TestAddDomainToolReloadsConfig(t *testing.T) {
	h, path, prefixes := addHarness(t)
	var logged bytes.Buffer
	log := logx.New(&logged, logx.LevelDebug)
	h.deps.AddCookiePrefix = func(p string) {
		*prefixes = append(*prefixes, p)
		log.AddCookiePrefix(p)
	}

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

	// On disk: the domain exactly once, in TOML that config.Load accepts.
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
	if n := strings.Count(string(data), "[[domain]]"); n != 1 {
		t.Errorf("config has %d [[domain]] blocks, want 1:\n%s", n, data)
	}
	assertLoads(t, path, "found-api")
	if info, _ := os.Stat(path); info.Mode().Perm() != 0o600 {
		t.Errorf("config mode = %v, want 0600", info.Mode().Perm())
	}

	// Its cookie family reaches the logger, which redacts it from then on.
	if len(*prefixes) != 1 || (*prefixes)[0] != "_oauth2_proxy" {
		t.Errorf("registered cookie prefixes %v, want the new domain's", *prefixes)
	}
	log.Info("Cookie: _oauth2_proxy=s3cr3t-session-value")
	if strings.Contains(logged.String(), "s3cr3t-session-value") {
		t.Errorf("the new domain's cookie reached the log: %s", logged.String())
	}

	// The running server sees it without a restart: listed read-only, routed
	// by an absolute URL on its host, and held to its read-only methods.
	listed := call(t, h, ToolListDomains, map[string]any{}).([]DomainEntry)
	if len(listed) != 1 || listed[0].Name != "found-api" || strings.Join(listed[0].AllowMethods, ",") != "GET" {
		t.Fatalf("list_domains = %+v", listed)
	}
	routed, target, err := httpx.Resolve(h.deps.config(), "https://found.example.com/v1/items", "", "GET")
	if err != nil || routed.Name != "found-api" || target != "https://found.example.com/v1/items" {
		t.Fatalf("Resolve = %v, %q, %v", routed, target, err)
	}
	assertCode(t, callErr(t, h, ToolHTTPRequest, map[string]any{
		"url": "https://found.example.com/v1", "method": "POST",
	}), auth.CodeMethodNotAllowed)
	status := call(t, h, ToolAuthStatus, map[string]any{"domain": "found-api"}).([]StatusEntry)
	if len(status) != 1 || status[0].Authenticated {
		t.Fatalf("auth_status = %+v", status)
	}

	// A domain added in the chat is reachable: an http_request to it logs in
	// (the stub authenticator) and gets the upstream's 200.
	call(t, h, ToolAddDomain, map[string]any{
		"name": "upstream", "base_url": h.alb.URL(), "idp_hostnames": []any{albfake.IDPHost},
	})
	resp := call(t, h, ToolHTTPRequest, map[string]any{"url": h.alb.URL() + "/v1/users"}).(*httpx.Response)
	if resp.Status != 200 || !resp.Authenticated || !strings.Contains(resp.Body, `"path":"/v1/users"`) {
		t.Fatalf("http_request to the added domain = %+v", resp)
	}
	if *h.logins != 1 {
		t.Errorf("performed %d logins, want 1", *h.logins)
	}

	// A further domain appends to the same file; read-only methods are kept.
	second := call(t, h, ToolAddDomain, map[string]any{
		"name": "second", "base_url": "https://second.example.com", "allow_methods": []any{"head", " OPTIONS "},
	}).(DomainEntry)
	if strings.Join(second.AllowMethods, ",") != "HEAD,OPTIONS" {
		t.Errorf("allow_methods = %v", second.AllowMethods)
	}
	if names := h.deps.config().DomainNames(); strings.Join(names, ",") != "found-api,upstream,second" {
		t.Errorf("domains after three adds = %v", names)
	}

	// A duplicate name, or a host another domain already claims, is a config
	// error and leaves both the file and the running config alone.
	before, _ := os.ReadFile(path)
	for what, args := range map[string]map[string]any{
		"same name":        {"name": "second", "base_url": "https://third.example.com"},
		"overlapping host": {"name": "found-again", "base_url": "https://found.example.com"},
	} {
		err = callErr(t, h, ToolAddDomain, args)
		assertCode(t, err, auth.CodeConfigInvalid)
		if coded, _ := errors.AsType[*auth.Error](err); !strings.Contains(coded.Hint, "not changed") {
			t.Errorf("%s: hint = %q", what, coded.Hint)
		}
		if after, _ := os.ReadFile(path); string(after) != string(before) {
			t.Errorf("%s: a refused add changed the config file", what)
		}
		if n := len(h.deps.config().Domains); n != 3 {
			t.Errorf("%s: running config has %d domains, want 3", what, n)
		}
	}

	// Concurrent adds, interleaved with reads, lose no write: every one lands
	// in the file and in the running config. Each write is slowed down, so
	// two read-modify-writes of the file would overlap if add_domain let them.
	origWrite := writeDomain
	t.Cleanup(func() { writeDomain = origWrite })
	var inFlight, overlapped atomic.Int32
	writeDomain = func(p string, d *config.Domain) error {
		if inFlight.Add(1) > 1 {
			overlapped.Add(1)
		}
		defer inFlight.Add(-1)
		time.Sleep(5 * time.Millisecond)
		return origWrite(p, d)
	}
	var wg sync.WaitGroup
	added := []string{"a", "b", "c", "d"}
	for _, name := range added {
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
	if n := overlapped.Load(); n != 0 {
		t.Errorf("%d config writes overlapped another; add_domain must serialise them", n)
	}
	all := append([]string{"found-api", "upstream", "second"}, added...)
	assertLoads(t, path, all...)
	if n := len(h.deps.config().Domains); n != len(all) {
		t.Fatalf("%d domains in the running config after concurrent adds, want %d", n, len(all))
	}
}

// assertLoads checks that the config file at path loads and names each domain
// exactly once.
func assertLoads(t *testing.T, path string, names ...string) {
	t.Helper()
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("config.Load rejects the written file: %v", err)
	}
	if len(cfg.Domains) != len(names) {
		t.Errorf("loaded domains %v, want %v", cfg.DomainNames(), names)
	}
	data, _ := os.ReadFile(path)
	for _, name := range names {
		if _, ok := cfg.Lookup(name); !ok {
			t.Errorf("loaded config lacks %q", name)
		}
		if n := strings.Count(string(data), `name = "`+name+`"`); n != 1 {
			t.Errorf("%q appears %d times in the file, want once", name, n)
		}
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

// After the user says yes, add_domain asks the follow-up questions the single
// unknown_domain GET did not: a forward-auth proxy's login route and settings.
func TestAddDomainToolFinishesForwardAuthSetup(t *testing.T) {
	idp := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	t.Cleanup(idp.Close)
	oauth2, seen := wallServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth2/start" {
			http.Redirect(w, r, idp.URL+"/auth", http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
	})

	h, path, prefixes := addHarness(t)
	h.deps.Probe = discover.DetectIDPHost
	call(t, h, ToolAddDomain, map[string]any{"name": "o2", "base_url": oauth2.URL})
	data, _ := os.ReadFile(path)
	for _, want := range []string{`login_probe_path = "/oauth2/start"`, `cookie_name_prefix = "_oauth2_proxy"`,
		`treat_401_as_expired = true`, `session_check_path = "/oauth2/auth"`, `idp_hostnames = ["127.0.0.1"]`} {
		if !strings.Contains(string(data), want) {
			t.Errorf("config lacks %s:\n%s", want, data)
		}
	}
	if len(*prefixes) != 1 || (*prefixes)[0] != "_oauth2_proxy" {
		t.Errorf("registered cookie prefixes %v", *prefixes)
	}
	for _, r := range seen() {
		if r.method != http.MethodGet || r.cookie != "" {
			t.Errorf("add_domain probe sent %+v; want a bare GET", r)
		}
	}

	// Explicit arguments win over what the probe finds.
	h2, path2, _ := addHarness(t)
	h2.deps.Probe = discover.DetectIDPHost
	call(t, h2, ToolAddDomain, map[string]any{
		"name": "o2", "base_url": oauth2.URL, "cookie_name_prefix": "my_cookie",
	})
	if data, _ := os.ReadFile(path2); !strings.Contains(string(data), `cookie_name_prefix = "my_cookie"`) ||
		!strings.Contains(string(data), `login_probe_path = "/oauth2/start"`) {
		t.Errorf("config = %s", data)
	}

	// Given idp_hostnames, nothing is probed; an unreachable host is not fatal.
	h3, _, _ := addHarness(t)
	h3.deps.Probe = func(string, string, time.Duration) (string, error) { return "", errors.New("unreachable") }
	call(t, h3, ToolAddDomain, map[string]any{"name": "gone", "base_url": "https://gone.example.com"})
	h3.deps.Probe = func(string, string, time.Duration) (string, error) {
		t.Fatal("probed although idp_hostnames was given")
		return "", nil
	}
	call(t, h3, ToolAddDomain, map[string]any{
		"name": "given", "base_url": "https://given.example.com", "idp_hostnames": []any{"login.example.net"},
	})
}
