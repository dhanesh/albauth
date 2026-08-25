package mcpserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"albauth/internal/auth"
	"albauth/internal/config"
	"albauth/internal/httpx"
	"albauth/internal/session"
	"albauth/test/albfake"
)

var now = time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)

// harness wires a real object graph around a fake load balancer, so the tool
// handlers are tested end to end rather than against mocks of their own logic.
type harness struct {
	deps    *Deps
	alb     *albfake.ALB
	store   *session.MemoryStore
	logins  *int
	cleared *string
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	alb := albfake.New()
	t.Cleanup(alb.Close)

	cfg := &config.Config{
		Domains: []config.Domain{
			{
				Name: "internal-api", BaseURL: alb.URL(), Match: []string{alb.Host()},
				CookieNamePrefix: albfake.CookiePrefix, IDPHostnames: []string{albfake.IDPHost},
				AllowMethods: []string{"GET", "POST"}, TimeoutSeconds: 5, LoginTimeoutSeconds: 5,
				LoginProbePath: "/",
			},
			{
				Name: "admin-console", BaseURL: "https://admin.example.com",
				Match: []string{"admin.example.com"}, AllowMethods: []string{"GET"},
				CookieNamePrefix: albfake.CookiePrefix, TimeoutSeconds: 5, LoginTimeoutSeconds: 5,
				LoginProbePath: "/",
			},
		},
		Settings: config.Settings{MaxResponseBytes: 1 << 20},
	}

	logins := 0
	store := session.NewMemoryStore()
	mgr := auth.NewManager(auth.ManagerOptions{
		Store: store,
		Now:   func() time.Time { return now },
		Loginer: auth.LoginerFunc(func(context.Context, *config.Domain, string) ([]session.Cookie, error) {
			logins++
			var cookies []session.Cookie
			for name, value := range alb.IssueSession(fmt.Sprintf("browser-%d", logins)) {
				cookies = append(cookies, session.Cookie{
					Name: name, Value: value, Path: "/", Expires: now.Add(time.Hour),
				})
			}
			return cookies, nil
		}),
	})

	cleared := ""
	h := &harness{alb: alb, store: store, logins: &logins, cleared: &cleared}
	h.deps = &Deps{
		Config: cfg, Auth: mgr,
		Client: httpx.NewClient(mgr, cfg.Settings.MaxResponseBytes),
		Now:    func() time.Time { return now },
		ClearBrowserProfile: func(name string) error {
			cleared = name
			return nil
		},
	}
	return h
}

func call(t *testing.T, h *harness, tool string, args map[string]any) any {
	t.Helper()
	got, err := h.deps.Handle(t.Context(), tool, args)
	if err != nil {
		t.Fatalf("%s: %v", tool, err)
	}
	return got
}

func callErr(t *testing.T, h *harness, tool string, args map[string]any) error {
	t.Helper()
	got, err := h.deps.Handle(t.Context(), tool, args)
	if err == nil {
		t.Fatalf("%s should have failed, returned %v", tool, got)
	}
	return err
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

func TestHTTPRequestAuthenticatesTransparently(t *testing.T) {
	h := newHarness(t)

	got := call(t, h, ToolHTTPRequest, map[string]any{
		"url": h.alb.URL() + "/v1/users",
	}).(*httpx.Response)

	if got.Status != 200 || !got.Authenticated {
		t.Fatalf("response = %+v", got)
	}
	if *h.logins != 1 {
		t.Fatalf("performed %d logins, want 1 on first use", *h.logins)
	}
	if !strings.Contains(got.Body, `"path":"/v1/users"`) {
		t.Fatalf("body = %q", got.Body)
	}

	// The second call reuses the session: no further login.
	call(t, h, ToolHTTPRequest, map[string]any{"url": h.alb.URL() + "/v1/other"})
	if *h.logins != 1 {
		t.Fatalf("performed %d logins across two calls, want 1", *h.logins)
	}
}

func TestHTTPRequestAcceptsARelativeURLWithADomain(t *testing.T) {
	h := newHarness(t)
	got := call(t, h, ToolHTTPRequest, map[string]any{
		"url": "/v1/users", "domain": "internal-api",
	}).(*httpx.Response)
	if got.Status != 200 {
		t.Fatalf("status = %d", got.Status)
	}
}

func TestHTTPRequestPassesEveryArgumentThrough(t *testing.T) {
	h := newHarness(t)
	var gotQuery, gotHeader, gotMethod string
	h.alb.Handler = func(w http.ResponseWriter, r *http.Request) {
		gotQuery, gotHeader, gotMethod = r.URL.RawQuery, r.Header.Get("X-Trace"), r.Method
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{}`)
	}

	call(t, h, ToolHTTPRequest, map[string]any{
		"url":     "/v1/users",
		"domain":  "internal-api",
		"method":  "POST",
		"query":   map[string]any{"page": "2"},
		"headers": map[string]any{"X-Trace": "abc"},
		"body":    `{"name":"x"}`,
	})
	if gotQuery != "page=2" || gotHeader != "abc" || gotMethod != "POST" {
		t.Fatalf("query=%q header=%q method=%q", gotQuery, gotHeader, gotMethod)
	}
}

func TestHTTPRequestArgumentValidation(t *testing.T) {
	h := newHarness(t)
	tests := []struct {
		name string
		args map[string]any
		code string
	}{
		{"no url", map[string]any{}, auth.CodeInvalidRequest},
		{"url is not a string", map[string]any{"url": 42}, auth.CodeInvalidRequest},
		{"domain is not a string", map[string]any{"url": "/x", "domain": 1}, auth.CodeInvalidRequest},
		{"method is not a string", map[string]any{"url": "/x", "domain": "internal-api", "method": 1}, auth.CodeInvalidRequest},
		{"query is not an object", map[string]any{"url": "/x", "domain": "internal-api", "query": "a=b"}, auth.CodeInvalidRequest},
		{"a query value is not a string", map[string]any{"url": "/x", "domain": "internal-api", "query": map[string]any{"a": 1}}, auth.CodeInvalidRequest},
		{"headers is not an object", map[string]any{"url": "/x", "domain": "internal-api", "headers": "a"}, auth.CodeInvalidRequest},
		{"a header value is not a string", map[string]any{"url": "/x", "domain": "internal-api", "headers": map[string]any{"a": 1}}, auth.CodeInvalidRequest},
		{"body is not a string", map[string]any{"url": "/x", "domain": "internal-api", "body": 1}, auth.CodeInvalidRequest},
		{"an unknown host", map[string]any{"url": "https://nowhere.example.org/x"}, auth.CodeUnknownDomain},
		{"a method the domain forbids", map[string]any{"url": "/x", "domain": "internal-api", "method": "DELETE"}, auth.CodeMethodNotAllowed},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assertCode(t, callErr(t, h, ToolHTTPRequest, tc.args), tc.code)
		})
	}
}

func TestHTTPRequestTreatsAnExplicitNullAsAbsent(t *testing.T) {
	h := newHarness(t)
	got := call(t, h, ToolHTTPRequest, map[string]any{
		"url": "/v1/users", "domain": "internal-api",
		"method": nil, "query": nil, "headers": nil, "body": nil,
	}).(*httpx.Response)
	if got.Status != 200 {
		t.Fatalf("status = %d", got.Status)
	}
}

func TestAuthLogin(t *testing.T) {
	h := newHarness(t)

	first := call(t, h, ToolAuthLogin, map[string]any{"domain": "internal-api"}).(*LoginResult)
	if !first.Authenticated || first.Domain != "internal-api" || first.ExpiresAt == "" {
		t.Fatalf("result = %+v", first)
	}
	if *h.logins != 1 {
		t.Fatalf("logins = %d", *h.logins)
	}

	// Without force, an existing valid session is reused.
	call(t, h, ToolAuthLogin, map[string]any{"domain": "internal-api"})
	if *h.logins != 1 {
		t.Fatalf("logins after a second call = %d, want 1", *h.logins)
	}

	// With force, the stored session is discarded first.
	call(t, h, ToolAuthLogin, map[string]any{"domain": "internal-api", "force": true})
	if *h.logins != 2 {
		t.Fatalf("logins after force = %d, want 2", *h.logins)
	}
}

func TestAuthLoginArgumentValidation(t *testing.T) {
	h := newHarness(t)
	assertCode(t, callErr(t, h, ToolAuthLogin, map[string]any{}), auth.CodeInvalidRequest)
	assertCode(t, callErr(t, h, ToolAuthLogin, map[string]any{"domain": "nope"}), auth.CodeUnknownDomain)
	assertCode(t, callErr(t, h, ToolAuthLogin,
		map[string]any{"domain": "internal-api", "force": "yes"}), auth.CodeInvalidRequest)
}

func TestAuthLoginReportsALoginFailure(t *testing.T) {
	h := newHarness(t)
	h.deps.Auth = auth.NewManager(auth.ManagerOptions{
		Store: session.NewMemoryStore(),
		Now:   func() time.Time { return now },
		Loginer: auth.LoginerFunc(func(context.Context, *config.Domain, string) ([]session.Cookie, error) {
			return nil, auth.Errorf(auth.CodeNoBrowser, "install Chrome", "no browser")
		}),
	})
	assertCode(t, callErr(t, h, ToolAuthLogin, map[string]any{"domain": "internal-api"}), auth.CodeNoBrowser)
	assertCode(t, callErr(t, h, ToolAuthLogin,
		map[string]any{"domain": "internal-api", "force": true}), auth.CodeNoBrowser)
}

func TestAuthStatus(t *testing.T) {
	h := newHarness(t)

	all := call(t, h, ToolAuthStatus, map[string]any{}).([]StatusEntry)
	if len(all) != 2 {
		t.Fatalf("got %d entries, want one per configured domain", len(all))
	}
	for _, e := range all {
		if e.Authenticated {
			t.Fatalf("%s should start logged out", e.Domain)
		}
		if e.StorageBackend != session.BackendMemory {
			t.Fatalf("storage_backend = %q", e.StorageBackend)
		}
	}

	call(t, h, ToolAuthLogin, map[string]any{"domain": "internal-api"})
	one := call(t, h, ToolAuthStatus, map[string]any{"domain": "internal-api"}).([]StatusEntry)
	if len(one) != 1 || !one[0].Authenticated {
		t.Fatalf("entries = %+v", one)
	}
	if one[0].ExpiresAt == "" || one[0].AcquiredAt == "" {
		t.Fatalf("timestamps = %+v", one[0])
	}
	if one[0].BaseURL != h.alb.URL() {
		t.Fatalf("base_url = %q", one[0].BaseURL)
	}

	// Cookie values never appear in the status payload.
	encoded, err := json.Marshal(one)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	stored, _ := h.store.Get("internal-api")
	for _, value := range stored.CookieValues() {
		if strings.Contains(string(encoded), value) {
			t.Fatalf("a cookie value reached auth_status output: %s", encoded)
		}
	}
}

func TestAuthStatusReportsAnExpiredSessionAsLoggedOut(t *testing.T) {
	h := newHarness(t)
	if err := h.store.Set("internal-api", &session.Session{
		Cookies:    []session.Cookie{{Name: albfake.CookiePrefix + "-0", Value: "old", Expires: now.Add(-time.Hour)}},
		AcquiredAt: now.Add(-2 * time.Hour),
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	entries := call(t, h, ToolAuthStatus, map[string]any{"domain": "internal-api"}).([]StatusEntry)
	if entries[0].Authenticated {
		t.Fatal("an expired session must not report as authenticated")
	}
	if entries[0].ExpiresAt == "" {
		t.Fatal("an expired session should still report when it expired")
	}
}

// A broken store for one domain must not hide the others.
func TestAuthStatusReportsAStorageErrorInline(t *testing.T) {
	h := newHarness(t)
	h.deps.Auth = auth.NewManager(auth.ManagerOptions{
		Store: brokenStore{err: session.ErrInsecureFile},
		Now:   func() time.Time { return now },
	})

	entries := call(t, h, ToolAuthStatus, map[string]any{}).([]StatusEntry)
	if len(entries) != 2 {
		t.Fatalf("got %d entries, want 2", len(entries))
	}
	for _, e := range entries {
		if e.Error == "" {
			t.Fatalf("%s should carry the storage error", e.Domain)
		}
		if e.Authenticated {
			t.Fatalf("%s cannot be authenticated when the store is unreadable", e.Domain)
		}
	}
}

func TestAuthStatusArgumentValidation(t *testing.T) {
	h := newHarness(t)
	assertCode(t, callErr(t, h, ToolAuthStatus, map[string]any{"domain": 1}), auth.CodeInvalidRequest)
	assertCode(t, callErr(t, h, ToolAuthStatus, map[string]any{"domain": "nope"}), auth.CodeUnknownDomain)
}

func TestAuthLogout(t *testing.T) {
	h := newHarness(t)
	call(t, h, ToolAuthLogin, map[string]any{"domain": "internal-api"})

	got := call(t, h, ToolAuthLogout, map[string]any{"domain": "internal-api"}).(*LogoutResult)
	if got.Authenticated || got.BrowserProfileCleared {
		t.Fatalf("result = %+v", got)
	}
	if s, _ := h.store.Get("internal-api"); s != nil {
		t.Fatal("the session was not deleted")
	}
	if *h.cleared != "" {
		t.Fatal("the browser profile must be kept unless explicitly asked for")
	}

	withProfile := call(t, h, ToolAuthLogout, map[string]any{
		"domain": "internal-api", "clear_browser_profile": true,
	}).(*LogoutResult)
	if !withProfile.BrowserProfileCleared || *h.cleared != "internal-api" {
		t.Fatalf("result = %+v, cleared = %q", withProfile, *h.cleared)
	}
}

func TestAuthLogoutFailures(t *testing.T) {
	h := newHarness(t)
	assertCode(t, callErr(t, h, ToolAuthLogout, map[string]any{}), auth.CodeInvalidRequest)
	assertCode(t, callErr(t, h, ToolAuthLogout, map[string]any{"domain": "nope"}), auth.CodeUnknownDomain)
	assertCode(t, callErr(t, h, ToolAuthLogout,
		map[string]any{"domain": "internal-api", "clear_browser_profile": "yes"}), auth.CodeInvalidRequest)

	h.deps.ClearBrowserProfile = func(string) error { return errors.New("permission denied") }
	assertCode(t, callErr(t, h, ToolAuthLogout,
		map[string]any{"domain": "internal-api", "clear_browser_profile": true}), auth.CodeStorageUnavailable)

	broken := newHarness(t)
	broken.deps.Auth = auth.NewManager(auth.ManagerOptions{Store: brokenStore{err: errors.New("read-only")}})
	assertCode(t, callErr(t, broken, ToolAuthLogout,
		map[string]any{"domain": "internal-api"}), auth.CodeStorageUnavailable)
}

func TestAuthLogoutWithoutAProfileCleaner(t *testing.T) {
	h := newHarness(t)
	h.deps.ClearBrowserProfile = nil
	got := call(t, h, ToolAuthLogout, map[string]any{
		"domain": "internal-api", "clear_browser_profile": true,
	}).(*LogoutResult)
	if got.BrowserProfileCleared {
		t.Fatal("nothing was cleared, so the result must not claim otherwise")
	}
}

func TestListDomains(t *testing.T) {
	h := newHarness(t)
	got := call(t, h, ToolListDomains, map[string]any{}).([]DomainEntry)
	if len(got) != 2 {
		t.Fatalf("got %d domains", len(got))
	}
	// Sorted by name for a stable, diffable listing.
	if got[0].Name != "admin-console" || got[1].Name != "internal-api" {
		t.Fatalf("order = %q, %q; want alphabetical", got[0].Name, got[1].Name)
	}
	if got[0].BaseURL == "" || len(got[0].Match) == 0 || len(got[0].AllowMethods) == 0 {
		t.Fatalf("entry = %+v", got[0])
	}
}

func TestHandleRejectsAnUnknownTool(t *testing.T) {
	h := newHarness(t)
	assertCode(t, callErr(t, h, "not_a_tool", map[string]any{}), auth.CodeInvalidRequest)
}

func TestDepsNowDefaultsToTheWallClock(t *testing.T) {
	d := &Deps{}
	if d.now().IsZero() {
		t.Fatal("now() should fall back to the real clock")
	}
}

func TestRenderError(t *testing.T) {
	t.Run("a coded error keeps its code and hint", func(t *testing.T) {
		out := RenderError(auth.Errorf(auth.CodeLoginTimeout, "raise login_timeout_seconds", "timed out after %ds", 180))
		var payload map[string]string
		if err := json.Unmarshal([]byte(out), &payload); err != nil {
			t.Fatalf("output is not JSON: %v (%s)", err, out)
		}
		if payload["error"] != auth.CodeLoginTimeout ||
			payload["message"] != "timed out after 180s" ||
			payload["hint"] != "raise login_timeout_seconds" {
			t.Fatalf("payload = %v", payload)
		}
	})

	t.Run("an error with no hint omits the field", func(t *testing.T) {
		var payload map[string]string
		if err := json.Unmarshal([]byte(RenderError(auth.Errorf(auth.CodeAuthLoop, "", "looped"))), &payload); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if _, present := payload["hint"]; present {
			t.Fatalf("hint should be omitted, got %v", payload)
		}
	})

	t.Run("an uncoded error is given a generic code", func(t *testing.T) {
		var payload map[string]string
		if err := json.Unmarshal([]byte(RenderError(errors.New("something went wrong"))), &payload); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if payload["error"] != auth.CodeUpstreamError {
			t.Fatalf("payload = %v", payload)
		}
	})
}

func TestJoinNames(t *testing.T) {
	if got := joinNames(nil); got != "(none configured)" {
		t.Fatalf("joinNames(nil) = %q", got)
	}
	if got := joinNames([]string{"a"}); got != "a" {
		t.Fatalf("joinNames = %q", got)
	}
	if got := joinNames([]string{"a", "b", "c"}); got != "a, b, c" {
		t.Fatalf("joinNames = %q", got)
	}
}

func TestFormatTime(t *testing.T) {
	if got := formatTime(time.Time{}); got != "" {
		t.Fatalf("formatTime(zero) = %q", got)
	}
	if got := formatTime(now); got != "2026-08-26T12:00:00Z" {
		t.Fatalf("formatTime = %q", got)
	}
}

// brokenStore fails every operation with a fixed error.
type brokenStore struct{ err error }

func (b brokenStore) Get(string) (*session.Session, error) { return nil, b.err }
func (b brokenStore) Set(string, *session.Session) error   { return b.err }
func (b brokenStore) Delete(string) error                  { return b.err }
func (b brokenStore) Backend() string                      { return "broken" }
