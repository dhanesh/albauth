package httpx

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"albauth/internal/auth"
	"albauth/internal/config"
	"albauth/internal/session"
)

const (
	checkPath     = "/oauth2/auth"
	proxyCookie   = "_oauth2_proxy"
	appRefusal    = `{"error":"invalid application token"}`
	appCookieName = "app_csrf"
	appOK         = `{"ok":true}`
)

// proxyApp stands in for oauth2-proxy in front of an application that answers
// 401 on its own. The check endpoint's answer is chosen per test, and every
// check request is recorded so the test can see exactly what it carried.
type proxyApp struct {
	srv     *httptest.Server
	check   func(w http.ResponseWriter, r *http.Request)
	appHits atomic.Int32
	// acceptsFresh makes the application answer 200 to a request carrying
	// the session the re-login hands out, so a retry can succeed.
	acceptsFresh atomic.Bool
	mu           sync.Mutex
	checkReqs    []*http.Request
}

func newProxyApp(t *testing.T, check func(w http.ResponseWriter, r *http.Request)) *proxyApp {
	t.Helper()
	p := &proxyApp{check: check}
	p.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == checkPath {
			p.mu.Lock()
			p.checkReqs = append(p.checkReqs, r.Clone(r.Context()))
			p.mu.Unlock()
			p.check(w, r)
			return
		}
		p.appHits.Add(1)
		if ck, err := r.Cookie(proxyCookie); err == nil && ck.Value == "fresh" && p.acceptsFresh.Load() {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, appOK)
			return
		}
		// The application hands out a cookie of its own, which the domain's
		// jar keeps, and then refuses the caller's credential.
		http.SetCookie(w, &http.Cookie{Name: appCookieName, Value: "app-value", Path: "/"})
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("WWW-Authenticate", `Bearer realm="app"`)
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, appRefusal)
	}))
	t.Cleanup(p.srv.Close)
	return p
}

func (p *proxyApp) checks() []*http.Request {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]*http.Request(nil), p.checkReqs...)
}

func (p *proxyApp) domain() *config.Domain {
	return &config.Domain{
		Name: "o2", BaseURL: p.srv.URL, Match: []string{strings.TrimPrefix(p.srv.URL, "http://")},
		CookieNamePrefix:  proxyCookie,
		AllowMethods:      []string{"GET", "POST"},
		Treat401AsExpired: true,
		SessionCheckPath:  checkPath,
		TimeoutSeconds:    5, LoginTimeoutSeconds: 5,
		Headers: map[string]string{"X-Api-Key": "domain-secret"},
	}
}

func accepted(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusAccepted) }
func rejected(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusUnauthorized) }

func proxyAuth() *stubAuth {
	return &stubAuth{
		current: sessionFrom(map[string]string{proxyCookie: "live"}),
		next:    func() *session.Session { return sessionFrom(map[string]string{proxyCookie: "fresh"}) },
	}
}

// R8: when the proxy still accepts the session, a 401 is the application
// refusing the request. It comes back as the application's own answer, with
// no re-login, and the check itself carried the session cookies and nothing
// that could make a dead session look alive.
func TestSessionCheckReturnsApplicationRefusal(t *testing.T) {
	p := newProxyApp(t, accepted)
	a := proxyAuth()
	client := NewClient(a, 1<<20)
	d := p.domain()
	req := &Request{Domain: d, Method: "GET", URL: p.srv.URL + "/v1/things",
		Headers: map[string]string{"X-Caller": "caller-secret"}}

	// Twice, so the second call runs with the application's cookie in the jar.
	for i := range 2 {
		resp, err := client.Do(t.Context(), req)
		if err != nil {
			t.Fatalf("call %d: Do: %v", i, err)
		}
		if resp.Status != http.StatusUnauthorized || resp.Body != appRefusal {
			t.Fatalf("call %d: response = %+v, want the application's 401 and body", i, resp)
		}
		if resp.ReloginPerformed || !resp.Authenticated {
			t.Fatalf("call %d: response = %+v, want authenticated without a re-login", i, resp)
		}
		if resp.Headers["www-authenticate"] != `Bearer realm="app"` {
			t.Fatalf("call %d: headers = %v, want the application's own", i, resp.Headers)
		}
	}
	if got := a.refreshes.Load(); got != 0 {
		t.Fatalf("performed %d re-logins, want 0", got)
	}
	if got := p.appHits.Load(); got != 2 {
		t.Fatalf("the application saw %d requests, want 2", got)
	}

	checks := p.checks()
	if len(checks) != 2 {
		t.Fatalf("made %d session checks, want 2", len(checks))
	}
	for i, r := range checks {
		if r.Method != http.MethodGet {
			t.Fatalf("check %d used %s, want GET", i, r.Method)
		}
		cookies := r.Cookies()
		if len(cookies) != 1 || cookies[0].Name != proxyCookie || cookies[0].Value != "live" {
			t.Fatalf("check %d carried cookies %v, want only the session cookie", i, cookies)
		}
		for _, h := range []string{"X-Api-Key", "X-Caller"} {
			if v := r.Header.Get(h); v != "" {
				t.Fatalf("check %d carried %s = %q; it must carry only the session cookies", i, h, v)
			}
		}
	}
}

// A body larger than the size cap is still truncated and counted correctly
// after being held across the check, and an unlimited client returns all of it.
func TestSessionCheckKeepsTheHeldBodyIntact(t *testing.T) {
	p := newProxyApp(t, accepted)
	d := p.domain()

	resp, err := NewClient(proxyAuth(), 10).Do(t.Context(), &Request{Domain: d, Method: "GET", URL: p.srv.URL + "/x"})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	want := appRefusal[:10] + fmt.Sprintf("\n…[truncated: %d bytes total]", len(appRefusal))
	if !resp.Truncated || resp.Body != want {
		t.Fatalf("body = %q (truncated %v), want %q", resp.Body, resp.Truncated, want)
	}

	resp, err = NewClient(proxyAuth(), 0).Do(t.Context(), &Request{Domain: d, Method: "GET", URL: p.srv.URL + "/x"})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if resp.Truncated || resp.Body != appRefusal {
		t.Fatalf("body = %q (truncated %v), want the whole refusal", resp.Body, resp.Truncated)
	}
}

// A write the application refused is returned as its answer too: it reached
// the application once and is never resent.
func TestSessionCheckReturnsARefusedWriteWithoutResending(t *testing.T) {
	p := newProxyApp(t, accepted)
	a := proxyAuth()

	resp, err := NewClient(a, 1<<20).Do(t.Context(), &Request{
		Domain: p.domain(), Method: "POST", URL: p.srv.URL + "/v1/orders", Body: `{}`})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if resp.Status != http.StatusUnauthorized || resp.ReloginPerformed {
		t.Fatalf("response = %+v, want the application's 401 without a re-login", resp)
	}
	if got := p.appHits.Load(); got != 1 {
		t.Fatalf("the application saw %d writes, want exactly 1", got)
	}
	if got := a.refreshes.Load(); got != 0 {
		t.Fatalf("performed %d re-logins, want 0", got)
	}
}

// R9 / O3: when the check answers anything but a 2xx, or fails to answer, the
// 401 is treated as the proxy's "no session" and triggers the re-login: a
// refusal, a forbidden, a redirect (never followed), a server error, a timeout,
// a refused connection or a path that cannot form a URL. A read is retried
// once on the fresh session and its answer returned with relogin_performed;
// a write is re-logged in for but not sent again (resend_required).
func TestFailedSessionCheckTriggersRelogin(t *testing.T) {
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })

	status := func(code int) func(w http.ResponseWriter, r *http.Request) {
		return func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(code) }
	}
	cases := map[string]struct {
		check func(w http.ResponseWriter, r *http.Request)
		edit  func(d *config.Domain)
	}{
		"401": {check: rejected},
		"403": {check: status(http.StatusForbidden)},
		"302 not followed": {check: func(w http.ResponseWriter, r *http.Request) {
			if r.URL.RawQuery == "" {
				// Following this would ask the check path again, and accept.
				http.Redirect(w, r, checkPath+"?followed=1", http.StatusFound)
				return
			}
			accepted(w, r)
		}},
		"500": {check: status(http.StatusInternalServerError)},
		"timeout": {check: func(_ http.ResponseWriter, r *http.Request) {
			select {
			case <-release:
			case <-r.Context().Done():
			}
		}, edit: func(d *config.Domain) { d.TimeoutSeconds = 1 }},
		"connection refused": {check: accepted, edit: func(d *config.Domain) {
			dead := httptest.NewServer(http.NotFoundHandler())
			dead.Close()
			// The check goes to the dead host; the request URL stays absolute.
			d.BaseURL = dead.URL
		}},
		"unbuildable path": {check: accepted, edit: func(d *config.Domain) {
			d.SessionCheckPath = "/\x7f"
		}},
	}
	for name, tc := range cases {
		setup := func(t *testing.T) (*proxyApp, *stubAuth, *config.Domain) {
			p := newProxyApp(t, tc.check)
			p.acceptsFresh.Store(true)
			d := p.domain()
			if tc.edit != nil {
				tc.edit(d)
			}
			return p, proxyAuth(), d
		}
		assertChecks := func(t *testing.T, p *proxyApp) {
			t.Helper()
			if got := len(p.checks()); got > 1 {
				t.Fatalf("made %d session checks, want at most 1 (a redirect is never followed)", got)
			}
		}

		t.Run(name+"/GET", func(t *testing.T) {
			p, a, d := setup(t)
			start := time.Now()
			resp, err := NewClient(a, 1<<20).Do(t.Context(), &Request{Domain: d, Method: "GET", URL: p.srv.URL + "/json"})
			if err != nil {
				t.Fatalf("Do: %v", err)
			}
			if resp.Status != http.StatusOK || resp.Body != appOK || !resp.ReloginPerformed || !resp.Authenticated {
				t.Fatalf("response = %+v, want the retried 200 with relogin_performed", resp)
			}
			if got := a.refreshes.Load(); got != 1 {
				t.Fatalf("performed %d re-logins, want 1", got)
			}
			if got := p.appHits.Load(); got != 2 {
				t.Fatalf("the application saw %d requests, want the original plus one retry", got)
			}
			assertChecks(t, p)
			if elapsed := time.Since(start); elapsed > 8*time.Second {
				t.Fatalf("took %s; the check did not honour timeout_seconds", elapsed)
			}
		})

		t.Run(name+"/POST", func(t *testing.T) {
			p, a, d := setup(t)
			_, err := NewClient(a, 1<<20).Do(t.Context(), &Request{
				Domain: d, Method: "POST", URL: p.srv.URL + "/v1/orders", Body: `{}`})
			assertCode(t, err, auth.CodeResendRequired)
			if got := a.refreshes.Load(); got != 1 {
				t.Fatalf("performed %d re-logins, want 1", got)
			}
			if got := p.appHits.Load(); got != 1 {
				t.Fatalf("the application saw %d writes, want exactly 1", got)
			}
			assertChecks(t, p)
		})
	}
}

// A 401 whose body cannot be read is not held; it takes the re-login path
// without asking the proxy.
func TestSessionCheckIsSkippedWhenThe401BodyCannotBeRead(t *testing.T) {
	var checks, calls atomic.Int32
	client := NewClient(proxyAuth(), 1<<20)
	client.newClient = func(time.Duration) *http.Client {
		return &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			if r.URL.Path == checkPath {
				checks.Add(1)
				return &http.Response{StatusCode: http.StatusAccepted, Body: io.NopCloser(strings.NewReader(""))}, nil
			}
			calls.Add(1)
			return &http.Response{StatusCode: http.StatusUnauthorized, Header: http.Header{},
				Body: errBody{errors.New("connection reset")}, Request: r}, nil
		})}
	}
	d := &config.Domain{Name: "o2", BaseURL: "https://o2.example.com", Treat401AsExpired: true,
		SessionCheckPath: checkPath, TimeoutSeconds: 5, AllowMethods: []string{"GET"}}

	_, err := client.Do(t.Context(), &Request{Domain: d, Method: "GET", URL: d.BaseURL + "/x"})
	assertCode(t, err, auth.CodeAuthLoop)
	if got := checks.Load(); got != 0 {
		t.Fatalf("made %d session checks for an unreadable 401, want 0", got)
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("made %d requests, want the original plus one retry", got)
	}
}

// Without session_check_path a 401 on a treat_401_as_expired domain re-logs in
// exactly as before, and no check is made.
func TestNoSessionCheckWithoutTheSetting(t *testing.T) {
	p := newProxyApp(t, accepted)
	a := proxyAuth()
	d := p.domain()
	d.SessionCheckPath = ""

	_, err := NewClient(a, 1<<20).Do(t.Context(), &Request{Domain: d, Method: "GET", URL: p.srv.URL + "/x"})
	assertCode(t, err, auth.CodeAuthLoop)
	if got := len(p.checks()); got != 0 {
		t.Fatalf("made %d session checks, want 0", got)
	}
	if got := a.refreshes.Load(); got != 1 {
		t.Fatalf("performed %d re-logins, want 1", got)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
