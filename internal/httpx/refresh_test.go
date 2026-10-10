package httpx

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"albauth/internal/config"
	"albauth/internal/session"
)

// reissuingProxy stands in for a login proxy that refreshes its session on an
// ordinary response, the way oauth2-proxy --cookie-refresh does. Each path
// answers 200 with the Set-Cookie lines it is given, and every request's
// session-family cookies are recorded.
type reissuingProxy struct {
	srv    *httptest.Server
	prefix string
	mu     sync.Mutex
	seen   [][]string
}

func newReissuingProxy(t *testing.T, prefix string, routes map[string][]string) *reissuingProxy {
	t.Helper()
	p := &reissuingProxy{prefix: prefix}
	p.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var sent []string
		for _, c := range r.Cookies() {
			if strings.HasPrefix(c.Name, prefix) {
				sent = append(sent, c.Name+"="+c.Value)
			}
		}
		p.mu.Lock()
		p.seen = append(p.seen, sent)
		p.mu.Unlock()
		for _, line := range routes[r.URL.Path] {
			w.Header().Add("Set-Cookie", line)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	t.Cleanup(p.srv.Close)
	return p
}

func (p *reissuingProxy) domain() *config.Domain {
	return &config.Domain{
		Name: "api", BaseURL: p.srv.URL, CookieNamePrefix: p.prefix,
		AllowMethods: []string{"GET"}, TimeoutSeconds: 5, LoginTimeoutSeconds: 5,
	}
}

func (p *reissuingProxy) last() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return strings.Join(p.seen[len(p.seen)-1], "; ")
}

func orderedSession(pairs []string) *session.Session {
	s := &session.Session{}
	for _, pair := range pairs {
		name, value, _ := strings.Cut(pair, "=")
		s.Cookies = append(s.Cookies, session.Cookie{Name: name, Value: value, Path: "/", Expires: time.Now().Add(time.Hour)})
	}
	return s
}

func cookieValues(s *session.Session) string {
	parts := make([]string, 0, len(s.Cookies))
	for _, c := range s.Cookies {
		parts = append(parts, c.Name+"="+c.Value)
	}
	return strings.Join(parts, "; ")
}

// R12: a session cookie the proxy reissues replaces the stored one, the next
// request carries the new value, and the caller never sees it.
func TestRefreshedSessionCookieIsStored(t *testing.T) {
	const o2 = "_oauth2_proxy"
	const alb = "AWSELBAuthSessionCookie"

	cases := []struct {
		name    string
		prefix  string
		stored  []string // name=value, in order
		setOn   []string
		want    string // the stored session afterwards, and what the next request sends
		updated bool
	}{
		{
			name: "replace", prefix: o2,
			stored:  []string{o2 + "=v1"},
			setOn:   []string{o2 + "=v2; Path=/; HttpOnly; Max-Age=3600"},
			want:    o2 + "=v2",
			updated: true,
		},
		{
			name: "chunk added", prefix: alb,
			stored:  []string{alb + "-0=a"},
			setOn:   []string{alb + "-0=a2; Path=/", alb + "-1=b2; Path=/"},
			want:    alb + "-0=a2; " + alb + "-1=b2",
			updated: true,
		},
		{
			name: "chunks deleted", prefix: alb,
			stored: []string{alb + "-0=a", alb + "-1=b", alb + "-2=c"},
			setOn: []string{
				alb + "-0=a2; Path=/",
				alb + "-1=; Path=/; Max-Age=0",
				alb + "-2=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT",
			},
			want:    alb + "-0=a2",
			updated: true,
		},
		{
			name: "no session-family cookie", prefix: o2,
			stored: []string{o2 + "=v1"},
			setOn:  []string{"csrftoken=app; Path=/"},
			want:   o2 + "=v1",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := newReissuingProxy(t, tc.prefix, map[string][]string{"/rotate": tc.setOn})
			before := orderedSession(tc.stored)
			a := &stubAuth{current: before}
			client := NewClient(a, 1<<20)
			d := p.domain()

			resp, err := client.Do(t.Context(), &Request{Domain: d, Method: "GET", URL: p.srv.URL + "/rotate"})
			if err != nil {
				t.Fatalf("Do /rotate: %v", err)
			}
			if _, ok := resp.Headers["set-cookie"]; ok {
				t.Fatalf("Set-Cookie reached the caller: %v", resp.Headers)
			}
			if got := len(a.remembered); (got == 1) != tc.updated {
				t.Fatalf("Remember called %d time(s), want an update %v", got, tc.updated)
			}
			if !tc.updated && a.current != before {
				t.Fatal("a response with no session-family cookie changed the session")
			}
			if got := cookieValues(a.current); got != tc.want {
				t.Fatalf("stored session = %q, want %q", got, tc.want)
			}

			if _, err := client.Do(t.Context(), &Request{Domain: d, Method: "GET", URL: p.srv.URL + "/json"}); err != nil {
				t.Fatalf("Do /json: %v", err)
			}
			if got := p.last(); got != tc.want {
				t.Fatalf("next request sent %q, want %q — once each, from the store", got, tc.want)
			}
		})
	}

	t.Run("expiry and flags are kept", func(t *testing.T) {
		p := newReissuingProxy(t, o2, map[string][]string{"/rotate": {o2 + "=v2; Path=/; HttpOnly; Secure; Max-Age=3600"}})
		a := &stubAuth{current: sessionFrom(map[string]string{o2: "v1"})}
		start := time.Now()
		if _, err := NewClient(a, 1<<20).Do(t.Context(), &Request{Domain: p.domain(), Method: "GET", URL: p.srv.URL + "/rotate"}); err != nil {
			t.Fatalf("Do: %v", err)
		}
		c := a.current.Cookies[0]
		if !c.HTTPOnly || !c.Secure || c.Expires.Before(start.Add(59*time.Minute)) || c.Expires.After(time.Now().Add(time.Hour)) {
			t.Fatalf("stored cookie = %+v, want HttpOnly, Secure and an expiry an hour out", c)
		}
	})
}

// The response that sends albauth to log in again is not taken into the
// store: a proxy clearing its cookie on the way to the identity provider must
// not make the re-login think a concurrent one already replaced the session.
func TestTheResponseThatTriggersAReLoginIsNotRemembered(t *testing.T) {
	const o2 = "_oauth2_proxy"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if c, err := r.Cookie(o2); err == nil && c.Value == "fresh" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{}`))
			return
		}
		w.Header().Add("Set-Cookie", o2+"=; Path=/; Max-Age=0")
		http.Redirect(w, r, "https://idp.example.com/authorize", http.StatusFound)
	}))
	t.Cleanup(srv.Close)

	a := &stubAuth{
		current: sessionFrom(map[string]string{o2: "stale"}),
		next:    func() *session.Session { return sessionFrom(map[string]string{o2: "fresh"}) },
	}
	d := &config.Domain{
		Name: "api", BaseURL: srv.URL, CookieNamePrefix: o2, IDPHostnames: []string{"idp.example.com"},
		AllowMethods: []string{"GET"}, TimeoutSeconds: 5, LoginTimeoutSeconds: 5,
	}
	resp, err := NewClient(a, 1<<20).Do(t.Context(), &Request{Domain: d, Method: "GET", URL: srv.URL + "/x"})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if !resp.ReloginPerformed || a.refreshes.Load() != 1 {
		t.Fatalf("response = %+v after %d re-logins, want one re-login", resp, a.refreshes.Load())
	}
	if len(a.remembered) != 0 {
		t.Fatalf("remembered %d response(s), want none", len(a.remembered))
	}
}
