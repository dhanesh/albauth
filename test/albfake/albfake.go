// Package albfake is a test double for an Application Load Balancer with an
// authenticate-oidc listener rule in front of it.
//
// It reproduces the behaviour albmcp actually has to cope with: an
// unauthenticated request is redirected to an identity provider host, the
// callback sets a session cookie split across several chunks, and only a
// request carrying every chunk reaches the API behind it.
package albfake

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// CookiePrefix is the cookie family the fake issues, matching the real one.
const CookiePrefix = "AWSELBAuthSessionCookie"

// IDPHost is the identity provider hostname the fake redirects to. It is never
// contacted — only its name appears in the Location header.
const IDPHost = "login.example.net"

// Chunks is how many cookies the fake splits a session across, mirroring the
// way a real load balancer chunks a large session into -0, -1, ….
const Chunks = 2

// ALB is a fake load balancer plus the API behind it.
type ALB struct {
	server *httptest.Server

	mu sync.Mutex
	// valid is the set of session values the fake currently accepts.
	valid map[string]bool

	// RejectEverything makes the fake refuse every session, however fresh.
	// It models a listener rule scoped so narrowly that a valid cookie is
	// immediately rejected — the condition the retry cap exists for.
	RejectEverything atomic.Bool

	// Requests counts authenticated API requests served.
	Requests atomic.Int32
	// Redirects counts requests bounced to the identity provider.
	Redirects atomic.Int32

	// Handler serves authenticated API requests. Nil means a JSON 200.
	Handler http.HandlerFunc
}

// New starts a fake load balancer. Close it with Close.
func New() *ALB {
	alb := &ALB{valid: map[string]bool{}}
	alb.server = httptest.NewServer(http.HandlerFunc(alb.serve))
	return alb
}

// URL is the base URL of the fake, suitable for a domain's base_url.
func (a *ALB) URL() string { return a.server.URL }

// Host is the host:port of the fake.
func (a *ALB) Host() string { return strings.TrimPrefix(a.server.URL, "http://") }

// Close shuts the fake down.
func (a *ALB) Close() { a.server.Close() }

// IssueSession registers a session value as valid and returns the cookie
// name/value pairs a browser would have received.
func (a *ALB) IssueSession(value string) map[string]string {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.valid[value] = true

	out := make(map[string]string, Chunks)
	for i := range Chunks {
		out[fmt.Sprintf("%s-%d", CookiePrefix, i)] = fmt.Sprintf("%s.%d", value, i)
	}
	return out
}

// ExpireSession stops accepting a previously issued session.
func (a *ALB) ExpireSession(value string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.valid, value)
}

// accepts reports whether the request carries every chunk of a valid session.
func (a *ALB) accepts(r *http.Request) bool {
	if a.RejectEverything.Load() {
		return false
	}
	var value string
	for i := range Chunks {
		c, err := r.Cookie(fmt.Sprintf("%s-%d", CookiePrefix, i))
		if err != nil {
			return false
		}
		chunkValue, ok := strings.CutSuffix(c.Value, fmt.Sprintf(".%d", i))
		if !ok {
			return false
		}
		if i > 0 && chunkValue != value {
			return false // chunks from different sessions
		}
		value = chunkValue
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.valid[value]
}

func (a *ALB) serve(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/oauth2/idpresponse" {
		// The callback leg: set every chunk, exactly as a real one does.
		for name, value := range a.IssueSession("callback") {
			http.SetCookie(w, &http.Cookie{
				Name: name, Value: value, Path: "/",
				Expires: time.Now().Add(time.Hour), HttpOnly: true,
			})
		}
		w.WriteHeader(http.StatusOK)
		return
	}

	if !a.accepts(r) {
		a.Redirects.Add(1)
		w.Header().Set("Location",
			"https://"+IDPHost+"/authorize?redirect_uri="+a.server.URL+"/oauth2/idpresponse")
		w.WriteHeader(http.StatusFound)
		return
	}

	a.Requests.Add(1)
	if a.Handler != nil {
		a.Handler(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, `{"path":%q,"method":%q}`, r.URL.Path, r.Method)
}
