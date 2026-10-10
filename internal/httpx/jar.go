package httpx

import (
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"sync"

	"golang.org/x/net/publicsuffix"

	"albauth/internal/session"
)

// appJar remembers the cookies an application sets, so that a request can
// build on the one before it.
//
// Some tools hand out a token in one response and require it back in the next,
// paired with a session cookie set at the same moment — Jenkins' crumb and
// Superset's CSRF token both work this way. Without somewhere to keep that
// cookie the second request arrives with a valid-looking token and nothing to
// match it against, and every write fails.
//
// It deliberately ignores the load balancer's own session cookies. Those live
// in the session store, survive restarts, and are re-acquired by logging in;
// letting them accumulate here as well would mean sending each of them twice.
// When the proxy reissues one, Client.Do hands it to the session store instead
// (see Authenticator.Remember).
//
// Values never leave this process. Set-Cookie is still stripped from every
// response before it is returned, so a caller can benefit from the session
// without ever seeing it.
type appJar struct {
	inner  http.CookieJar
	prefix string
}

func newAppJar(sessionCookiePrefix string) *appJar {
	// The public suffix list is what stops a response setting a cookie scoped
	// to a registry suffix — Domain=.co.uk — which the jar would then attach to
	// every unrelated host under it. Go's own documentation calls a nil list
	// insecure, and this jar holds application session cookies, so it matters.
	//
	// cookiejar.New only fails on a malformed options struct, and this one is
	// a literal.
	inner, _ := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
	return &appJar{inner: inner, prefix: sessionCookiePrefix}
}

// SetCookies records everything except the load balancer's session cookies.
func (j *appJar) SetCookies(u *url.URL, cookies []*http.Cookie) {
	keep := make([]*http.Cookie, 0, len(cookies))
	for _, c := range cookies {
		if session.InFamily(c.Name, j.prefix) {
			continue
		}
		keep = append(keep, c)
	}
	if len(keep) > 0 {
		j.inner.SetCookies(u, keep)
	}
}

// Cookies implements http.CookieJar.
func (j *appJar) Cookies(u *url.URL) []*http.Cookie { return j.inner.Cookies(u) }

// jarStore hands out one jar per domain, so two domains never share a session.
type jarStore struct {
	mu   sync.Mutex
	jars map[string]*appJar
}

func newJarStore() *jarStore { return &jarStore{jars: map[string]*appJar{}} }

func (s *jarStore) for_(domainName, sessionCookiePrefix string) *appJar {
	s.mu.Lock()
	defer s.mu.Unlock()
	if jar, ok := s.jars[domainName]; ok {
		return jar
	}
	jar := newAppJar(sessionCookiePrefix)
	s.jars[domainName] = jar
	return jar
}

// forget drops a domain's application cookies. Logging out of a domain should
// not leave the application still believing the caller is signed in.
func (s *jarStore) forget(domainName string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.jars, domainName)
}
