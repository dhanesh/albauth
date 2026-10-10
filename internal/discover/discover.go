// Package discover works out how a host sends an unauthenticated caller to
// log in, by asking it.
//
// Both `albauth config add-domain` and the MCP server's unknown_domain path use
// it. Every request it makes is a plain GET with no cookies and no configured
// headers, and no redirect is followed: the first Location is the answer, and
// following it would land on a login page.
package discover

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"albauth/internal/config"
)

// Detector asks baseURL+probePath where it sends a caller with no session and
// returns the identity provider's hostname. DetectIDPHost is the real one; it
// is a type so callers can substitute a stub that never reaches the network.
type Detector func(baseURL, probePath string, timeout time.Duration) (string, error)

// UnauthorizedError means the probe path answered 401. It is a distinct type
// because that answer is the signature of a forward-auth proxy, which Probe
// follows up on, rather than an ordinary probe failure.
type UnauthorizedError struct{ Target string }

func (e UnauthorizedError) Error() string {
	return fmt.Sprintf("%s answered 401 rather than redirecting to a login", e.Target)
}

// DetectIDPHost asks the host for its probe path and reads the host it is
// redirected to.
//
// This is the one field a user cannot reasonably guess: the proxy knows its
// identity provider, and asking it is more reliable than reading a hostname off
// a browser's address bar.
func DetectIDPHost(baseURL, probePath string, timeout time.Duration) (string, error) {
	target := strings.TrimRight(baseURL, "/") + "/" + strings.TrimLeft(probePath, "/")
	req, err := http.NewRequest(http.MethodGet, target, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/json")

	// A fresh client with no jar: nothing albauth holds is ever sent.
	client := &http.Client{
		Timeout:       timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusUnauthorized {
		return "", UnauthorizedError{Target: target}
	}
	if resp.StatusCode != http.StatusFound && resp.StatusCode != http.StatusSeeOther {
		return "", fmt.Errorf("%s answered %d rather than redirecting to a login", target, resp.StatusCode)
	}
	location, err := url.Parse(resp.Header.Get("Location"))
	if err != nil || location.Host == "" {
		return "", fmt.Errorf("%s redirected without a usable Location header", target)
	}
	if requestHost := HostOf(target); strings.EqualFold(location.Host, requestHost) {
		return "", fmt.Errorf("%s redirected to itself, not to an identity provider", target)
	}
	return location.Hostname(), nil
}

// forwardAuthStartPaths are where a proxy that answers 401 instead of
// redirecting keeps its login entry point, and what it names the session
// cookie it issues.
//
// oauth2-proxy uses these two paths, whether it is fronting the app itself or
// being consulted by Traefik's forwardAuth middleware. A proxy that redirects —
// an AWS ALB, Authelia, Authentik, Pomerium — never reaches this list, because
// the ordinary probe already found its identity provider.
//
// The cookie name matters as much as the path: albauth waits for a specific
// cookie family to appear, and its default is the ALB's. Against a proxy that
// names its cookie something else the browser login visibly succeeds while
// albauth keeps waiting for a cookie that will never arrive.
//
// The session check path is the proxy's own "is this session valid?" endpoint.
// oauth2-proxy documents /oauth2/auth: 202 when the session is live, 401 when
// it is not. With it set, a 401 from the application is told apart from an
// expired session instead of always opening a browser.
var forwardAuthStartPaths = []struct{ path, cookiePrefix, sessionCheckPath string }{
	{"/oauth2/start", "_oauth2_proxy", "/oauth2/auth"},
	{"/oauth2/sign_in", "_oauth2_proxy", "/oauth2/auth"},
}

// Findings is what a probe learned about a host.
type Findings struct {
	IDPHost      string // identity provider hostname, empty if not found
	LoginPath    string // path that actually starts the login, empty if the probe path does
	CookiePrefix string // session cookie family the proxy issues, empty if unknown
	SessionCheck string // proxy endpoint that says whether a session is live, empty if unknown
	Saw401       bool   // the probe path answered 401 rather than redirecting
}

// LoginWall reports whether the probe found a login in front of the host: a
// redirect to an identity provider, directly or from a forward-auth start
// path. A bare 401 with no login route behind it is not one — that is usually
// an application refusing a caller, which albauth cannot help with.
func (f Findings) LoginWall() bool { return f.IDPHost != "" }

// Probe works out how a host sends an unauthenticated caller to log in.
//
// The common case is a redirect, which names the identity provider outright.
// A proxy doing forward auth answers 401 instead and keeps its login route
// elsewhere, so a bare 401 is a lead rather than a dead end: the paths in
// forwardAuthStartPaths are tried, and a redirect from one of those identifies
// both the identity provider and where a browser has to start.
func Probe(detect Detector, baseURL, probePath string, timeout time.Duration) (Findings, error) {
	host, err := detect(baseURL, probePath, timeout)
	if err == nil {
		return Findings{IDPHost: host}, nil
	}
	var unauthorized UnauthorizedError
	if !errors.As(err, &unauthorized) {
		return Findings{}, err
	}
	for _, candidate := range forwardAuthStartPaths {
		if host, startErr := detect(baseURL, candidate.path, timeout); startErr == nil {
			return Findings{
				IDPHost:      host,
				LoginPath:    candidate.path,
				CookiePrefix: candidate.cookiePrefix,
				SessionCheck: candidate.sessionCheckPath,
				Saw401:       true,
			}, nil
		}
	}
	return Findings{Saw401: true}, err
}

// Applied says which of a domain's settings ApplyTo filled in.
type Applied struct {
	IDPHost, LoginPath, Treat401, CookiePrefix, SessionCheck bool
}

// ApplyTo fills in the settings the probe observed that d does not already
// have. A setting given explicitly always wins.
//
// A proxy that answers 401 and keeps its login route elsewhere needs settings
// that nobody guesses on a first run: where the browser starts, that a 401
// here means "not logged in" rather than "refused", the session cookie's name,
// and the endpoint that tells the two apart. All of them are set only when the
// probe actually found that login route, never assumed from a 401 alone.
func (f Findings) ApplyTo(d *config.Domain) Applied {
	var a Applied
	if f.IDPHost != "" && len(d.IDPHostnames) == 0 {
		d.IDPHostnames = []string{f.IDPHost}
		a.IDPHost = true
	}
	if f.LoginPath == "" || d.LoginProbePath != "" {
		return a
	}
	d.LoginProbePath, a.LoginPath = f.LoginPath, true
	if !d.Treat401AsExpired {
		d.Treat401AsExpired, a.Treat401 = true, true
	}
	if d.CookieNamePrefix == "" && f.CookiePrefix != "" {
		d.CookieNamePrefix, a.CookiePrefix = f.CookiePrefix, true
	}
	if d.SessionCheckPath == "" && f.SessionCheck != "" {
		d.SessionCheckPath, a.SessionCheck = f.SessionCheck, true
	}
	return a
}

// HostOf returns the host (with port) of a URL, or "" if it does not parse.
func HostOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return u.Host
}
