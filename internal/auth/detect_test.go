package auth

import (
	"net/http"
	"net/url"
	"testing"

	"albauth/internal/config"
)

func testDomain() *config.Domain {
	return &config.Domain{
		Name:         "api",
		BaseURL:      "https://api.example.com",
		IDPHostnames: []string{"login.example.net"},
	}
}

func request(t *testing.T, rawURL, accept string) *http.Request {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("parse %q: %v", rawURL, err)
	}
	req := &http.Request{URL: u, Header: http.Header{}}
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	return req
}

func response(status int, headers map[string]string) *http.Response {
	resp := &http.Response{StatusCode: status, Header: http.Header{}}
	for k, v := range headers {
		resp.Header.Set(k, v)
	}
	return resp
}

func TestIsUnauthenticated(t *testing.T) {
	tests := []struct {
		name       string
		req        string
		accept     string
		resp       *http.Response
		wantUnauth bool
		wantReason Reason
	}{
		{
			name: "rule 1: redirect to a configured identity provider",
			req:  "https://api.example.com/v1/users", accept: "application/json",
			resp:       response(302, map[string]string{"Location": "https://login.example.net/authorize?x=1"}),
			wantUnauth: true, wantReason: ReasonIDPRedirect,
		},
		{
			name: "rule 1: redirect to the load balancer's own callback path",
			req:  "https://api.example.com/v1/users", accept: "application/json",
			resp:       response(302, map[string]string{"Location": "https://api.example.com/oauth2/idpresponse?code=x"}),
			wantUnauth: true, wantReason: ReasonIDPRedirect,
		},
		{
			name: "rule 1 also fires on 303",
			req:  "https://api.example.com/v1/users", accept: "application/json",
			resp:       response(303, map[string]string{"Location": "https://login.example.net/authorize"}),
			wantUnauth: true, wantReason: ReasonIDPRedirect,
		},
		{
			name: "rule 2: any cross-host redirect off an API endpoint",
			req:  "https://api.example.com/v1/users", accept: "application/json",
			resp:       response(302, map[string]string{"Location": "https://unknown-provider.example.org/login"}),
			wantUnauth: true, wantReason: ReasonCrossHost,
		},
		{
			// A 401 is the application refusing the caller far more often than
			// it is the load balancer, so it is not an expiry signal by default.
			name: "a 401 is not treated as expiry unless the domain opts in",
			req:  "https://api.example.com/v1/users", accept: "application/json",
			resp:       response(401, nil),
			wantUnauth: false, wantReason: ReasonAuthenticated,
		},
		{
			name: "rule 4: an HTML login page answering a JSON request",
			req:  "https://api.example.com/v1/users", accept: "application/json",
			resp:       response(403, map[string]string{"Content-Type": "text/html; charset=utf-8"}),
			wantUnauth: true, wantReason: ReasonHTMLForJSON,
		},
		{
			// Applications behind these proxies serve HTML of their own. Judging
			// a successful page expired costs a browser window and then fails a
			// request that had a working session.
			name: "rule 4 does not fire on an HTML page the application served successfully",
			req:  "https://api.example.com/", accept: "application/json",
			resp:       response(200, map[string]string{"Content-Type": "text/html; charset=utf-8"}),
			wantUnauth: false, wantReason: ReasonAuthenticated,
		},
		{
			// oauth2-proxy answers a JSON request with no session with a 401
			// sign-in page, and that holds without treat_401_as_expired.
			name: "rule 4: an HTML 401 sign-in page answering a JSON request",
			req:  "https://api.example.com/v1/users", accept: "application/json",
			resp:       response(401, map[string]string{"Content-Type": "text/html"}),
			wantUnauth: true, wantReason: ReasonHTMLForJSON,
		},
		// An application's own HTML error pages are its answer, not a login
		// page: re-logging in for them opens a browser on a working session.
		{
			name: "rule 4 does not fire on an application's HTML 404",
			req:  "https://api.example.com/v1/users", accept: "application/json",
			resp:       response(404, map[string]string{"Content-Type": "text/html; charset=utf-8"}),
			wantUnauth: false, wantReason: ReasonAuthenticated,
		},
		{
			name: "rule 4 does not fire on an application's HTML 500",
			req:  "https://api.example.com/v1/users", accept: "application/json",
			resp:       response(500, map[string]string{"Content-Type": "text/html"}),
			wantUnauth: false, wantReason: ReasonAuthenticated,
		},
		{
			name: "rule 4 does not fire on a gateway's HTML 502",
			req:  "https://api.example.com/v1/users", accept: "application/json",
			resp:       response(502, map[string]string{"Content-Type": "text/html"}),
			wantUnauth: false, wantReason: ReasonAuthenticated,
		},
		{
			name: "rule 4 does not fire on a gateway's HTML 503",
			req:  "https://api.example.com/v1/users", accept: "application/json",
			resp:       response(503, map[string]string{"Content-Type": "text/html"}),
			wantUnauth: false, wantReason: ReasonAuthenticated,
		},

		// The cases that must NOT be treated as authentication failures.
		{
			name: "a legitimate same-host redirect",
			req:  "https://api.example.com/v1/users", accept: "application/json",
			resp:       response(302, map[string]string{"Location": "https://api.example.com/v2/users"}),
			wantUnauth: false, wantReason: ReasonAuthenticated,
		},
		{
			name: "a relative redirect stays on the same host",
			req:  "https://api.example.com/v1/users", accept: "application/json",
			resp:       response(302, map[string]string{"Location": "/v2/users"}),
			wantUnauth: false, wantReason: ReasonAuthenticated,
		},
		{
			name: "a normal JSON 200",
			req:  "https://api.example.com/v1/users", accept: "application/json",
			resp:       response(200, map[string]string{"Content-Type": "application/json"}),
			wantUnauth: false, wantReason: ReasonAuthenticated,
		},
		{
			name: "HTML is fine when HTML was asked for",
			req:  "https://api.example.com/page", accept: "text/html",
			resp:       response(200, map[string]string{"Content-Type": "text/html"}),
			wantUnauth: false, wantReason: ReasonAuthenticated,
		},
		{
			name: "an application error is the caller's problem, not an auth failure",
			req:  "https://api.example.com/v1/users", accept: "application/json",
			resp:       response(500, map[string]string{"Content-Type": "application/json"}),
			wantUnauth: false, wantReason: ReasonAuthenticated,
		},
		{
			name: "403 is an authorisation decision, not a missing session",
			req:  "https://api.example.com/v1/users", accept: "application/json",
			resp:       response(403, map[string]string{"Content-Type": "application/json"}),
			wantUnauth: false, wantReason: ReasonAuthenticated,
		},
		{
			name: "a 301 is not one of the redirect statuses the rules cover",
			req:  "https://api.example.com/v1/users", accept: "application/json",
			resp:       response(301, map[string]string{"Location": "https://login.example.net/authorize"}),
			wantUnauth: false, wantReason: ReasonAuthenticated,
		},
		{
			name: "a redirect with no Location header",
			req:  "https://api.example.com/v1/users", accept: "application/json",
			resp:       response(302, nil),
			wantUnauth: false, wantReason: ReasonAuthenticated,
		},
		{
			name: "a redirect with an unparseable Location header",
			req:  "https://api.example.com/v1/users", accept: "application/json",
			resp:       response(302, map[string]string{"Location": "://not a url"}),
			wantUnauth: false, wantReason: ReasonAuthenticated,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotUnauth, gotReason := IsUnauthenticated(testDomain(), request(t, tc.req, tc.accept), tc.resp)
			if gotUnauth != tc.wantUnauth || gotReason != tc.wantReason {
				t.Fatalf("IsUnauthenticated() = %v, %q; want %v, %q",
					gotUnauth, gotReason, tc.wantUnauth, tc.wantReason)
			}
		})
	}
}

// A listener rule with OnUnauthenticatedRequest = "deny" answers 401 itself,
// so those domains opt in and the rule applies.
func TestIsUnauthenticatedHonoursTreat401AsExpired(t *testing.T) {
	d := testDomain()
	d.Treat401AsExpired = true
	req := request(t, "https://api.example.com/v1/users", "application/json")

	unauth, reason := IsUnauthenticated(d, req, response(401, nil))
	if !unauth || reason != ReasonUnauthorized {
		t.Fatalf("with the flag on, a 401 should read as expired: %v %q", unauth, reason)
	}

	// The opt-in must not widen anything else: a 403 is still an authorisation
	// decision, not a missing session.
	if unauth, _ := IsUnauthenticated(d, req, response(403, nil)); unauth {
		t.Fatal("403 must not be treated as expiry even with the flag on")
	}
}

func TestIsUnauthenticatedHandlesMissingInputs(t *testing.T) {
	if unauth, _ := IsUnauthenticated(testDomain(), request(t, "https://api.example.com/x", ""), nil); unauth {
		t.Fatal("a nil response cannot be judged unauthenticated")
	}
	// A nil request has no host to compare against, so a cross-host redirect
	// still reads as a redirect away from nothing — and must not panic.
	resp := response(302, map[string]string{"Location": "https://elsewhere.example.org/"})
	if unauth, reason := IsUnauthenticated(testDomain(), nil, resp); !unauth || reason != ReasonCrossHost {
		t.Fatalf("nil request = %v, %q", unauth, reason)
	}
	// Rule 4 needs a request to read Accept from; without one it cannot fire.
	html := response(200, map[string]string{"Content-Type": "text/html"})
	if unauth, _ := IsUnauthenticated(testDomain(), nil, html); unauth {
		t.Fatal("rule 4 must not fire without a request")
	}
}

func TestIsUnauthenticatedIgnoresPortDifferencesInTheSameHost(t *testing.T) {
	d := &config.Domain{Name: "api", BaseURL: "http://localhost:8080"}
	req := request(t, "http://localhost:8080/v1/users", "application/json")
	resp := response(302, map[string]string{"Location": "http://localhost:8080/login"})
	if unauth, reason := IsUnauthenticated(d, req, resp); unauth {
		t.Fatalf("same host and port must not be an auth failure, got %v %q", unauth, reason)
	}
	// A different port is a different host, and so is a cross-host redirect.
	other := response(302, map[string]string{"Location": "http://localhost:9999/login"})
	if unauth, reason := IsUnauthenticated(d, req, other); !unauth || reason != ReasonCrossHost {
		t.Fatalf("different port = %v, %q", unauth, reason)
	}
}

// TestSignInPageStillTriggersRelogin pins the other half of rule 4's narrowing:
// a 401 or 403 HTML page answering a JSON request is the proxy's sign-in page,
// whichever proxy sent it, and still costs exactly one re-login. The domain has
// no idp_hostnames and treat_401_as_expired off, so rule 4 alone decides.
func TestSignInPageStillTriggersRelogin(t *testing.T) {
	d := &config.Domain{Name: "api", BaseURL: "https://api.example.com"}
	tests := []struct {
		name       string
		status     int
		accept     string
		wantUnauth bool
		wantReason Reason
	}{
		{"401 HTML answering a JSON request", 401, "application/json", true, ReasonHTMLForJSON},
		{"403 HTML answering a JSON request", 403, "application/json", true, ReasonHTMLForJSON},
		{"403 HTML answering a mixed Accept that includes JSON", 403, "text/plain, application/json;q=0.9", true, ReasonHTMLForJSON},
		{"403 HTML answering a request that did not ask for JSON", 403, "text/html", false, ReasonAuthenticated},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := request(t, "https://api.example.com/v1/users", tt.accept)
			resp := response(tt.status, map[string]string{"Content-Type": "text/html; charset=utf-8"})
			gotUnauth, gotReason := IsUnauthenticated(d, req, resp)
			if gotUnauth != tt.wantUnauth || gotReason != tt.wantReason {
				t.Fatalf("IsUnauthenticated = (%v, %q), want (%v, %q)", gotUnauth, gotReason, tt.wantUnauth, tt.wantReason)
			}
		})
	}
}
