package auth

import (
	"cmp"
	"net/http"
	"net/url"
	"strings"

	"albauth/internal/config"
)

// Reason explains why a response was judged unauthenticated.
type Reason string

// Detection reasons, one per rule in the specification.
const (
	ReasonAuthenticated Reason = ""
	ReasonIDPRedirect   Reason = "redirect_to_idp"
	ReasonCrossHost     Reason = "cross_host_redirect"
	ReasonUnauthorized  Reason = "status_401"
	ReasonHTMLForJSON   Reason = "html_response_to_json_request"
	idpResponsePath            = "/oauth2/idpresponse"
)

// IsUnauthenticated reports whether resp indicates the ALB session is missing
// or expired, and why.
//
// The four rules are deliberately narrow. A same-host redirect — 301, 302,
// 303, 307 or 308, with or without a body — is a legitimate application
// redirect and must not trigger a browser login, which is the case most easily
// got wrong here.
func IsUnauthenticated(d *config.Domain, req *http.Request, resp *http.Response) (bool, Reason) {
	if resp == nil {
		return false, ReasonAuthenticated
	}

	// Only when the domain says its load balancer is the one answering 401.
	// See config.Domain.Treat401AsExpired for why this is not the default.
	if resp.StatusCode == http.StatusUnauthorized && d.Treat401AsExpired {
		return true, ReasonUnauthorized
	}

	if isRedirect(resp.StatusCode) {
		location := resp.Header.Get("Location")
		if loc, err := url.Parse(location); err == nil && location != "" {
			locHost := hostOf(loc, requestHost(req))
			// Rule 1: the redirect points at a known identity provider, or at
			// the ALB's own OIDC callback.
			if d.IsIDPHost(locHost) || strings.EqualFold(loc.Path, idpResponsePath) {
				return true, ReasonIDPRedirect
			}
			// Rule 2: any cross-host redirect off an API endpoint. These APIs
			// never legitimately redirect to another host, so this catches
			// providers that were not listed in idp_hostnames.
			if !strings.EqualFold(locHost, requestHost(req)) {
				return true, ReasonCrossHost
			}
		}
	}

	// Rule 4: an HTML body answering a request that asked for JSON is a login
	// page leaking through a rule the redirect checks did not catch.
	//
	// Only on a 401 or a 403. Those are the statuses a proxy uses when it
	// answers "no session" with a page of its own instead of a redirect.
	// Every other status carrying text/html is the application talking: a 2xx
	// page it serves, or its own 404, 500 or a gateway's 502 and 503. Judging
	// those expired costs the user a browser window and then fails their
	// request outright, on a session that was working.
	if req != nil && isSessionRefusal(resp.StatusCode) &&
		wantsJSON(req.Header.Get("Accept")) && isHTML(resp.Header.Get("Content-Type")) {
		return true, ReasonHTMLForJSON
	}

	return false, ReasonAuthenticated
}

func isSessionRefusal(status int) bool {
	return status == http.StatusUnauthorized || status == http.StatusForbidden
}

func isRedirect(status int) bool {
	return status == http.StatusFound || status == http.StatusSeeOther
}

func requestHost(req *http.Request) string {
	if req == nil || req.URL == nil {
		return ""
	}
	return req.URL.Host
}

// hostOf resolves a possibly-relative Location against the request host.
func hostOf(loc *url.URL, fallback string) string {
	return cmp.Or(loc.Host, fallback)
}

func wantsJSON(accept string) bool {
	return strings.Contains(strings.ToLower(accept), "application/json")
}

func isHTML(contentType string) bool {
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(contentType)), "text/html")
}
