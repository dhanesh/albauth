// Package httpx issues authenticated requests to configured domains.
package httpx

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"albmcp/internal/auth"
	"albmcp/internal/config"
	"albmcp/internal/session"
)

// noRedirect keeps redirects visible to the caller.
//
// The whole expiry detection in the specification reads the 302 the ALB issues.
// If the standard client followed it, the response the caller sees would be the
// identity provider's login page and the signal would be lost.
func noRedirect(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

// NewHTTPClient returns a client configured for ALB request semantics.
func NewHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{Timeout: timeout, CheckRedirect: noRedirect}
}

// Request is one resolved, ready-to-issue API call.
type Request struct {
	Domain  *config.Domain
	Method  string
	URL     string
	Query   map[string]string
	Headers map[string]string
	Body    string
}

// Resolve turns tool arguments into a Request, applying the documented
// resolution rules and failing closed on a disallowed method.
func Resolve(cfg *config.Config, rawURL, domainName, method string) (*config.Domain, string, error) {
	if strings.TrimSpace(rawURL) == "" {
		return nil, "", auth.Errorf(auth.CodeInvalidRequest, "pass an absolute URL or a path plus 'domain'",
			"url is required")
	}
	if method == "" {
		method = http.MethodGet
	}
	method = strings.ToUpper(method)

	var d *config.Domain
	var target string

	if isAbsolute(rawURL) {
		parsed, err := url.Parse(rawURL)
		if err != nil {
			return nil, "", auth.Wrap(err, auth.CodeInvalidRequest, "", "url %q is not a valid URL", rawURL)
		}
		d = matchDomain(cfg, parsed.Host)
		if d == nil {
			return nil, "", auth.Errorf(auth.CodeUnknownDomain,
				"configured domains: "+strings.Join(cfg.DomainNames(), ", "),
				"no configured domain matches host %q", parsed.Host)
		}
		if domainName != "" && domainName != d.Name {
			return nil, "", auth.Errorf(auth.CodeDomainMismatch, "",
				"url host %q resolves to domain %q, but domain %q was given",
				parsed.Host, d.Name, domainName)
		}
		target = parsed.String()
	} else {
		if domainName == "" {
			return nil, "", auth.Errorf(auth.CodeInvalidRequest,
				"configured domains: "+strings.Join(cfg.DomainNames(), ", "),
				"url %q is relative, so 'domain' is required", rawURL)
		}
		found, ok := cfg.Lookup(domainName)
		if !ok {
			return nil, "", auth.Errorf(auth.CodeUnknownDomain,
				"configured domains: "+strings.Join(cfg.DomainNames(), ", "),
				"unknown domain %q", domainName)
		}
		d = found
		target = strings.TrimRight(d.BaseURL, "/") + "/" + strings.TrimLeft(rawURL, "/")
	}

	if !d.MethodAllowed(method) {
		return nil, "", auth.Errorf(auth.CodeMethodNotAllowed,
			fmt.Sprintf("add %q to allow_methods for domain %q in the config file", method, d.Name),
			"method %s is not allowed for domain %q (allowed: %s)",
			method, d.Name, strings.Join(d.AllowMethods, ", "))
	}
	return d, target, nil
}

func isAbsolute(raw string) bool {
	lower := strings.ToLower(raw)
	return strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://")
}

func matchDomain(cfg *config.Config, host string) *config.Domain {
	for i := range cfg.Domains {
		if cfg.Domains[i].MatchHost(host) {
			return &cfg.Domains[i]
		}
	}
	return nil
}

// build assembles the outbound request: query parameters, the domain's static
// headers, the caller's headers, and the session cookies.
func build(ctx context.Context, req *Request, s *session.Session) (*http.Request, error) {
	parsed, err := url.Parse(req.URL)
	if err != nil {
		return nil, auth.Wrap(err, auth.CodeInvalidRequest, "", "url %q is not a valid URL", req.URL)
	}
	if len(req.Query) > 0 {
		q := parsed.Query()
		for k, v := range req.Query {
			q.Set(k, v)
		}
		parsed.RawQuery = q.Encode()
	}

	// A fresh reader per attempt: the retry-once path builds the request again
	// rather than trying to rewind a consumed body.
	var body io.Reader
	if req.Body != "" {
		body = strings.NewReader(req.Body)
	}
	httpReq, err := http.NewRequestWithContext(ctx, req.Method, parsed.String(), body)
	if err != nil {
		return nil, auth.Wrap(err, auth.CodeInvalidRequest, "", "cannot build request: %v", err)
	}

	for k, v := range req.Domain.Headers {
		httpReq.Header.Set(k, v)
	}
	for k, v := range req.Headers {
		httpReq.Header.Set(k, v)
	}
	if httpReq.Header.Get("Accept") == "" {
		httpReq.Header.Set("Accept", "application/json")
	}
	for _, c := range s.Cookies {
		httpReq.AddCookie(&http.Cookie{Name: c.Name, Value: c.Value})
	}
	return httpReq, nil
}
