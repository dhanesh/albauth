package httpx

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
	"unicode/utf8"

	"albauth/internal/auth"
	"albauth/internal/config"
	"albauth/internal/session"
)

// Response is the model-facing result of an authenticated request.
//
// Set-Cookie is stripped and no cookie value can reach this struct, so the
// whole value is safe to hand to a client verbatim.
type Response struct {
	Status  int               `json:"status"`
	Headers map[string]string `json:"headers"`
	Body    string            `json:"body"`

	// BodyBase64 reports that Body is base64 rather than the bytes themselves.
	// A response that is not valid UTF-8 — an image, a spreadsheet, a PDF —
	// cannot survive a JSON string: the invalid sequences are replaced, and the
	// caller receives something that looks like text and is silently corrupt.
	// Encoding it instead keeps the bytes intact and says so.
	BodyBase64 bool `json:"body_base64,omitzero"`

	Truncated        bool `json:"truncated"`
	Authenticated    bool `json:"authenticated"`
	ReloginPerformed bool `json:"relogin_performed"`
}

// Authenticator is the part of auth.Manager the client depends on.
type Authenticator interface {
	Ensure(ctx context.Context, d *config.Domain) (*session.Session, error)
	Refresh(ctx context.Context, d *config.Domain, stale *session.Session) (*session.Session, error)
	// Remember stores the session cookies a proxy reissued on a response.
	Remember(d *config.Domain, host string, set []*http.Cookie)
	// Touch records that the domain's session was just used successfully.
	Touch(d *config.Domain)
}

// Client issues authenticated requests, refreshing the session when the ALB
// says it has expired.
type Client struct {
	auth             Authenticator
	maxResponseBytes int
	newClient        func(timeout time.Duration) *http.Client
	jars             *jarStore
}

// NewClient builds a Client. maxResponseBytes bounds the body handed back to
// the model; a value of zero means unlimited.
func NewClient(a Authenticator, maxResponseBytes int) *Client {
	return &Client{
		auth:             a,
		maxResponseBytes: maxResponseBytes,
		newClient:        NewHTTPClient,
		jars:             newJarStore(),
	}
}

// ForgetCookies drops a domain's remembered application cookies. Called on
// logout so the next request starts from a clean slate.
func (c *Client) ForgetCookies(domainName string) { c.jars.forget(domainName) }

// Do performs the request, transparently authenticating.
//
// A write (anything but GET, HEAD or OPTIONS) is resent only when the first
// attempt met a redirect to the identity provider; otherwise the session is
// still refreshed but the caller gets resend_required, because the application
// may already have applied the write.
//
// On a domain with session_check_path, a 401 is first checked against the
// proxy: if it still accepts the session, the 401 is the application's and is
// returned as a result without a re-login.
//
// The retry is deliberately capped at exactly one. If a freshly acquired
// session is rejected too, something is wrong with the ALB rule rather than
// with the cookie, and looping would spawn browser windows forever.
func (c *Client) Do(ctx context.Context, req *Request) (*Response, error) {
	d := req.Domain

	s, err := c.auth.Ensure(ctx, d)
	if err != nil {
		return nil, err
	}

	resp, httpReq, err := c.attempt(ctx, req, s)
	if err != nil {
		return nil, err
	}

	unauthenticated, reason := auth.IsUnauthenticated(d, httpReq, resp)
	if !unauthenticated {
		c.accepted(d, httpReq, resp)
		return c.render(resp, true, false)
	}
	if reason == auth.ReasonUnauthorized && d.SessionCheckPath != "" {
		// Hold the 401's body before asking the proxy, so it is still there to
		// return if the application turns out to be the one refusing.
		if held, ok := c.hold(resp); ok {
			if c.sessionAccepted(ctx, d, s) {
				c.accepted(d, httpReq, held)
				return c.render(held, true, false)
			}
			resp = held
		}
	}
	drain(resp)

	refreshed, err := c.auth.Refresh(ctx, d, s)
	if err != nil {
		return nil, err
	}
	if !resendable(req.Method, reason) {
		return nil, auth.Errorf(auth.CodeResendRequired,
			"the session was refreshed, so the next call will be authenticated; the application may already "+
				"have applied this write, so check whether it took effect and resend it only if repeating it is safe",
			"%s to domain %q was judged unauthenticated (%s) and may have reached the application, so it was not sent again after the re-login",
			strings.ToUpper(req.Method), d.Name, reason)
	}

	resp, httpReq, err = c.attempt(ctx, req, refreshed)
	if err != nil {
		return nil, err
	}
	if stillUnauthenticated, secondReason := auth.IsUnauthenticated(d, httpReq, resp); stillUnauthenticated {
		drain(resp)
		return nil, auth.Errorf(auth.CodeAuthLoop,
			"the session may be invalidated immediately; check which paths the proxy protects for "+d.BaseURL+" (the ALB listener rule, the oauth2-proxy or forward-auth route) and its cookie settings",
			"domain %q is still unauthenticated after one re-login and retry (first: %s, second: %s)",
			d.Name, reason, secondReason)
	}
	c.accepted(d, httpReq, resp)
	return c.render(resp, true, true)
}

// remember hands the session cookies a response reissued to the store, so a
// proxy that refreshes its session (oauth2-proxy --cookie-refresh, an ALB
// re-issuing its chunks) does not leave albauth sending the old value until it
// stops working. The jar refuses these cookies, so the store is the one place
// they are kept and they are never sent twice.
//
// Only responses judged authenticated count. The response that triggers a
// re-login is left alone: a proxy bouncing to its identity provider may clear
// or set family cookies of its own, and a store changed underneath the
// re-login would look like a concurrent login had already replaced the
// session. A response with no session-family cookie never touches the store.
func (c *Client) remember(d *config.Domain, httpReq *http.Request, resp *http.Response) {
	set := resp.Cookies()
	for _, ck := range set {
		if session.InFamily(ck.Name, d.CookieNamePrefix) {
			c.auth.Remember(d, httpReq.URL.Hostname(), set)
			return
		}
	}
}

// accepted handles a response judged authenticated before it is rendered:
// it keeps any session cookie the proxy reissued and records the use.
func (c *Client) accepted(d *config.Domain, httpReq *http.Request, resp *http.Response) {
	c.remember(d, httpReq, resp)
	c.auth.Touch(d)
}

// sessionAccepted asks the proxy's session_check_path whether it still
// accepts the session, to tell an application's own 401 from the proxy's.
//
// The check carries the session cookies and nothing else: no [domain.headers],
// no caller headers and no application cookies, so the answer reflects the
// proxy's session alone and an application credential cannot make a dead
// session look alive. Only a 2xx counts as accepted. Every other outcome — a
// redirect, any other status, an unbuildable URL, a transport error or a
// timeout — reports false, so a wrong or unreachable path fails toward a
// re-login rather than toward reusing a dead session.
func (c *Client) sessionAccepted(ctx context.Context, d *config.Domain, s *session.Session) bool {
	target := strings.TrimRight(d.BaseURL, "/") + d.SessionCheckPath
	checkReq, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return false
	}
	for _, ck := range s.Cookies {
		checkReq.AddCookie(&http.Cookie{Name: ck.Name, Value: ck.Value})
	}
	// A client of its own, without the domain's application jar.
	resp, err := c.newClient(time.Duration(d.TimeoutSeconds) * time.Second).Do(checkReq)
	if err != nil {
		return false
	}
	drain(resp)
	accepted := resp.StatusCode >= 200 && resp.StatusCode < 300
	if accepted {
		// oauth2-proxy refreshes its cookie on /oauth2/auth as on any other
		// path, so a refresh handed out here is kept like any other.
		c.remember(d, checkReq, resp)
	}
	return accepted
}

// hold reads a response body up to the size cap into memory, so the response
// can be rendered after another request has been made. The bytes past the cap
// are left on the wire for render to count. It reports false when the body
// cannot be read, and the caller then treats the response as unheld.
func (c *Client) hold(resp *http.Response) (*http.Response, bool) {
	reader := io.Reader(resp.Body)
	if c.maxResponseBytes > 0 {
		reader = io.LimitReader(resp.Body, int64(c.maxResponseBytes)+1)
	}
	head, err := io.ReadAll(reader)
	if err != nil {
		return resp, false
	}
	held := *resp
	held.Body = struct {
		io.Reader
		io.Closer
	}{io.MultiReader(bytes.NewReader(head), resp.Body), resp.Body}
	return &held, true
}

// resendable reports whether a request judged unauthenticated may be sent a
// second time after the re-login. A read can always be repeated. A write can
// only when the first attempt met a redirect to the identity provider: the
// proxy intercepted it, so the application never saw it. A 401 or an HTML
// 403 may have come from the application itself after it acted, and resending
// would apply the write twice.
func resendable(method string, reason auth.Reason) bool {
	switch strings.ToUpper(method) {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	}
	return reason == auth.ReasonIDPRedirect || reason == auth.ReasonCrossHost
}

// attempt issues one request and returns both the response and the request
// that produced it, because the detection rules read the request's Accept
// header and host.
func (c *Client) attempt(ctx context.Context, req *Request, s *session.Session) (*http.Response, *http.Request, error) {
	httpReq, err := build(ctx, req, s)
	if err != nil {
		return nil, nil, err
	}
	timeout := time.Duration(req.Domain.TimeoutSeconds) * time.Second
	client := c.newClient(timeout)
	// One jar per domain, so a token handed out by one response is still
	// paired with its session on the next request.
	client.Jar = c.jars.for_(req.Domain.Name, req.Domain.CookieNamePrefix)
	resp, err := client.Do(httpReq)
	if err != nil {
		if isTimeout(err) {
			return nil, nil, auth.Wrap(err, auth.CodeUpstreamTimeout, "",
				"request to %s exceeded timeout_seconds (%ds)", req.Domain.Name, req.Domain.TimeoutSeconds)
		}
		return nil, nil, auth.Wrap(err, auth.CodeUpstreamError,
			"check the host is reachable from this machine",
			"request to %s failed: %v", req.Domain.Name, err)
	}
	return resp, httpReq, nil
}

func isTimeout(err error) bool {
	var netErr interface{ Timeout() bool }
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}
	return errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded)
}

// render reads the body under the size cap and builds the model-facing result.
func (c *Client) render(resp *http.Response, authenticated, relogin bool) (*Response, error) {
	defer func() { _ = resp.Body.Close() }()

	limit := c.maxResponseBytes
	var body []byte
	var err error
	truncated := false
	consumed := 0
	if limit > 0 {
		// Read one byte past the cap so a body sitting exactly on the limit is
		// not mislabelled as truncated.
		body, err = io.ReadAll(io.LimitReader(resp.Body, int64(limit)+1))
		consumed = len(body)
		if len(body) > limit {
			body = body[:limit]
			truncated = true
		}
	} else {
		body, err = io.ReadAll(resp.Body)
	}
	if err != nil {
		return nil, auth.Wrap(err, auth.CodeUpstreamError, "", "reading response body: %v", err)
	}

	// Count what is left first, so the size is known before the body is encoded.
	var remaining int64
	if truncated {
		remaining, _ = io.Copy(io.Discard, resp.Body)
	}

	text := string(body)
	binary := !utf8.Valid(body)
	if binary {
		// Base64 rather than a lossy string. The truncation marker is left off:
		// appending text would corrupt the encoding, and Truncated already says
		// the body is short.
		text = base64.StdEncoding.EncodeToString(body)
	} else if truncated {
		text += fmt.Sprintf("\n…[truncated: %d bytes total]", int64(consumed)+remaining)
	}

	return &Response{
		Status:           resp.StatusCode,
		Headers:          safeHeaders(resp.Header),
		Body:             text,
		BodyBase64:       binary,
		Truncated:        truncated,
		Authenticated:    authenticated,
		ReloginPerformed: relogin,
	}, nil
}

// safeHeaders lowercases header names and drops Set-Cookie, which is the one
// header that could carry a session value back to the model.
func safeHeaders(h http.Header) map[string]string {
	out := make(map[string]string, len(h))
	for name, values := range h {
		if strings.EqualFold(name, "Set-Cookie") {
			continue
		}
		out[strings.ToLower(name)] = strings.Join(values, ", ")
	}
	return out
}

// drain releases a response we are about to discard so the connection can be
// reused for the retry.
func drain(resp *http.Response) {
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	_ = resp.Body.Close()
}
