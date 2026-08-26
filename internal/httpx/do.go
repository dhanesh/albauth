package httpx

import (
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
}

// Client issues authenticated requests, refreshing the session when the ALB
// says it has expired.
type Client struct {
	auth             Authenticator
	maxResponseBytes int
	newClient        func(timeout time.Duration) *http.Client
}

// NewClient builds a Client. maxResponseBytes bounds the body handed back to
// the model; a value of zero means unlimited.
func NewClient(a Authenticator, maxResponseBytes int) *Client {
	return &Client{auth: a, maxResponseBytes: maxResponseBytes, newClient: NewHTTPClient}
}

// Do performs the request, transparently authenticating.
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
		return c.render(resp, true, false)
	}
	drain(resp)

	refreshed, err := c.auth.Refresh(ctx, d, s)
	if err != nil {
		return nil, err
	}

	resp, httpReq, err = c.attempt(ctx, req, refreshed)
	if err != nil {
		return nil, err
	}
	if stillUnauthenticated, secondReason := auth.IsUnauthenticated(d, httpReq, resp); stillUnauthenticated {
		drain(resp)
		return nil, auth.Errorf(auth.CodeAuthLoop,
			"the session may be invalidated immediately; check the ALB listener rule scope for "+d.BaseURL,
			"domain %q is still unauthenticated after one re-login and retry (first: %s, second: %s)",
			d.Name, reason, secondReason)
	}
	return c.render(resp, true, true)
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
	resp, err := c.newClient(timeout).Do(httpReq)
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
