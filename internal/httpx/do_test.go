package httpx

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"albauth/internal/auth"
	"albauth/internal/config"
	"albauth/internal/session"
	"albauth/test/albfake"
)

// stubAuth stands in for auth.Manager, counting re-logins so the retry-once
// rule and the single-flight rule can be asserted directly.
type stubAuth struct {
	mu          sync.Mutex
	current     *session.Session
	next        func() *session.Session
	ensureErr   error
	refreshErr  error
	refreshes   atomic.Int32
	ensureCalls atomic.Int32
}

func (s *stubAuth) Ensure(context.Context, *config.Domain) (*session.Session, error) {
	s.ensureCalls.Add(1)
	if s.ensureErr != nil {
		return nil, s.ensureErr
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.current, nil
}

func (s *stubAuth) Refresh(context.Context, *config.Domain, *session.Session) (*session.Session, error) {
	s.refreshes.Add(1)
	if s.refreshErr != nil {
		return nil, s.refreshErr
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.next != nil {
		s.current = s.next()
	}
	return s.current, nil
}

func sessionFrom(cookies map[string]string) *session.Session {
	s := &session.Session{AcquiredAt: time.Now(), LastUsedAt: time.Now()}
	for name, value := range cookies {
		s.Cookies = append(s.Cookies, session.Cookie{
			Name: name, Value: value, Path: "/", Expires: time.Now().Add(time.Hour),
		})
	}
	return s
}

func albDomain(alb *albfake.ALB) *config.Domain {
	return &config.Domain{
		Name: "api", BaseURL: alb.URL(), Match: []string{alb.Host()},
		CookieNamePrefix: albfake.CookiePrefix,
		IDPHostnames:     []string{albfake.IDPHost},
		AllowMethods:     []string{"GET", "POST"},
		TimeoutSeconds:   5, LoginTimeoutSeconds: 5,
	}
}

func TestDoSucceedsWithAValidSession(t *testing.T) {
	alb := albfake.New()
	t.Cleanup(alb.Close)

	a := &stubAuth{current: sessionFrom(alb.IssueSession("good"))}
	client := NewClient(a, 1<<20)
	d := albDomain(alb)

	resp, err := client.Do(t.Context(), &Request{Domain: d, Method: "GET", URL: alb.URL() + "/v1/users"})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if resp.Status != 200 || !resp.Authenticated || resp.ReloginPerformed || resp.Truncated {
		t.Fatalf("response = %+v", resp)
	}
	if !strings.Contains(resp.Body, `"path":"/v1/users"`) {
		t.Fatalf("body = %q", resp.Body)
	}
	if a.refreshes.Load() != 0 {
		t.Fatalf("performed %d re-logins for a valid session, want 0", a.refreshes.Load())
	}
}

// The headline behaviour: an expired session triggers exactly one re-login and
// one retry, and the result says so.
func TestDoReAuthenticatesOnceWhenTheSessionHasExpired(t *testing.T) {
	alb := albfake.New()
	t.Cleanup(alb.Close)

	stale := sessionFrom(alb.IssueSession("stale"))
	alb.ExpireSession("stale")
	a := &stubAuth{
		current: stale,
		next:    func() *session.Session { return sessionFrom(alb.IssueSession("fresh")) },
	}
	client := NewClient(a, 1<<20)

	resp, err := client.Do(t.Context(), &Request{
		Domain: albDomain(alb), Method: "GET", URL: alb.URL() + "/v1/users"})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if resp.Status != 200 || !resp.ReloginPerformed {
		t.Fatalf("response = %+v, want a successful retry with relogin_performed", resp)
	}
	if got := a.refreshes.Load(); got != 1 {
		t.Fatalf("performed %d re-logins, want exactly 1", got)
	}
	if got := alb.Redirects.Load(); got != 1 {
		t.Fatalf("the load balancer bounced %d requests, want 1", got)
	}
}

// A session the load balancer rejects however fresh must not loop: one retry,
// then a clear error.
func TestDoRetriesExactlyOnceThenReportsAnAuthLoop(t *testing.T) {
	alb := albfake.New()
	t.Cleanup(alb.Close)
	alb.RejectEverything.Store(true)

	a := &stubAuth{
		current: sessionFrom(alb.IssueSession("never-accepted")),
		next:    func() *session.Session { return sessionFrom(alb.IssueSession("also-rejected")) },
	}
	client := NewClient(a, 1<<20)

	_, err := client.Do(t.Context(), &Request{
		Domain: albDomain(alb), Method: "GET", URL: alb.URL() + "/v1/users"})
	assertCode(t, err, auth.CodeAuthLoop)
	if got := a.refreshes.Load(); got != 1 {
		t.Fatalf("performed %d re-logins, want exactly 1 — the loop must not repeat", got)
	}
	if got := alb.Redirects.Load(); got != 2 {
		t.Fatalf("issued %d requests, want exactly 2 (original plus one retry)", got)
	}
	if !strings.Contains(err.Error(), "listener rule") {
		t.Fatalf("the hint should point at the listener rule, got: %v", err)
	}
}

// Every chunk of a split session must be replayed, or the load balancer cannot
// reassemble it.
func TestDoReplaysEveryCookieChunk(t *testing.T) {
	alb := albfake.New()
	t.Cleanup(alb.Close)

	var seen []string
	alb.Handler = func(w http.ResponseWriter, r *http.Request) {
		for _, c := range r.Cookies() {
			seen = append(seen, c.Name)
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{}`)
	}

	a := &stubAuth{current: sessionFrom(alb.IssueSession("chunked"))}
	if _, err := NewClient(a, 1<<20).Do(t.Context(), &Request{
		Domain: albDomain(alb), Method: "GET", URL: alb.URL() + "/v1/users"}); err != nil {
		t.Fatalf("Do: %v", err)
	}
	for i := range albfake.Chunks {
		want := fmt.Sprintf("%s-%d", albfake.CookiePrefix, i)
		if !containsString(seen, want) {
			t.Fatalf("chunk %s was not replayed; sent %v", want, seen)
		}
	}
}

func TestDoSendsQueryHeadersAndBody(t *testing.T) {
	alb := albfake.New()
	t.Cleanup(alb.Close)

	var gotQuery, gotHeader, gotDomainHeader, gotAccept, gotBody, gotMethod string
	alb.Handler = func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
		gotHeader = r.Header.Get("X-Request-Id")
		gotDomainHeader = r.Header.Get("X-Client")
		gotAccept = r.Header.Get("Accept")
		gotMethod = r.Method
		buf := make([]byte, r.ContentLength)
		_, _ = r.Body.Read(buf)
		gotBody = string(buf)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{}`)
	}

	d := albDomain(alb)
	d.Headers = map[string]string{"X-Client": "albauth"}
	a := &stubAuth{current: sessionFrom(alb.IssueSession("v"))}

	_, err := NewClient(a, 1<<20).Do(t.Context(), &Request{
		Domain: d, Method: "POST", URL: alb.URL() + "/v1/users?existing=1",
		Query:   map[string]string{"page": "2"},
		Headers: map[string]string{"X-Request-Id": "abc", "Accept": "application/vnd.api+json"},
		Body:    `{"name":"x"}`,
	})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if !strings.Contains(gotQuery, "page=2") || !strings.Contains(gotQuery, "existing=1") {
		t.Fatalf("query = %q, want both the URL's and the argument's parameters", gotQuery)
	}
	if gotHeader != "abc" || gotDomainHeader != "albauth" {
		t.Fatalf("headers = %q, %q", gotHeader, gotDomainHeader)
	}
	// A caller-supplied Accept wins over the JSON default.
	if gotAccept != "application/vnd.api+json" {
		t.Fatalf("Accept = %q", gotAccept)
	}
	if gotBody != `{"name":"x"}` || gotMethod != "POST" {
		t.Fatalf("body = %q, method = %q", gotBody, gotMethod)
	}
}

func TestDoDefaultsAcceptToJSON(t *testing.T) {
	alb := albfake.New()
	t.Cleanup(alb.Close)
	var gotAccept string
	alb.Handler = func(w http.ResponseWriter, r *http.Request) {
		gotAccept = r.Header.Get("Accept")
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{}`)
	}
	a := &stubAuth{current: sessionFrom(alb.IssueSession("v"))}
	if _, err := NewClient(a, 1<<20).Do(t.Context(), &Request{
		Domain: albDomain(alb), Method: "GET", URL: alb.URL() + "/v1/users"}); err != nil {
		t.Fatalf("Do: %v", err)
	}
	if gotAccept != "application/json" {
		t.Fatalf("Accept = %q, want the JSON default", gotAccept)
	}
}

// A non-2xx is the caller's business, not a tool error: the model needs to see
// the status and body to reason about it.
func TestDoReturnsNon2xxAsAResultNotAnError(t *testing.T) {
	alb := albfake.New()
	t.Cleanup(alb.Close)
	alb.Handler = func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, `{"error":"no such user"}`)
	}
	a := &stubAuth{current: sessionFrom(alb.IssueSession("v"))}

	resp, err := NewClient(a, 1<<20).Do(t.Context(), &Request{
		Domain: albDomain(alb), Method: "GET", URL: alb.URL() + "/v1/users/999"})
	if err != nil {
		t.Fatalf("a 404 must not be a tool error, got: %v", err)
	}
	if resp.Status != 404 || !strings.Contains(resp.Body, "no such user") {
		t.Fatalf("response = %+v", resp)
	}
}

// An application's own HTML error page is its answer to a JSON request, not a
// login page leaking through: it comes back once, with no re-login and no
// retry. Only a 401 or 403 page reads as the proxy's "no session".
func TestDoReturnsApplicationHTMLErrors(t *testing.T) {
	for _, status := range []int{404, 500, 502, 503} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			alb := albfake.New()
			t.Cleanup(alb.Close)
			var hits atomic.Int32
			alb.Handler = func(w http.ResponseWriter, r *http.Request) {
				hits.Add(1)
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				w.WriteHeader(status)
				fmt.Fprintf(w, "<html><body>error %d</body></html>", status)
			}
			a := &stubAuth{current: sessionFrom(alb.IssueSession("v"))}

			resp, err := NewClient(a, 1<<20).Do(t.Context(), &Request{
				Domain: albDomain(alb), Method: "GET", URL: alb.URL() + "/v1/users"})
			if err != nil {
				t.Fatalf("an HTML %d must be a result, got: %v", status, err)
			}
			if resp.Status != status || resp.ReloginPerformed ||
				!strings.Contains(resp.Body, fmt.Sprintf("error %d", status)) {
				t.Fatalf("response = %+v", resp)
			}
			if got := a.refreshes.Load(); got != 0 {
				t.Fatalf("performed %d re-logins, want 0", got)
			}
			if got := hits.Load(); got != 1 {
				t.Fatalf("the application saw %d requests, want 1", got)
			}
		})
	}
}

func TestDoStripsSetCookieFromReturnedHeaders(t *testing.T) {
	alb := albfake.New()
	t.Cleanup(alb.Close)
	alb.Handler = func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: albfake.CookiePrefix + "-0", Value: "leaked-value"})
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Custom", "kept")
		fmt.Fprint(w, `{}`)
	}
	a := &stubAuth{current: sessionFrom(alb.IssueSession("v"))}

	resp, err := NewClient(a, 1<<20).Do(t.Context(), &Request{
		Domain: albDomain(alb), Method: "GET", URL: alb.URL() + "/v1/users"})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	encoded, _ := json.Marshal(resp)
	if strings.Contains(string(encoded), "leaked-value") {
		t.Fatalf("a cookie value reached the model-facing result: %s", encoded)
	}
	for name := range resp.Headers {
		if strings.EqualFold(name, "set-cookie") {
			t.Fatalf("Set-Cookie survived: %v", resp.Headers)
		}
	}
	// Header names are lower-cased, and everything else is kept.
	if resp.Headers["x-custom"] != "kept" {
		t.Fatalf("headers = %v", resp.Headers)
	}
}

func TestDoTruncatesAnOversizedBody(t *testing.T) {
	alb := albfake.New()
	t.Cleanup(alb.Close)
	const total = 5000
	alb.Handler = func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, strings.Repeat("x", total))
	}
	a := &stubAuth{current: sessionFrom(alb.IssueSession("v"))}

	resp, err := NewClient(a, 100).Do(t.Context(), &Request{
		Domain: albDomain(alb), Method: "GET", URL: alb.URL() + "/v1/big"})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if !resp.Truncated {
		t.Fatal("an oversized body must be marked truncated")
	}
	if !strings.HasPrefix(resp.Body, strings.Repeat("x", 100)) {
		t.Fatalf("body should start with the first 100 bytes, got %d chars", len(resp.Body))
	}
	if !strings.Contains(resp.Body, fmt.Sprintf("[truncated: %d bytes total]", total)) {
		t.Fatalf("the marker should report the real total, got: %q", resp.Body[len(resp.Body)-60:])
	}
}

func TestDoDoesNotMarkAnExactlyFittingBodyAsTruncated(t *testing.T) {
	alb := albfake.New()
	t.Cleanup(alb.Close)
	alb.Handler = func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, strings.Repeat("x", 100))
	}
	a := &stubAuth{current: sessionFrom(alb.IssueSession("v"))}

	resp, err := NewClient(a, 100).Do(t.Context(), &Request{
		Domain: albDomain(alb), Method: "GET", URL: alb.URL() + "/v1/exact"})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if resp.Truncated {
		t.Fatal("a body exactly at the limit is not truncated")
	}
	if len(resp.Body) != 100 {
		t.Fatalf("body length = %d, want 100", len(resp.Body))
	}
}

func TestDoWithNoSizeLimitReadsTheWholeBody(t *testing.T) {
	alb := albfake.New()
	t.Cleanup(alb.Close)
	alb.Handler = func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, strings.Repeat("y", 3000))
	}
	a := &stubAuth{current: sessionFrom(alb.IssueSession("v"))}

	resp, err := NewClient(a, 0).Do(t.Context(), &Request{
		Domain: albDomain(alb), Method: "GET", URL: alb.URL() + "/v1/big"})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if resp.Truncated || len(resp.Body) != 3000 {
		t.Fatalf("truncated = %v, length = %d", resp.Truncated, len(resp.Body))
	}
}

func TestDoPropagatesAuthenticationFailures(t *testing.T) {
	alb := albfake.New()
	t.Cleanup(alb.Close)

	t.Run("the initial login fails", func(t *testing.T) {
		a := &stubAuth{ensureErr: auth.Errorf(auth.CodeNoBrowser, "install Chrome", "no browser")}
		_, err := NewClient(a, 1<<20).Do(t.Context(), &Request{
			Domain: albDomain(alb), Method: "GET", URL: alb.URL() + "/v1/users"})
		assertCode(t, err, auth.CodeNoBrowser)
	})

	t.Run("the re-login fails", func(t *testing.T) {
		alb.ExpireSession("gone")
		a := &stubAuth{
			current:    sessionFrom(map[string]string{albfake.CookiePrefix + "-0": "gone.0"}),
			refreshErr: auth.Errorf(auth.CodeLoginTimeout, "raise the timeout", "timed out"),
		}
		_, err := NewClient(a, 1<<20).Do(t.Context(), &Request{
			Domain: albDomain(alb), Method: "GET", URL: alb.URL() + "/v1/users"})
		assertCode(t, err, auth.CodeLoginTimeout)
	})
}

func TestDoReportsTransportFailures(t *testing.T) {
	alb := albfake.New()
	d := albDomain(alb)
	a := &stubAuth{current: sessionFrom(alb.IssueSession("v"))}
	alb.Close() // nothing is listening any more

	_, err := NewClient(a, 1<<20).Do(t.Context(), &Request{
		Domain: d, Method: "GET", URL: d.BaseURL + "/v1/users"})
	assertCode(t, err, auth.CodeUpstreamError)
}

func TestDoReportsATimeout(t *testing.T) {
	alb := albfake.New()
	t.Cleanup(alb.Close)
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	alb.Handler = func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}

	d := albDomain(alb)
	d.TimeoutSeconds = 1
	a := &stubAuth{current: sessionFrom(alb.IssueSession("v"))}

	start := time.Now()
	_, err := NewClient(a, 1<<20).Do(t.Context(), &Request{
		Domain: d, Method: "GET", URL: alb.URL() + "/v1/slow"})
	assertCode(t, err, auth.CodeUpstreamTimeout)
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("the request took %s; timeout_seconds was not honoured", elapsed)
	}
}

func TestDoRejectsAnUnbuildableRequest(t *testing.T) {
	a := &stubAuth{current: &session.Session{}}
	d := &config.Domain{Name: "api", BaseURL: "https://api.example.com", TimeoutSeconds: 5}

	_, err := NewClient(a, 1<<20).Do(t.Context(), &Request{Domain: d, Method: "GET", URL: "https://exa mple.com/x"})
	assertCode(t, err, auth.CodeInvalidRequest)

	_, err = NewClient(a, 1<<20).Do(t.Context(), &Request{Domain: d, Method: "IN VALID", URL: "https://api.example.com/x"})
	assertCode(t, err, auth.CodeInvalidRequest)
}

func TestRenderReportsABodyReadFailure(t *testing.T) {
	resp := &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       errBody{errors.New("connection reset")},
	}
	_, err := NewClient(&stubAuth{}, 1<<20).render(resp, true, false)
	assertCode(t, err, auth.CodeUpstreamError)
}

func TestNoRedirectKeepsRedirectsVisible(t *testing.T) {
	if err := noRedirect(nil, nil); !errors.Is(err, http.ErrUseLastResponse) {
		t.Fatalf("noRedirect returned %v, want http.ErrUseLastResponse", err)
	}
	if got := NewHTTPClient(3 * time.Second); got.Timeout != 3*time.Second || got.CheckRedirect == nil {
		t.Fatalf("NewHTTPClient = %+v", got)
	}
}

func TestIsTimeout(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"context deadline", context.DeadlineExceeded, true},
		{"os deadline", errFromOS(), true},
		{"a net error that reports a timeout", timeoutError{}, true},
		{"a plain error", errors.New("connection refused"), false},
		{"wrapped", fmt.Errorf("dial: %w", context.DeadlineExceeded), true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := isTimeout(tc.err); got != tc.want {
				t.Fatalf("isTimeout(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

// --- helpers ---------------------------------------------------------------

type errBody struct{ err error }

func (e errBody) Read([]byte) (int, error) { return 0, e.err }
func (e errBody) Close() error             { return nil }

type timeoutError struct{}

func (timeoutError) Error() string { return "i/o timeout" }
func (timeoutError) Timeout() bool { return true }

func containsString(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}

func errFromOS() error { return os.ErrDeadlineExceeded }

// The retry leg can fail at the transport just as the first attempt can, and
// that failure must surface rather than being reported as an auth loop.
func TestDoReportsATransportFailureOnTheRetry(t *testing.T) {
	alb := albfake.New()
	d := albDomain(alb)

	stale := sessionFrom(alb.IssueSession("stale"))
	alb.ExpireSession("stale")
	a := &stubAuth{current: stale, next: func() *session.Session {
		alb.Close() // the upstream disappears between the two attempts
		return stale
	}}

	_, err := NewClient(a, 1<<20).Do(t.Context(), &Request{
		Domain: d, Method: "GET", URL: d.BaseURL + "/v1/users"})
	assertCode(t, err, auth.CodeUpstreamError)
	if got := a.refreshes.Load(); got != 1 {
		t.Fatalf("performed %d re-logins, want 1", got)
	}
}

// A response that is not valid UTF-8 must survive intact. Returned as a plain
// string it would be silently corrupted — invalid sequences replaced — and the
// caller would receive something that looks like text and is not.
func TestDoReturnsBinaryBodiesAsBase64(t *testing.T) {
	alb := albfake.New()
	t.Cleanup(alb.Close)

	// A real PNG header: the leading 0x89 is exactly what a UTF-8 round trip
	// destroys.
	png := []byte{0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0xff, 0xfe}
	alb.Handler = func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/png")
		_, _ = w.Write(png)
	}
	a := &stubAuth{current: sessionFrom(alb.IssueSession("v"))}

	resp, err := NewClient(a, 1<<20).Do(t.Context(), &Request{
		Domain: albDomain(alb), Method: "GET", URL: alb.URL() + "/render"})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if !resp.BodyBase64 {
		t.Fatal("a non-UTF-8 body must be reported as base64")
	}
	decoded, err := base64.StdEncoding.DecodeString(resp.Body)
	if err != nil {
		t.Fatalf("body is not valid base64: %v", err)
	}
	if !bytes.Equal(decoded, png) {
		t.Fatalf("bytes did not survive: got %x, want %x", decoded, png)
	}
}

func TestDoLeavesTextBodiesAlone(t *testing.T) {
	alb := albfake.New()
	t.Cleanup(alb.Close)
	alb.Handler = func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"ok":true,"unicode":"héllo ✅"}`)
	}
	a := &stubAuth{current: sessionFrom(alb.IssueSession("v"))}

	resp, err := NewClient(a, 1<<20).Do(t.Context(), &Request{
		Domain: albDomain(alb), Method: "GET", URL: alb.URL() + "/v1/x"})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if resp.BodyBase64 {
		t.Fatal("valid UTF-8 must not be base64-encoded")
	}
	if !strings.Contains(resp.Body, "héllo ✅") {
		t.Fatalf("multi-byte UTF-8 was mangled: %q", resp.Body)
	}
}

// Appending the truncation marker to base64 would corrupt the encoding, so a
// truncated binary body relies on the Truncated field instead.
func TestDoDoesNotAppendTheTruncationMarkerToBase64(t *testing.T) {
	alb := albfake.New()
	t.Cleanup(alb.Close)
	blob := bytes.Repeat([]byte{0xff, 0xfe, 0x00}, 500) // 1500 bytes, never valid UTF-8
	alb.Handler = func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(blob)
	}
	a := &stubAuth{current: sessionFrom(alb.IssueSession("v"))}

	resp, err := NewClient(a, 100).Do(t.Context(), &Request{
		Domain: albDomain(alb), Method: "GET", URL: alb.URL() + "/blob"})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if !resp.Truncated || !resp.BodyBase64 {
		t.Fatalf("truncated=%v base64=%v", resp.Truncated, resp.BodyBase64)
	}
	if strings.Contains(resp.Body, "truncated:") {
		t.Fatal("the marker must not be appended to a base64 body")
	}
	decoded, err := base64.StdEncoding.DecodeString(resp.Body)
	if err != nil {
		t.Fatalf("truncated base64 is not decodable: %v", err)
	}
	if !bytes.Equal(decoded, blob[:100]) {
		t.Fatalf("decoded %d bytes, want the first 100", len(decoded))
	}
}

// A token handed out by one response is often only valid alongside a session
// cookie set at the same moment. Without a jar the second request arrives with
// a valid-looking token and nothing to pair it with, and every write fails.
func TestApplicationCookiesPersistAcrossRequests(t *testing.T) {
	alb := albfake.New()
	t.Cleanup(alb.Close)

	var seenOnSecond string
	first := true
	alb.Handler = func(w http.ResponseWriter, r *http.Request) {
		if first {
			first = false
			http.SetCookie(w, &http.Cookie{Name: "JSESSIONID", Value: "app-session-1", Path: "/"})
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"crumb":"abc"}`)
			return
		}
		if c, err := r.Cookie("JSESSIONID"); err == nil {
			seenOnSecond = c.Value
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"ok":true}`)
	}

	a := &stubAuth{current: sessionFrom(alb.IssueSession("v"))}
	client := NewClient(a, 1<<20)
	d := albDomain(alb)

	if _, err := client.Do(t.Context(), &Request{Domain: d, Method: "GET", URL: alb.URL() + "/crumb"}); err != nil {
		t.Fatalf("first: %v", err)
	}
	if _, err := client.Do(t.Context(), &Request{Domain: d, Method: "POST", URL: alb.URL() + "/create"}); err != nil {
		t.Fatalf("second: %v", err)
	}
	if seenOnSecond != "app-session-1" {
		t.Fatalf("the application session did not carry over: got %q", seenOnSecond)
	}
}

// The load balancer's own cookies live in the session store. Letting the jar
// keep them as well would send each of them twice.
func TestTheJarIgnoresLoadBalancerCookies(t *testing.T) {
	alb := albfake.New()
	t.Cleanup(alb.Close)

	var counts []int
	alb.Handler = func(w http.ResponseWriter, r *http.Request) {
		n := 0
		for _, c := range r.Cookies() {
			if strings.HasPrefix(c.Name, albfake.CookiePrefix) {
				n++
			}
		}
		counts = append(counts, n)
		// Re-issue a session cookie, as a real load balancer refreshing one would.
		http.SetCookie(w, &http.Cookie{Name: albfake.CookiePrefix + "-0", Value: "refreshed", Path: "/"})
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{}`)
	}

	a := &stubAuth{current: sessionFrom(alb.IssueSession("v"))}
	client := NewClient(a, 1<<20)
	d := albDomain(alb)
	for i := range 3 {
		if _, err := client.Do(t.Context(), &Request{
			Domain: d, Method: "GET", URL: alb.URL() + "/x"}); err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
	}
	for i, n := range counts {
		if n != albfake.Chunks {
			t.Fatalf("request %d carried %d session cookies, want %d — the jar is duplicating them",
				i, n, albfake.Chunks)
		}
	}
}

func TestJarsAreIsolatedPerDomainAndClearedOnLogout(t *testing.T) {
	alb := albfake.New()
	t.Cleanup(alb.Close)
	var seen []string
	alb.Handler = func(w http.ResponseWriter, r *http.Request) {
		if c, err := r.Cookie("APPSESSION"); err == nil {
			seen = append(seen, c.Value)
		} else {
			seen = append(seen, "-")
		}
		http.SetCookie(w, &http.Cookie{Name: "APPSESSION", Value: "s1", Path: "/"})
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{}`)
	}

	a := &stubAuth{current: sessionFrom(alb.IssueSession("v"))}
	client := NewClient(a, 1<<20)
	one := albDomain(alb)
	two := albDomain(alb)
	two.Name = "other"

	do := func(d *config.Domain) {
		if _, err := client.Do(t.Context(), &Request{Domain: d, Method: "GET", URL: alb.URL() + "/x"}); err != nil {
			t.Fatalf("Do: %v", err)
		}
	}
	do(one) // no cookie yet
	do(one) // carries s1
	do(two) // a different domain must not inherit it
	client.ForgetCookies(one.Name)
	do(one) // forgotten, so no cookie again

	want := []string{"-", "s1", "-", "-"}
	if len(seen) != len(want) {
		t.Fatalf("got %v", seen)
	}
	for i := range want {
		if seen[i] != want[i] {
			t.Fatalf("request %d saw %q, want %q (all: %v)", i, seen[i], want[i], seen)
		}
	}
}

// Whatever the jar holds, a cookie value must never be handed back.
func TestSetCookieIsStillStrippedFromResponses(t *testing.T) {
	alb := albfake.New()
	t.Cleanup(alb.Close)
	alb.Handler = func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "JSESSIONID", Value: "must-not-escape", Path: "/"})
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{}`)
	}
	a := &stubAuth{current: sessionFrom(alb.IssueSession("v"))}
	resp, err := NewClient(a, 1<<20).Do(t.Context(), &Request{
		Domain: albDomain(alb), Method: "GET", URL: alb.URL() + "/x"})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	encoded, _ := json.Marshal(resp)
	if strings.Contains(string(encoded), "must-not-escape") {
		t.Fatalf("a session value reached the caller: %s", encoded)
	}
}
