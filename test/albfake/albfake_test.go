package albfake

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
)

// get issues a request to the fake carrying the supplied cookies, without
// following redirects — the same posture albauth itself uses.
func get(t *testing.T, alb *ALB, path string, cookies map[string]string) *http.Response {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, alb.URL()+path, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	for name, value := range cookies {
		req.AddCookie(&http.Cookie{Name: name, Value: value})
	}
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

func TestUnauthenticatedRequestsRedirectToTheIdentityProvider(t *testing.T) {
	alb := New()
	t.Cleanup(alb.Close)

	resp := get(t, alb, "/v1/users", nil)
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status = %d, want 302", resp.StatusCode)
	}
	if !strings.Contains(resp.Header.Get("Location"), IDPHost) {
		t.Fatalf("Location = %q, want the identity provider host", resp.Header.Get("Location"))
	}
	if alb.Redirects.Load() != 1 || alb.Requests.Load() != 0 {
		t.Fatalf("counters = %d redirects, %d requests", alb.Redirects.Load(), alb.Requests.Load())
	}
}

func TestAValidSessionReachesTheAPI(t *testing.T) {
	alb := New()
	t.Cleanup(alb.Close)

	resp := get(t, alb, "/v1/users", alb.IssueSession("good"))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if alb.Requests.Load() != 1 {
		t.Fatalf("requests = %d, want 1", alb.Requests.Load())
	}
}

func TestEveryChunkIsRequired(t *testing.T) {
	alb := New()
	t.Cleanup(alb.Close)
	full := alb.IssueSession("chunked")

	partial := map[string]string{CookiePrefix + "-0": full[CookiePrefix+"-0"]}
	if resp := get(t, alb, "/v1/users", partial); resp.StatusCode != http.StatusFound {
		t.Fatalf("a partial session should be refused, got %d", resp.StatusCode)
	}

	// Chunks from two different sessions must not be accepted together.
	other := alb.IssueSession("other")
	mixed := map[string]string{
		CookiePrefix + "-0": full[CookiePrefix+"-0"],
		CookiePrefix + "-1": other[CookiePrefix+"-1"],
	}
	if resp := get(t, alb, "/v1/users", mixed); resp.StatusCode != http.StatusFound {
		t.Fatalf("mismatched chunks should be refused, got %d", resp.StatusCode)
	}

	// A chunk whose value does not carry its own index is malformed.
	malformed := map[string]string{
		CookiePrefix + "-0": "no-index-suffix",
		CookiePrefix + "-1": full[CookiePrefix+"-1"],
	}
	if resp := get(t, alb, "/v1/users", malformed); resp.StatusCode != http.StatusFound {
		t.Fatalf("a malformed chunk should be refused, got %d", resp.StatusCode)
	}
}

func TestExpireSession(t *testing.T) {
	alb := New()
	t.Cleanup(alb.Close)
	cookies := alb.IssueSession("temporary")

	if resp := get(t, alb, "/v1/users", cookies); resp.StatusCode != http.StatusOK {
		t.Fatalf("status before expiry = %d", resp.StatusCode)
	}
	alb.ExpireSession("temporary")
	if resp := get(t, alb, "/v1/users", cookies); resp.StatusCode != http.StatusFound {
		t.Fatalf("status after expiry = %d, want 302", resp.StatusCode)
	}
}

func TestRejectEverything(t *testing.T) {
	alb := New()
	t.Cleanup(alb.Close)
	cookies := alb.IssueSession("fresh")
	alb.RejectEverything.Store(true)

	if resp := get(t, alb, "/v1/users", cookies); resp.StatusCode != http.StatusFound {
		t.Fatalf("status = %d, want 302 for a load balancer refusing every session", resp.StatusCode)
	}
}

func TestTheCallbackPathIssuesEveryChunk(t *testing.T) {
	alb := New()
	t.Cleanup(alb.Close)

	resp := get(t, alb, "/oauth2/idpresponse?code=x", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	set := resp.Cookies()
	if len(set) != Chunks {
		t.Fatalf("callback set %d cookies, want %d", len(set), Chunks)
	}
	for i := range Chunks {
		want := fmt.Sprintf("%s-%d", CookiePrefix, i)
		found := false
		for _, c := range set {
			if c.Name == want {
				found = true
			}
		}
		if !found {
			t.Fatalf("callback did not set %s", want)
		}
	}
}

func TestCustomHandler(t *testing.T) {
	alb := New()
	t.Cleanup(alb.Close)
	alb.Handler = func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	}
	if resp := get(t, alb, "/v1/brew", alb.IssueSession("v")); resp.StatusCode != http.StatusTeapot {
		t.Fatalf("status = %d, want the custom handler's", resp.StatusCode)
	}
}

func TestHost(t *testing.T) {
	alb := New()
	t.Cleanup(alb.Close)
	if strings.Contains(alb.Host(), "://") {
		t.Fatalf("Host() = %q, want host:port with no scheme", alb.Host())
	}
	if !strings.HasSuffix(alb.URL(), alb.Host()) {
		t.Fatalf("URL() = %q and Host() = %q disagree", alb.URL(), alb.Host())
	}
}
