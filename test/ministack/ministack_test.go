//go:build ministack

// Package ministack drives albauth's real browser code against a real
// Application Load Balancer with an authenticate-oidc listener rule.
//
// Everything here is genuine except the cloud: a real Chrome, a real redirect
// to an identity provider, a real HTML login form, a real back-channel code
// exchange, and a real AWSELBAuthSessionCookie. It is the only suite that
// exercises internal/browser, which every other test replaces with a stub
// because it needs a running browser.
//
// Bring the world up first (see test/ministack/README.md), then:
//
//	go test -tags ministack -v -timeout 5m ./test/ministack/...
package ministack

import (
	"context"
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/chromedp/chromedp"

	"albauth/internal/auth"
	"albauth/internal/browser"
	"albauth/internal/config"
	"albauth/internal/httpx"
	"albauth/internal/session"
)

type fixture struct {
	BaseURL   string `json:"base_url"`
	ALBHost   string `json:"alb_host"`
	IDPHost   string `json:"idp_host"`
	LoginPath string `json:"login_path"`
	Username  string `json:"username"`
	Password  string `json:"password"`
}

func load(t *testing.T) *fixture {
	t.Helper()
	path := os.Getenv("ALBAUTH_MINISTACK_FIXTURE")
	if path == "" {
		path = filepath.Join(".", "fixture.json")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("no fixture at %s — run test/ministack/setup.sh first (%v)", path, err)
	}
	var f fixture
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatalf("fixture %s is not valid JSON: %v", path, err)
	}
	return &f
}

func (f *fixture) domain() *config.Domain {
	return &config.Domain{
		Name:                "local-alb",
		BaseURL:             f.BaseURL,
		Match:               []string{strings.Split(f.ALBHost, ":")[0]},
		LoginProbePath:      f.LoginPath,
		CookieNamePrefix:    config.DefaultCookieNamePrefix,
		IDPHostnames:        []string{strings.Split(f.IDPHost, ":")[0]},
		AllowMethods:        []string{"GET", "POST"},
		TimeoutSeconds:      30,
		LoginTimeoutSeconds: 45,
	}
}

// signIn completes the identity provider's login form in a browser profile,
// standing in for the human who would normally type their credentials.
//
// It is deliberately separate from albauth: albauth never touches a login form
// — it opens a window and waits, because a real provider means passwords, MFA
// and device trust. Once this has run, the provider's own session lives in the
// profile, which is what makes albauth's later login silent.
func signIn(t *testing.T, f *fixture, profileDir string) {
	t.Helper()
	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.Flag("headless", true),
		chromedp.UserDataDir(profileDir),
	)
	allocCtx, cancelAlloc := chromedp.NewExecAllocator(context.Background(), opts...)
	defer cancelAlloc()
	browserCtx, cancelBrowser := chromedp.NewContext(allocCtx)
	defer cancelBrowser()
	ctx, cancel := context.WithTimeout(browserCtx, 90*time.Second)
	defer cancel()

	target := f.BaseURL + f.LoginPath
	albHost := strings.Split(f.ALBHost, ":")[0]

	if err := chromedp.Run(ctx,
		chromedp.Navigate(target),
		chromedp.WaitVisible(`input[name="username"]`, chromedp.ByQuery),
		chromedp.SendKeys(`input[name="username"]`, f.Username, chromedp.ByQuery),
		chromedp.SendKeys(`input[name="password"]`, f.Password, chromedp.ByQuery),
		chromedp.Click(`button[type="submit"]`, chromedp.ByQuery),
	); err != nil {
		t.Fatalf("could not complete the provider login form: %v", err)
	}

	// Submitting is not the end of it. The provider redirects to the load
	// balancer's callback, which exchanges the code and only then writes the
	// session. Waiting for the browser to arrive back on the load balancer's
	// own host is what tells us the session exists in this profile.
	deadline := time.Now().Add(60 * time.Second)
	for {
		var current string
		if err := chromedp.Run(ctx, chromedp.Location(&current)); err != nil {
			t.Fatalf("reading the browser location: %v", err)
		}
		// Compare the parsed host, never a substring: the load balancer's own
		// hostname appears inside the redirect_uri query parameter on the
		// provider's page, so a substring test matches while still on it.
		if parsed, err := url.Parse(current); err == nil && strings.EqualFold(parsed.Hostname(), albHost) {
			t.Logf("provider login complete; browser is back on %s", current)
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("login did not return to %s within 60s; stuck on %s", albHost, current)
		}
		time.Sleep(300 * time.Millisecond)
	}

	// Close this browser before anyone else opens the same profile. Chrome
	// holds an exclusive lock on a user-data-dir, so a second instance started
	// while this one is still shutting down blocks until the lock clears —
	// which looks exactly like a hung login.
	if err := chromedp.Cancel(browserCtx); err != nil {
		t.Logf("closing the sign-in browser: %v", err)
	}
}

// The headline case: albauth's own browser driver captures a session from a real
// load balancer, and that session then authenticates a real API call.
func TestBrowserLoginCapturesARealALBSession(t *testing.T) {
	f := load(t)
	domain := f.domain()
	profileDir := t.TempDir()

	// A human logs in once. After this the profile holds a live load-balancer
	// session, which is the state albauth's own login has to recognise.
	t.Log("completing the provider login…")
	signIn(t, f, profileDir)
	t.Log("handing over to albauth's browser driver…")

	// albauth then takes over, driving the same profile. Because the provider
	// still recognises the browser, this completes without interaction — the
	// silent re-authentication albauth promises.
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()

	loginer := &browser.Loginer{Headless: true}
	start := time.Now()
	cookies, err := loginer.Login(ctx, domain, profileDir)
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	t.Logf("captured %d cookie(s) in %s with no interaction", len(cookies), time.Since(start).Round(time.Millisecond))

	if len(cookies) == 0 {
		t.Fatal("no session cookie was captured")
	}
	for _, c := range cookies {
		if !strings.HasPrefix(c.Name, config.DefaultCookieNamePrefix) {
			t.Fatalf("captured a cookie that is not part of the session: %q", c.Name)
		}
		if c.Value == "" {
			t.Fatalf("%s has an empty value", c.Name)
		}
		if c.Expires.IsZero() {
			t.Fatalf("%s carries no expiry; session expiry detection depends on it", c.Name)
		}
		t.Logf("  %s: %d bytes, expires %s", c.Name, len(c.Value), c.Expires.UTC().Format(time.RFC3339))
	}

	// The captured session must actually work against the load balancer.
	store := session.NewMemoryStore()
	mgr := auth.NewManager(auth.ManagerOptions{Store: store, Loginer: loginer})
	if err := mgr.Save(domain.Name, &session.Session{
		Cookies: cookies, AcquiredAt: time.Now(), LastUsedAt: time.Now(),
	}); err != nil {
		t.Fatalf("Save: %v", err)
	}

	resp, err := httpx.NewClient(mgr, 1<<20).Do(ctx, &httpx.Request{
		Domain: domain, Method: "GET", URL: f.BaseURL + "/v1/users",
	})
	if err != nil {
		t.Fatalf("authenticated request: %v", err)
	}
	if resp.Status != 200 {
		t.Fatalf("status = %d, body = %s", resp.Status, resp.Body)
	}
	if resp.ReloginPerformed {
		t.Fatal("a freshly captured session should not need re-authenticating")
	}

	// The load balancer only injects these once it has authenticated the caller,
	// so seeing them proves the request really went through the auth layer
	// rather than around it.
	var target struct {
		Path             string `json:"path"`
		OIDCIdentity     string `json:"oidc_identity"`
		OIDCDataPresent  bool   `json:"oidc_data_present"`
		OIDCTokenPresent bool   `json:"oidc_accesstoken_present"`
	}
	if err := json.Unmarshal([]byte(resp.Body), &target); err != nil {
		t.Fatalf("target response is not JSON: %v\n%s", err, resp.Body)
	}
	if target.OIDCIdentity == "" || !target.OIDCDataPresent || !target.OIDCTokenPresent {
		t.Fatalf("the target did not receive the caller's identity: %+v", target)
	}
	t.Logf("target saw identity %s with the OIDC data and access token attached", target.OIDCIdentity)
}

// An unauthenticated request must be recognised as such — this is the detection
// logic running against a genuine load balancer redirect rather than a fake.
func TestUnauthenticatedRequestIsDetectedAgainstARealALB(t *testing.T) {
	f := load(t)
	domain := f.domain()

	store := session.NewMemoryStore()
	// No Loginer: the re-login attempt must fail cleanly rather than hang or
	// silently return the identity provider's login page as if it were data.
	mgr := auth.NewManager(auth.ManagerOptions{Store: store})

	_, err := httpx.NewClient(mgr, 1<<20).Do(t.Context(), &httpx.Request{
		Domain: domain, Method: "GET", URL: f.BaseURL + "/v1/users",
	})
	if err == nil {
		t.Fatal("a request with no session must not appear to succeed")
	}
	coded, ok := errorsAsCoded(err)
	if !ok {
		t.Fatalf("error is not coded: %v", err)
	}
	if coded.Code != auth.CodeNoBrowser {
		t.Fatalf("error code = %q, want %q — the redirect to the identity provider "+
			"should have been recognised as an expired session (%v)",
			coded.Code, auth.CodeNoBrowser, err)
	}
}

func errorsAsCoded(err error) (*auth.Error, bool) {
	var coded *auth.Error
	for e := err; e != nil; {
		if c, ok := e.(*auth.Error); ok {
			coded = c
			return coded, true
		}
		u, ok := e.(interface{ Unwrap() error })
		if !ok {
			break
		}
		e = u.Unwrap()
	}
	return nil, false
}
