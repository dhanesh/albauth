//go:build manual

// Package manual holds the one test that drives a real browser.
//
// It is build-tagged out of every automatic run because it needs Chrome, a
// reachable load balancer, and a human to complete the identity-provider flow.
// Run it deliberately:
//
//	ALBAUTH_MANUAL_BASE_URL=https://api.example.com \
//	  go test -tags manual -v -timeout 5m ./test/manual/...
package manual

import (
	"context"
	"os"
	"testing"
	"time"

	"albauth/internal/browser"
	"albauth/internal/config"
)

func TestRealBrowserLogin(t *testing.T) {
	baseURL := os.Getenv("ALBAUTH_MANUAL_BASE_URL")
	if baseURL == "" {
		t.Skip("set ALBAUTH_MANUAL_BASE_URL to the base URL of a real protected domain")
	}

	domain := &config.Domain{
		Name:                "manual",
		BaseURL:             baseURL,
		LoginProbePath:      envOr("ALBAUTH_MANUAL_PROBE_PATH", "/"),
		CookieNamePrefix:    envOr("ALBAUTH_MANUAL_COOKIE_PREFIX", config.DefaultCookieNamePrefix),
		LoginTimeoutSeconds: 180,
	}

	ctx, cancel := context.WithTimeout(t.Context(), 4*time.Minute)
	defer cancel()

	t.Logf("a browser window will open; complete the login for %s", baseURL)
	cookies, err := browser.New().Login(ctx, domain, t.TempDir())
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	if len(cookies) == 0 {
		t.Fatal("the flow completed but no session cookie was captured")
	}
	for _, c := range cookies {
		// The value itself is never logged, only its shape.
		t.Logf("captured %s (%d bytes, expires %s)", c.Name, len(c.Value), c.Expires)
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
