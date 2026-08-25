// Package browser drives a real, headed Chrome session to complete an
// interactive identity-provider login and reads the resulting ALB cookies out
// of the browser's cookie store.
//
// Why a real browser: the ALB only accepts its own session cookie, which is set
// on the load balancer's hostname by the browser after the user completes the
// provider flow. A plain HTTP client cannot get one — an OAuth callback yields
// an ID token the ALB will not accept, and scripting the provider's login form
// breaks on password, MFA and device-trust steps. So albmcp lets a human do the
// part only a human can do, then takes the cookie.
//
// Coverage note: this file is the one package excluded from the 100% unit-test
// gate, because every statement in it needs a running Chrome. It is kept small
// and free of decision logic for that reason — everything testable lives in
// internal/auth behind the Loginer interface, and the real path is exercised by
// the build-tagged manual test in test/manual.
package browser

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"

	"albmcp/internal/auth"
	"albmcp/internal/config"
	"albmcp/internal/session"
)

// pollInterval is how often the login state machine re-checks whether the
// redirect chain has settled back on the target host with a cookie in place.
const pollInterval = 500 * time.Millisecond

// Loginer drives Chrome via the DevTools protocol.
type Loginer struct {
	// Headless is false in production, and exists only so the manual test can
	// be run without a visible window. The point of the flow is that a person
	// completes MFA, so a headless login cannot succeed against a real provider.
	Headless bool
}

// New returns a headed Chrome Loginer.
func New() *Loginer { return &Loginer{Headless: false} }

// Login opens a browser at the domain's login probe path, waits for the user to
// complete the provider flow, and returns the ALB cookies.
//
// profileDir is a persistent user-data directory. Reusing it means the
// provider's own SSO session usually survives between logins, so re-auth
// completes in about a second with no interaction and the window closes itself.
func (l *Loginer) Login(ctx context.Context, d *config.Domain, profileDir string) ([]session.Cookie, error) {
	target, err := url.JoinPath(d.BaseURL, d.LoginProbePath)
	if err != nil {
		return nil, auth.Wrap(err, auth.CodeLoginFailed, "check base_url and login_probe_path",
			"cannot build login probe URL for %q", d.Name)
	}
	baseHost, err := hostOf(d.BaseURL)
	if err != nil {
		return nil, auth.Wrap(err, auth.CodeLoginFailed, "check base_url", "invalid base_url for %q", d.Name)
	}

	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.Flag("headless", l.Headless),
		chromedp.UserDataDir(profileDir),
	)
	allocCtx, cancelAlloc := chromedp.NewExecAllocator(ctx, opts...)
	defer cancelAlloc()
	browserCtx, cancelBrowser := chromedp.NewContext(allocCtx)
	defer cancelBrowser()

	if err := chromedp.Run(browserCtx, chromedp.Navigate(target)); err != nil {
		if isNoBrowser(err) {
			return nil, auth.Wrap(err, auth.CodeNoBrowser, noBrowserHint(d),
				"no Chrome or Chromium binary was found")
		}
		if errors.Is(err, context.DeadlineExceeded) {
			return nil, timeoutError(d)
		}
		return nil, auth.Wrap(err, auth.CodeLoginFailed, "check the domain is reachable from this machine",
			"could not open %s", target)
	}

	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()
	for {
		if cookies, ok := l.poll(browserCtx, d, baseHost); ok {
			return cookies, nil
		}
		select {
		case <-browserCtx.Done():
			return nil, timeoutError(d)
		case <-ticker.C:
		}
	}
}

// poll checks the single settle condition: the browser is back on the target
// host and at least one cookie with the configured prefix exists.
func (l *Loginer) poll(ctx context.Context, d *config.Domain, baseHost string) ([]session.Cookie, bool) {
	var currentURL string
	var raw []*network.Cookie
	err := chromedp.Run(ctx,
		chromedp.Location(&currentURL),
		chromedp.ActionFunc(func(ctx context.Context) error {
			var err error
			raw, err = network.GetCookies().Do(ctx)
			return err
		}),
	)
	if err != nil {
		return nil, false
	}
	parsed, err := url.Parse(currentURL)
	if err != nil || !strings.EqualFold(parsed.Host, baseHost) {
		return nil, false
	}
	// ALB splits a large session across -0, -1, -2…; every chunk is needed.
	cookies := convert(raw, d.CookieNamePrefix)
	if len(cookies) == 0 {
		return nil, false
	}
	return cookies, true
}

func convert(raw []*network.Cookie, prefix string) []session.Cookie {
	out := make([]session.Cookie, 0, len(raw))
	for _, c := range raw {
		if !strings.HasPrefix(c.Name, prefix) {
			continue
		}
		var expires time.Time
		if c.Expires > 0 {
			expires = time.Unix(int64(c.Expires), 0).UTC()
		}
		out = append(out, session.Cookie{
			Name:     c.Name,
			Value:    c.Value,
			Domain:   cookieHost(c.Domain),
			Path:     c.Path,
			Expires:  expires,
			Secure:   c.Secure,
			HTTPOnly: c.HTTPOnly,
		})
	}
	return out
}

func hostOf(rawURL string) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	if u.Host == "" {
		return "", fmt.Errorf("%q has no host", rawURL)
	}
	return u.Host, nil
}

func timeoutError(d *config.Domain) error {
	return auth.Errorf(auth.CodeLoginTimeout,
		fmt.Sprintf("raise login_timeout_seconds for domain %q", d.Name),
		"browser flow did not complete within %ds", d.LoginTimeoutSeconds)
}

func isNoBrowser(err error) bool {
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "exec: ") ||
		strings.Contains(msg, "executable file not found") ||
		strings.Contains(msg, "chrome failed to start")
}

func noBrowserHint(d *config.Domain) string {
	return "install Chrome or Chromium, or import a cookie manually with: albmcp auth import " + d.Name
}

// cookieHost strips the leading dot a browser uses to mark a domain-wide
// cookie, so the stored value matches the host albmcp will send it back to.
func cookieHost(domain string) string {
	host, _ := strings.CutPrefix(domain, ".")
	return host
}
