package auth

import (
	"bufio"
	"fmt"
	"io"
	"strings"
	"time"

	"albmcp/internal/config"
	"albmcp/internal/session"
)

// ImportedSessionTTL is the assumed lifetime of a manually imported cookie.
//
// A cookie copied out of a browser's developer tools carries no readable
// expiry, so this is a heuristic. It is deliberately short: if it is wrong the
// normal unauthenticated-response detection catches it on the next request,
// which costs one extra round trip rather than a confusing failure.
const ImportedSessionTTL = 8 * time.Hour

// ImportInstructions is the operator-facing text printed before reading cookies
// from stdin on a machine with no browser.
func ImportInstructions(d *config.Domain) string {
	return fmt.Sprintf(`On a machine with a browser:
  1. Log in to %s in Chrome or Firefox.
  2. Open DevTools -> Application -> Cookies -> %s
  3. Copy the value of every cookie named %s*

Paste them here as NAME=VALUE, one per line. Blank line to finish:`,
		d.BaseURL, d.BaseURL, d.CookieNamePrefix)
}

// ParseImportedCookies reads NAME=VALUE lines until a blank line or EOF.
//
// At least one name must match the domain's cookie prefix; otherwise the user
// has pasted the wrong cookies and would get a confusing failure much later.
func ParseImportedCookies(r io.Reader, d *config.Domain, now time.Time) ([]session.Cookie, error) {
	scanner := bufio.NewScanner(r)
	var cookies []session.Cookie
	var lineNo int

	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			break
		}
		name, value, ok := strings.Cut(line, "=")
		name = strings.TrimSpace(name)
		value = strings.TrimSpace(value)
		if !ok || name == "" || value == "" {
			return nil, Errorf(CodeInvalidRequest, "each line must read NAME=VALUE",
				"line %d is not a NAME=VALUE pair", lineNo)
		}
		cookies = append(cookies, session.Cookie{
			Name:     name,
			Value:    value,
			Domain:   d.BaseHost(),
			Path:     "/",
			Expires:  now.Add(ImportedSessionTTL),
			Secure:   true,
			HTTPOnly: true,
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, Wrap(err, CodeInvalidRequest, "", "reading pasted cookies: %v", err)
	}

	matching := session.FilterByPrefix(cookies, d.CookieNamePrefix)
	if len(matching) == 0 {
		return nil, Errorf(CodeLoginFailed,
			fmt.Sprintf("at least one cookie must be named %s*", d.CookieNamePrefix),
			"none of the %d pasted cookie(s) match the configured prefix %q",
			len(cookies), d.CookieNamePrefix)
	}
	return matching, nil
}

// ImportSession builds a session from pasted cookies.
func ImportSession(r io.Reader, d *config.Domain, now time.Time) (*session.Session, error) {
	cookies, err := ParseImportedCookies(r, d, now)
	if err != nil {
		return nil, err
	}
	return &session.Session{Cookies: cookies, AcquiredAt: now, LastUsedAt: now}, nil
}
