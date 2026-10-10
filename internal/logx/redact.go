// Package logx provides a stderr-only logger and secret redaction helpers.
//
// stdout belongs to the MCP JSON-RPC channel. Nothing in this package will ever
// write to it: the logger only accepts a writer the caller supplies, and the
// constructors here bind that writer to os.Stderr.
package logx

import (
	"fmt"
	"regexp"
	"strings"
)

// Redacted renders a secret as a fixed marker that reveals only its length.
// Cookie values must never appear in logs, MCP tool results, or errors, so
// every path that could render one goes through here.
func Redacted(value string) string {
	return fmt.Sprintf("<redacted:len=%d>", len(value))
}

// RedactCookie renders a name=value pair with the value redacted.
func RedactCookie(name, value string) string {
	return name + "=" + Redacted(value)
}

// DefaultCookiePrefix is the session cookie family RedactText always scrubs,
// whatever else is configured: the ALB's. It mirrors the config default so a
// domain that never set cookie_name_prefix is still covered.
const DefaultCookiePrefix = "AWSELBAuthSessionCookie"

// defaultCookiePattern is the pattern for DefaultCookiePrefix alone.
var defaultCookiePattern = cookiePattern(nil)

// cookiePattern matches "<name>=<value>" pairs whose name starts with
// DefaultCookiePrefix or any of prefixes, case-insensitively, in free-form text
// such as a wrapped error string or a Cookie header. The value runs to the next
// whitespace, ';', ',' or quote. Matching by prefix is a deliberate superset of
// the exact-or-chunk session family: over-redacting is safe.
func cookiePattern(prefixes []string) *regexp.Regexp {
	seen := map[string]bool{}
	alts := []string{regexp.QuoteMeta(DefaultCookiePrefix)}
	seen[strings.ToLower(DefaultCookiePrefix)] = true
	for _, p := range prefixes {
		if p == "" || seen[strings.ToLower(p)] {
			continue
		}
		seen[strings.ToLower(p)] = true
		alts = append(alts, regexp.QuoteMeta(p))
	}
	return regexp.MustCompile(`(?i)((?:` + strings.Join(alts, "|") + `)[A-Za-z0-9_.-]*\s*=\s*)([^\s;,"']+)`)
}

// RedactText scrubs session cookie values out of arbitrary text: every pair
// whose name starts with DefaultCookiePrefix or one of prefixes (normally each
// configured domain's cookie_name_prefix). It is the belt to RedactCookie's
// braces: used on strings assembled elsewhere (upstream error messages,
// response headers) where a value could otherwise slip through.
func RedactText(text string, prefixes ...string) string {
	pattern := defaultCookiePattern
	if len(prefixes) > 0 {
		pattern = cookiePattern(prefixes)
	}
	return redactWith(pattern, text)
}

func redactWith(pattern *regexp.Regexp, text string) string {
	return pattern.ReplaceAllStringFunc(text, func(match string) string {
		groups := pattern.FindStringSubmatch(match)
		return groups[1] + Redacted(groups[2])
	})
}

// RedactValues scrubs every occurrence of each known secret from text. Use it
// when the exact secrets are in hand and their surrounding syntax is unknown.
func RedactValues(text string, secrets []string) string {
	for _, secret := range secrets {
		if secret == "" {
			continue
		}
		text = strings.ReplaceAll(text, secret, Redacted(secret))
	}
	return text
}
