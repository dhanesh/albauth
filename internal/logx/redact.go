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

// cookieValuePattern matches "<name>=<value>" pairs whose name looks like an
// ALB session cookie, in free-form text such as a wrapped error string.
var cookieValuePattern = regexp.MustCompile(`(?i)(AWSELBAuthSessionCookie[A-Za-z0-9_.-]*\s*=\s*)([^\s;,"']+)`)

// RedactText scrubs ALB session cookie values out of arbitrary text. It is the
// belt to RedactCookie's braces: used on strings assembled elsewhere (upstream
// error messages, response headers) where a value could otherwise slip through.
func RedactText(text string) string {
	return cookieValuePattern.ReplaceAllStringFunc(text, func(match string) string {
		groups := cookieValuePattern.FindStringSubmatch(match)
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
