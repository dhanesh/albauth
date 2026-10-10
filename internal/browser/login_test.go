package browser

import (
	"testing"

	"github.com/chromedp/cdproto/network"

	"albauth/internal/session"
)

func TestSettleRequiresSuccessStatus(t *testing.T) {
	const host = "api.example.com"
	cases := []struct {
		name    string
		url     string
		status  int64
		host    string
		cookies int
		want    bool
	}{
		{"200 on host with cookie", "https://api.example.com/", 200, host, 1, true},
		{"host compared case-insensitively", "https://API.example.com/x", 200, host, 1, true},
		{"302 as the final status", "https://api.example.com/", 302, host, 2, true},
		{"399 is below the bar", "https://api.example.com/", 399, host, 1, true},
		{"403 sign-in page", "https://api.example.com/oauth2/sign_in", 403, host, 1, false},
		{"401 deny page", "https://api.example.com/", 401, host, 1, false},
		{"400 is the bar", "https://api.example.com/", 400, host, 1, false},
		{"500 error page", "https://api.example.com/", 500, host, 1, false},
		{"unknown status before any response", "https://api.example.com/", 0, host, 1, false},
		{"negative status", "https://api.example.com/", -1, host, 1, false},
		{"host mismatch", "https://idp.example.com/authorize", 200, host, 1, false},
		{"port is part of the host", "https://api.example.com:8443/", 200, host, 1, false},
		{"no cookie", "https://api.example.com/", 200, host, 0, false},
		{"unparseable URL", "://bad", 200, host, 1, false},
		{"blank page", "about:blank", 200, host, 1, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := settled(c.url, c.status, c.host, c.cookies); got != c.want {
				t.Errorf("settled(%q, %d, %q, %d) = %v, want %v", c.url, c.status, c.host, c.cookies, got, c.want)
			}
		})
	}
}

// TestSessionCookieNamesMatchExactlyOrAsChunks pins the capture rule (R14): the
// browser keeps a cookie only when its name is the configured name itself or a
// numbered chunk of it, never a sibling that merely starts with it, such as
// oauth2-proxy's _oauth2_proxy_csrf.
func TestSessionCookieNamesMatchExactlyOrAsChunks(t *testing.T) {
	cases := []struct {
		prefix string
		names  []string
		want   []string
	}{
		{
			prefix: "_oauth2_proxy",
			names:  []string{"_oauth2_proxy", "_oauth2_proxy_0", "_oauth2_proxy_csrf", "_oauth2_proxyX"},
			want:   []string{"_oauth2_proxy", "_oauth2_proxy_0"},
		},
		{
			prefix: "AWSELBAuthSessionCookie",
			names: []string{"AWSELBAuthSessionCookie-0", "AWSELBAuthSessionCookie-12",
				"AWSELBAuthSessionCookie-x", "AWSELBAuthSessionCookieFoo"},
			want: []string{"AWSELBAuthSessionCookie-0", "AWSELBAuthSessionCookie-12"},
		},
		{
			prefix: "",
			names:  []string{"_oauth2_proxy", "AWSELBAuthSessionCookie-0"},
			want:   nil,
		},
	}
	for _, c := range cases {
		raw := make([]*network.Cookie, 0, len(c.names))
		for _, n := range c.names {
			raw = append(raw, &network.Cookie{Name: n, Value: "v", Domain: ".api.example.com", Path: "/"})
		}
		got := convert(raw, c.prefix)
		if len(got) != len(c.want) {
			t.Fatalf("convert(prefix %q) kept %d cookies, want %d: %v", c.prefix, len(got), len(c.want), names(got))
		}
		for i, w := range c.want {
			if got[i].Name != w {
				t.Errorf("convert(prefix %q)[%d] = %q, want %q", c.prefix, i, got[i].Name, w)
			}
		}
	}
}

func names(cookies []session.Cookie) []string {
	out := make([]string, 0, len(cookies))
	for _, c := range cookies {
		out = append(out, c.Name)
	}
	return out
}
