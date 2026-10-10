package browser

import "testing"

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
