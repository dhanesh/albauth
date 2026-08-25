package auth

import (
	"errors"
	"io"
	"strings"
	"testing"
	"time"
)

func TestImportInstructionsNameTheDomain(t *testing.T) {
	text := ImportInstructions(loginDomain())
	for _, needle := range []string{"https://api.example.com", "AWSELBAuthSessionCookie*", "NAME=VALUE", "Blank line to finish"} {
		if !strings.Contains(text, needle) {
			t.Fatalf("instructions are missing %q:\n%s", needle, text)
		}
	}
}

func TestParseImportedCookies(t *testing.T) {
	in := strings.Join([]string{
		"AWSELBAuthSessionCookie-0=chunk-zero",
		"  AWSELBAuthSessionCookie-1 = chunk-one  ",
		"unrelated=ignored",
		"",
		"AWSELBAuthSessionCookie-2=never-read",
	}, "\n")

	got, err := ParseImportedCookies(strings.NewReader(in), loginDomain(), now)
	if err != nil {
		t.Fatalf("ParseImportedCookies: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d cookies, want 2 (the blank line ends input)", len(got))
	}
	if got[0].Value != "chunk-zero" || got[1].Value != "chunk-one" {
		t.Fatalf("values = %q, %q", got[0].Value, got[1].Value)
	}
	// Metadata a browser paste cannot supply is filled in sensibly.
	if got[0].Domain != "api.example.com" || got[0].Path != "/" || !got[0].Secure || !got[0].HTTPOnly {
		t.Fatalf("cookie metadata = %+v", got[0])
	}
	if want := now.Add(ImportedSessionTTL); !got[0].Expires.Equal(want) {
		t.Fatalf("expires = %v, want %v", got[0].Expires, want)
	}
}

func TestParseImportedCookiesRejectsBadInput(t *testing.T) {
	tests := []struct {
		name     string
		in       string
		wantCode string
	}{
		{"a line that is not a pair", "AWSELBAuthSessionCookie-0", CodeInvalidRequest},
		{"an empty name", "=value", CodeInvalidRequest},
		{"an empty value", "AWSELBAuthSessionCookie-0=", CodeInvalidRequest},
		{"no cookie matches the configured prefix", "session_id=abc\nother=def", CodeLoginFailed},
		{"nothing pasted at all", "", CodeLoginFailed},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseImportedCookies(strings.NewReader(tc.in), loginDomain(), now)
			assertCode(t, err, tc.wantCode)
		})
	}
}

func TestParseImportedCookiesReportsAReadFailure(t *testing.T) {
	_, err := ParseImportedCookies(errReader{errors.New("terminal closed")}, loginDomain(), now)
	assertCode(t, err, CodeInvalidRequest)
}

func TestImportSession(t *testing.T) {
	s, err := ImportSession(strings.NewReader("AWSELBAuthSessionCookie-0=abc\n"), loginDomain(), now)
	if err != nil {
		t.Fatalf("ImportSession: %v", err)
	}
	if !s.AcquiredAt.Equal(now) || !s.LastUsedAt.Equal(now) {
		t.Fatalf("timestamps = %v, %v", s.AcquiredAt, s.LastUsedAt)
	}
	if s.Valid(now) != true {
		t.Fatal("a freshly imported session should be valid")
	}
	// The assumed lifetime is deliberately short; detection catches it if wrong.
	if s.Valid(now.Add(ImportedSessionTTL + time.Minute)) {
		t.Fatal("an imported session should expire after the assumed lifetime")
	}

	if _, err := ImportSession(strings.NewReader("junk"), loginDomain(), now); err == nil {
		t.Fatal("ImportSession should propagate a parse failure")
	}
}

type errReader struct{ err error }

func (e errReader) Read([]byte) (int, error) { return 0, e.err }

var _ io.Reader = errReader{}
