package logx

import (
	"bytes"
	"strings"
	"sync"
	"testing"
)

const secretValue = "s3cr3t-alb-cookie-value-that-must-never-be-printed"

func TestRedacted(t *testing.T) {
	got := Redacted("abcd")
	if got != "<redacted:len=4>" {
		t.Fatalf("Redacted() = %q", got)
	}
	if strings.Contains(Redacted(secretValue), secretValue) {
		t.Fatal("Redacted leaked the value")
	}
}

func TestRedactCookie(t *testing.T) {
	got := RedactCookie("AWSELBAuthSessionCookie-0", secretValue)
	if !strings.HasPrefix(got, "AWSELBAuthSessionCookie-0=<redacted:len=") {
		t.Fatalf("RedactCookie() = %q", got)
	}
	if strings.Contains(got, secretValue) {
		t.Fatal("RedactCookie leaked the value")
	}
}

func TestRedactText(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		wantOut string
	}{
		{"plain pair", "AWSELBAuthSessionCookie-0=" + secretValue,
			"AWSELBAuthSessionCookie-0=" + Redacted(secretValue)},
		{"chunked with suffix", "cookie AWSELBAuthSessionCookie-12=abc; path=/",
			"cookie AWSELBAuthSessionCookie-12=" + Redacted("abc") + "; path=/"},
		{"spaces around equals", "AWSELBAuthSessionCookie-0 = abc",
			"AWSELBAuthSessionCookie-0 = " + Redacted("abc")},
		{"case insensitive", "awselbauthsessioncookie-0=abc",
			"awselbauthsessioncookie-0=" + Redacted("abc")},
		{"nothing to redact", "plain log line", "plain log line"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := RedactText(tc.in); got != tc.wantOut {
				t.Fatalf("RedactText(%q) = %q, want %q", tc.in, got, tc.wantOut)
			}
		})
	}
}

// TestRedactTextUsesConfiguredPrefixes proves redaction is not ALB-only: any
// configured session cookie family is scrubbed by prefix, in free text and in
// a Cookie header, without the value having been registered as a secret.
func TestRedactTextUsesConfiguredPrefixes(t *testing.T) {
	const o2 = "b2F1dGgyLXByb3h5LXNlc3Npb24tdmFsdWU"
	tests := []struct {
		name    string
		in      string
		wantOut string
	}{
		{"oauth2-proxy cookie in a wrapped error",
			"upstream: get: replaying _oauth2_proxy=" + o2 + " failed: EOF",
			"upstream: get: replaying _oauth2_proxy=" + Redacted(o2) + " failed: EOF"},
		{"oauth2-proxy chunk in a Cookie header",
			"Cookie: _oauth2_proxy_0=abc; _oauth2_proxy_1=" + o2 + "; theme=dark",
			"Cookie: _oauth2_proxy_0=" + Redacted("abc") + "; _oauth2_proxy_1=" + Redacted(o2) + "; theme=dark"},
		{"custom prefix with regexp metacharacters",
			"set-cookie: my.sess+id=xyz, other=1",
			"set-cookie: my.sess+id=" + Redacted("xyz") + ", other=1"},
		{"quoted value", `cookie "Traefik_Auth=tok"`,
			`cookie "Traefik_Auth=` + Redacted("tok") + `"`},
		{"ALB default still scrubbed", "AWSELBAuthSessionCookie-0=" + o2,
			"AWSELBAuthSessionCookie-0=" + Redacted(o2)},
		{"unrelated cookie untouched", "Cookie: theme=dark; lang=en", "Cookie: theme=dark; lang=en"},
		{"text without a cookie unchanged", "plain log line", "plain log line"},
	}
	prefixes := []string{"_oauth2_proxy", "", "my.sess+", "traefik_auth", "_OAUTH2_PROXY"}

	var buf bytes.Buffer
	log := New(&buf, LevelDebug)
	log.AddCookiePrefix("")
	for _, p := range prefixes {
		log.AddCookiePrefix(p)
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := RedactText(tc.in, prefixes...); got != tc.wantOut {
				t.Fatalf("RedactText(%q) = %q, want %q", tc.in, got, tc.wantOut)
			}
			buf.Reset()
			log.Info("%s", tc.in)
			if want := "albauth info: " + tc.wantOut + "\n"; buf.String() != want {
				t.Fatalf("logged %q, want %q", buf.String(), want)
			}
		})
	}

	// Without the prefix configured, only the ALB family is scrubbed.
	if got := RedactText("_oauth2_proxy=" + o2); got != "_oauth2_proxy="+o2 {
		t.Fatalf("default RedactText scrubbed an unconfigured family: %q", got)
	}
}

func TestRedactValues(t *testing.T) {
	got := RedactValues("body contains "+secretValue+" twice: "+secretValue,
		[]string{"", secretValue})
	if strings.Contains(got, secretValue) {
		t.Fatalf("RedactValues leaked the value: %q", got)
	}
	if strings.Count(got, Redacted(secretValue)) != 2 {
		t.Fatalf("RedactValues replaced %d occurrences, want 2: %q",
			strings.Count(got, Redacted(secretValue)), got)
	}
}

func TestLevelString(t *testing.T) {
	for level, want := range map[Level]string{
		LevelError: "error", LevelWarn: "warn", LevelInfo: "info",
		LevelDebug: "debug", Level(99): "unknown",
	} {
		if got := level.String(); got != want {
			t.Fatalf("Level(%d).String() = %q, want %q", level, got, want)
		}
	}
}

func TestParseLevel(t *testing.T) {
	for input, want := range map[string]Level{
		"error": LevelError, "WARN": LevelWarn, "Info": LevelInfo, "debug": LevelDebug,
	} {
		got, err := ParseLevel(input)
		if err != nil || got != want {
			t.Fatalf("ParseLevel(%q) = %v, %v; want %v, nil", input, got, err, want)
		}
	}
	if _, err := ParseLevel("chatty"); err == nil {
		t.Fatal("ParseLevel(\"chatty\") should fail")
	}
}

func TestLoggerLevelFiltering(t *testing.T) {
	var buf bytes.Buffer
	log := New(&buf, LevelWarn)
	log.Debug("debug line")
	log.Info("info line")
	log.Warn("warn line")
	log.Error("error line")

	out := buf.String()
	for _, absent := range []string{"debug line", "info line"} {
		if strings.Contains(out, absent) {
			t.Fatalf("level filtering let through %q: %s", absent, out)
		}
	}
	for _, present := range []string{"albauth warn: warn line", "albauth error: error line"} {
		if !strings.Contains(out, present) {
			t.Fatalf("missing %q in: %s", present, out)
		}
	}
}

func TestLoggerSetLevel(t *testing.T) {
	var buf bytes.Buffer
	log := New(&buf, LevelError)
	log.Debug("hidden")
	log.SetLevel(LevelDebug)
	log.Debug("shown")
	if strings.Contains(buf.String(), "hidden") || !strings.Contains(buf.String(), "shown") {
		t.Fatalf("SetLevel did not take effect: %s", buf.String())
	}
}

// A rendered log line must never contain a known cookie value, whichever route
// it took into the logger. This is the test the specification asks for by name.
func TestLoggerNeverRendersASecret(t *testing.T) {
	var buf bytes.Buffer
	log := New(&buf, LevelDebug)
	log.AddSecret("")
	log.AddSecret(secretValue)

	log.Info("replaying AWSELBAuthSessionCookie-0=%s", secretValue)
	log.Debug("raw value in a message: %s", secretValue)
	log.Warn("wrapped upstream error: set-cookie: AWSELBAuthSessionCookie-1=%s; Secure", secretValue)
	log.Error("%s", secretValue)

	if strings.Contains(buf.String(), secretValue) {
		t.Fatalf("cookie value appeared in log output:\n%s", buf.String())
	}
	if !strings.Contains(buf.String(), "<redacted:len=") {
		t.Fatalf("expected a redaction marker in:\n%s", buf.String())
	}
}

func TestWarnOnce(t *testing.T) {
	var buf bytes.Buffer
	log := New(&buf, LevelWarn)
	for range 5 {
		log.WarnOnce("storage-fallback", "keychain unavailable")
	}
	log.WarnOnce("other-key", "second warning")
	if got := strings.Count(buf.String(), "keychain unavailable"); got != 1 {
		t.Fatalf("WarnOnce emitted %d times, want 1:\n%s", got, buf.String())
	}
	if !strings.Contains(buf.String(), "second warning") {
		t.Fatal("a different key should still warn")
	}
}

func TestLoggerIsConcurrencySafe(t *testing.T) {
	var buf bytes.Buffer
	log := New(&buf, LevelDebug)
	var wg sync.WaitGroup
	for n := range 20 {
		wg.Go(func() {
			log.AddSecret(secretValue)
			log.Info("line %d with %s", n, secretValue)
			log.WarnOnce("k", "once")
			log.SetLevel(LevelDebug)
		})
	}
	wg.Wait()
	if strings.Contains(buf.String(), secretValue) {
		t.Fatal("concurrent logging leaked the secret")
	}
}

func TestNewStderrAndDiscard(t *testing.T) {
	if NewStderr(LevelInfo) == nil {
		t.Fatal("NewStderr returned nil")
	}
	d := Discard()
	d.Info("goes nowhere")
	if d.level != LevelError {
		t.Fatalf("Discard level = %v", d.level)
	}
}
