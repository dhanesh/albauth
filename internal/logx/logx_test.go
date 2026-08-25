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
