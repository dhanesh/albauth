package cli

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// stubTerminal makes readSecret take the terminal path and feeds it lines.
func stubTerminal(t *testing.T, lines []string, readErr error) {
	t.Helper()
	origIsTerminal, origRead := termIsTerminal, termReadPassword
	t.Cleanup(func() { termIsTerminal, termReadPassword = origIsTerminal, origRead })

	i := 0
	termIsTerminal = func(int) bool { return true }
	termReadPassword = func(int) ([]byte, error) {
		if readErr != nil {
			return nil, readErr
		}
		if i >= len(lines) {
			return nil, io.EOF
		}
		line := lines[i]
		i++
		return []byte(line), nil
	}
}

// tempFile gives readSecret an *os.File to inspect, standing in for stdin.
func tempFile(t *testing.T) *os.File {
	t.Helper()
	f, err := os.Create(filepath.Join(t.TempDir(), "stdin"))
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	t.Cleanup(func() { _ = f.Close() })
	return f
}

// A pipe is not a terminal, so there is no echo to suppress and the reader is
// handed back unchanged.
func TestReadSecretPassesThroughANonFileReader(t *testing.T) {
	in := strings.NewReader("cookie=value\n")
	if got := readSecret(in); got != io.Reader(in) {
		t.Fatal("a non-file reader should be returned unchanged")
	}
}

func TestReadSecretPassesThroughAFileThatIsNotATerminal(t *testing.T) {
	orig := termIsTerminal
	t.Cleanup(func() { termIsTerminal = orig })
	termIsTerminal = func(int) bool { return false }

	file := tempFile(t)
	if got := readSecret(file); got != io.Reader(file) {
		t.Fatal("a non-terminal file should be returned unchanged")
	}
}

func TestReadSecretReadsTerminalLinesWithEchoDisabled(t *testing.T) {
	stubTerminal(t, []string{"AWSELBAuthSessionCookie-0=abc", "  AWSELBAuthSessionCookie-1=def  ", ""}, nil)

	got, err := io.ReadAll(readSecret(tempFile(t)))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	want := "AWSELBAuthSessionCookie-0=abc\nAWSELBAuthSessionCookie-1=def\n"
	if string(got) != want {
		t.Fatalf("readSecret = %q, want %q", got, want)
	}
}

func TestReadSecretStopsOnAReadError(t *testing.T) {
	stubTerminal(t, nil, errors.New("terminal closed"))
	got, err := io.ReadAll(readSecret(tempFile(t)))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if strings.TrimSpace(string(got)) != "" {
		t.Fatalf("readSecret = %q, want nothing", got)
	}
}

// A stuck terminal must not be read forever.
func TestReadSecretStopsAtTheLineCap(t *testing.T) {
	lines := make([]string, maxSecretLines+10)
	for i := range lines {
		lines[i] = "AWSELBAuthSessionCookie-0=x"
	}
	stubTerminal(t, lines, nil)

	got, err := io.ReadAll(readSecret(tempFile(t)))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if n := strings.Count(strings.TrimSpace(string(got)), "\n") + 1; n != maxSecretLines {
		t.Fatalf("read %d lines, want the cap of %d", n, maxSecretLines)
	}
}
