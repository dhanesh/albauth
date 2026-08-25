package cli

import (
	"io"
	"os"
	"strings"

	"golang.org/x/term"
)

// Indirected so both branches of readSecret are reachable in tests without a
// controlling terminal.
var (
	termIsTerminal   = term.IsTerminal
	termReadPassword = term.ReadPassword
)

// maxSecretLines bounds a paste. ALB splits a session across a handful of
// cookies, so anything past this is a stuck terminal rather than real input.
const maxSecretLines = 64

// readSecret returns a reader over lines typed at a terminal with echo
// disabled, so pasted session cookies never appear on screen or in scrollback.
//
// When stdin is not a terminal — a pipe in a test, or a heredoc in a script —
// the reader is returned unchanged, because there is no echo to suppress.
func readSecret(r io.Reader) io.Reader {
	file, ok := r.(*os.File)
	if !ok {
		return r
	}
	fd := int(file.Fd())
	if !termIsTerminal(fd) {
		return r
	}

	var lines []string
	for len(lines) < maxSecretLines {
		line, err := termReadPassword(fd)
		if err != nil {
			break
		}
		text := strings.TrimSpace(string(line))
		if text == "" {
			break
		}
		lines = append(lines, text)
	}
	return strings.NewReader(strings.Join(lines, "\n") + "\n")
}
