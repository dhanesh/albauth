package logx

import (
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"sync"
)

// Level is a log severity. Lower values are more severe.
type Level int

// Log levels, in the order used by the log_level config key.
const (
	LevelError Level = iota
	LevelWarn
	LevelInfo
	LevelDebug
)

var levelNames = map[Level]string{
	LevelError: "error",
	LevelWarn:  "warn",
	LevelInfo:  "info",
	LevelDebug: "debug",
}

// String renders the level as it appears in config and in log lines.
func (l Level) String() string {
	if name, ok := levelNames[l]; ok {
		return name
	}
	return "unknown"
}

// ParseLevel converts a config value to a Level. Unknown values are an error so
// that config validation can report them rather than silently defaulting.
func ParseLevel(s string) (Level, error) {
	for level, name := range levelNames {
		if strings.EqualFold(s, name) {
			return level, nil
		}
	}
	return LevelInfo, fmt.Errorf("unknown log level %q (want error, warn, info or debug)", s)
}

// Logger writes redacted, level-filtered lines to a single writer.
//
// The writer is supplied at construction and is never stdout in production
// code: a stray line on stdout corrupts the MCP protocol stream.
type Logger struct {
	mu      sync.Mutex
	out     io.Writer
	level   Level
	secrets []string
	// prefixes are the configured session cookie families; pattern is the
	// redaction pattern built from them (plus the built-in default).
	prefixes []string
	pattern  *regexp.Regexp
	warned   map[string]bool
}

// New returns a Logger writing to out at the given level.
func New(out io.Writer, level Level) *Logger {
	return &Logger{out: out, level: level, pattern: defaultCookiePattern, warned: map[string]bool{}}
}

// NewStderr returns a Logger bound to os.Stderr, the only writer the server
// may log to.
func NewStderr(level Level) *Logger { return New(os.Stderr, level) }

// Discard returns a Logger that writes nowhere, for tests and quiet subcommands.
func Discard() *Logger { return New(io.Discard, LevelError) }

// AddSecret registers a value that must never appear in output. Every line is
// scrubbed of registered secrets before being written.
func (l *Logger) AddSecret(secret string) {
	if secret == "" {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.secrets = append(l.secrets, secret)
}

// AddCookiePrefix registers a session cookie family (a domain's
// cookie_name_prefix). From then on every line is scrubbed of the value of any
// cookie whose name starts with it, whether or not that exact value was
// registered with AddSecret. Call it for each configured domain, including one
// added while the server runs. The ALB's family is always covered.
func (l *Logger) AddCookiePrefix(prefix string) {
	if prefix == "" {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.prefixes = append(l.prefixes, prefix)
	l.pattern = cookiePattern(l.prefixes)
}

// SetLevel changes the severity threshold.
func (l *Logger) SetLevel(level Level) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.level = level
}

func (l *Logger) logf(level Level, format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if level > l.level {
		return
	}
	line := RedactValues(redactWith(l.pattern, fmt.Sprintf(format, args...)), l.secrets)
	fmt.Fprintf(l.out, "albauth %s: %s\n", level, strings.TrimRight(line, "\n"))
}

// Error logs at error level.
func (l *Logger) Error(format string, args ...any) { l.logf(LevelError, format, args...) }

// Warn logs at warn level.
func (l *Logger) Warn(format string, args ...any) { l.logf(LevelWarn, format, args...) }

// Info logs at info level.
func (l *Logger) Info(format string, args ...any) { l.logf(LevelInfo, format, args...) }

// Debug logs at debug level.
func (l *Logger) Debug(format string, args ...any) { l.logf(LevelDebug, format, args...) }

// WarnOnce logs a warning the first time it is called with a given key and does
// nothing afterwards. The file-storage fallback notice uses it so that a user
// on a headless box sees the warning exactly once per process.
func (l *Logger) WarnOnce(key, format string, args ...any) {
	l.mu.Lock()
	if l.warned[key] {
		l.mu.Unlock()
		return
	}
	l.warned[key] = true
	l.mu.Unlock()
	l.Warn(format, args...)
}
