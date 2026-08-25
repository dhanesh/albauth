// Package auth acquires and refreshes ALB session cookies.
package auth

import "fmt"

// Error codes surfaced to the MCP client. They are a closed set so a model can
// branch on them, and each carries a hint naming the concrete next action.
const (
	CodeUnknownDomain      = "unknown_domain"
	CodeDomainMismatch     = "domain_mismatch"
	CodeMethodNotAllowed   = "method_not_allowed"
	CodeNoBrowser          = "no_browser"
	CodeLoginTimeout       = "login_timeout"
	CodeLoginFailed        = "login_failed"
	CodeAuthLoop           = "auth_loop"
	CodeStorageUnavailable = "storage_unavailable"
	CodeStorageInsecure    = "storage_insecure"
	CodeUpstreamTimeout    = "upstream_timeout"
	CodeConfigInvalid      = "config_invalid"
	CodeInvalidRequest     = "invalid_request"
	CodeUpstreamError      = "upstream_error"
)

// Error is a coded, hinted failure. Every tool error is rendered from one, so
// the client always receives {error, message, hint} rather than a bare string.
type Error struct {
	Code    string `json:"error"`
	Message string `json:"message"`
	Hint    string `json:"hint,omitempty"`

	// Err is the wrapped cause, for errors.Is/As. It is never rendered to the
	// client, which keeps upstream detail out of model-visible output.
	Err error `json:"-"`
}

func (e *Error) Error() string {
	if e.Hint != "" {
		return fmt.Sprintf("%s: %s (%s)", e.Code, e.Message, e.Hint)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// Unwrap exposes the cause to errors.Is and errors.As.
func (e *Error) Unwrap() error { return e.Err }

// Errorf builds a coded error with a formatted message.
func Errorf(code, hint, format string, args ...any) *Error {
	return &Error{Code: code, Message: fmt.Sprintf(format, args...), Hint: hint}
}

// Wrap builds a coded error that wraps a cause.
func Wrap(err error, code, hint, format string, args ...any) *Error {
	return &Error{Code: code, Message: fmt.Sprintf(format, args...), Hint: hint, Err: err}
}
