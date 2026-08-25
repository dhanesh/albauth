package mcpserver

import (
	"errors"

	"albauth/internal/auth"
)

// codedError extracts albauth's coded error type, kept in one place so the
// rendering path and the transport adapter agree on what counts as coded.
func codedError(err error) (*auth.Error, bool) {
	return errors.AsType[*auth.Error](err)
}
