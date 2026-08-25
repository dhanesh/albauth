package auth

import (
	"errors"
	"strings"
	"testing"
)

func TestErrorMessage(t *testing.T) {
	withHint := Errorf(CodeLoginTimeout, "raise login_timeout_seconds", "flow did not complete in %ds", 180)
	if got := withHint.Error(); got != "login_timeout: flow did not complete in 180s (raise login_timeout_seconds)" {
		t.Fatalf("Error() = %q", got)
	}
	noHint := Errorf(CodeAuthLoop, "", "still unauthenticated")
	if got := noHint.Error(); got != "auth_loop: still unauthenticated" {
		t.Fatalf("Error() = %q", got)
	}
}

func TestErrorWrapping(t *testing.T) {
	cause := errors.New("d-bus is not running")
	err := Wrap(cause, CodeStorageUnavailable, `set storage = "file"`, "keychain failed: %v", cause)

	if !errors.Is(err, cause) {
		t.Fatal("Wrap should expose the cause to errors.Is")
	}
	coded, ok := errors.AsType[*Error](err)
	if !ok || coded.Code != CodeStorageUnavailable {
		t.Fatalf("errors.AsType = %v", coded)
	}
	if !strings.Contains(err.Error(), "d-bus is not running") {
		t.Fatalf("Error() = %q", err.Error())
	}
	// An unwrapped error has no cause, which errors.Is must handle.
	if errors.Is(Errorf(CodeAuthLoop, "", "x"), cause) {
		t.Fatal("an error with no cause should not match")
	}
}
