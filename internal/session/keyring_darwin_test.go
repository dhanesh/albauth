//go:build darwin

package session

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/zalando/go-keyring"
)

// TestRealKeyringRefusesOversizeBeforeWriting proves, against the real
// go-keyring on macOS, the premise the auto fallback rests on: a two-chunk
// session is refused with keyring.ErrSetDataTooBig. go-keyring checks the
// length of the `security` command before sending it, so this never writes to
// the user's keychain. Never call it with a value that fits.
func TestRealKeyringRefusesOversizeBeforeWriting(t *testing.T) {
	data, err := json.Marshal(bigSession())
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if len(data) < 5000 {
		t.Fatalf("the session is %d bytes; it must be well over the limit so nothing is written", len(data))
	}
	err = keyring.Set(KeyringService, "__albauth_oversize_test__", string(data))
	if !errors.Is(err, keyring.ErrSetDataTooBig) {
		t.Fatalf("keyring.Set of %d bytes = %v, want ErrSetDataTooBig", len(data), err)
	}
}
