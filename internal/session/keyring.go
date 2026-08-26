package session

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/zalando/go-keyring"
)

// KeyringService is the service name albauth registers under in the OS keychain.
const KeyringService = "albauth"

// probeUser is the keyring entry used to test whether a keychain is reachable.
// It is written and deleted during the probe and never holds a real secret.
const probeUser = "__albauth_probe__"

// keyring operations are indirected so tests can drive the failure branches
// without a real OS keychain (there is none on a headless CI box).
var (
	keyringSet    = keyring.Set
	keyringGet    = keyring.Get
	keyringDelete = keyring.Delete

	goos          = runtime.GOOS
	osUserHomeDir = os.UserHomeDir
	osReadDir     = os.ReadDir
)

// KeyringStore persists one session per domain in the OS keychain.
type KeyringStore struct{}

// NewKeyringStore returns a keychain-backed store.
func NewKeyringStore() *KeyringStore { return &KeyringStore{} }

// Backend implements Store.
func (k *KeyringStore) Backend() string { return BackendKeyring }

// probe round-trips a throwaway value to confirm the keychain is usable.
//
// go-keyring reports an error rather than degrading when there is no Secret
// Service on the D-Bus session, which is exactly the signal `storage = "auto"`
// needs to fall back to the file backend.
func (k *KeyringStore) probe() error {
	if err := keychainReachable(); err != nil {
		return err
	}
	if err := keyringSet(KeyringService, probeUser, "ok"); err != nil {
		return err
	}
	got, err := keyringGet(KeyringService, probeUser)
	_ = keyringDelete(KeyringService, probeUser)
	if err != nil {
		return err
	}
	if got != "ok" {
		return fmt.Errorf("keychain round-trip returned %q, want \"ok\"", got)
	}
	return nil
}

// keychainReachable reports whether probing the OS keychain is safe to attempt.
//
// On macOS, writing to a keychain that is not there makes the Security
// framework raise a modal "Keychain Not Found" dialog before it returns an
// error. albauth normally runs as a background MCP server — over SSH, in CI,
// under a service account, or from a client that shows it no windows — where
// that dialog is invisible to the user and the probe blocks until somebody
// dismisses it. Checking for a keychain first costs one stat and turns an
// interactive hang into the ordinary fallback to file storage.
//
// Everywhere else the probe itself is the check, and this is a no-op.
func keychainReachable() error {
	if goos != "darwin" {
		return nil
	}
	home, err := osUserHomeDir()
	if err != nil {
		return fmt.Errorf("cannot locate the keychain: %w", err)
	}
	entries, err := osReadDir(filepath.Join(home, "Library", "Keychains"))
	if err != nil {
		return fmt.Errorf("no keychain directory for this user: %w", err)
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".keychain-db") || strings.HasSuffix(e.Name(), ".keychain") {
			return nil
		}
	}
	return errors.New("this user has no keychain")
}

// Get implements Store.
func (k *KeyringStore) Get(domain string) (*Session, error) {
	raw, err := keyringGet(KeyringService, domain)
	if errors.Is(err, keyring.ErrNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("read keychain entry %s/%s: %w", KeyringService, domain, err)
	}
	var s Session
	if err := json.Unmarshal([]byte(raw), &s); err != nil {
		// A corrupt entry is a cache miss, not a fatal error: logging in again
		// rewrites it.
		return nil, ErrNotFound
	}
	return &s, nil
}

// Set implements Store.
func (k *KeyringStore) Set(domain string, s *Session) error {
	data, err := json.Marshal(s)
	if err != nil {
		return fmt.Errorf("encode session: %w", err)
	}
	if err := keyringSet(KeyringService, domain, string(data)); err != nil {
		return fmt.Errorf("write keychain entry %s/%s: %w", KeyringService, domain, err)
	}
	return nil
}

// Delete implements Store.
func (k *KeyringStore) Delete(domain string) error {
	err := keyringDelete(KeyringService, domain)
	if err == nil || errors.Is(err, keyring.ErrNotFound) {
		return nil
	}
	return fmt.Errorf("delete keychain entry %s/%s: %w", KeyringService, domain, err)
}
