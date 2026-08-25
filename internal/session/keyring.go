package session

import (
	"encoding/json"
	"errors"
	"fmt"

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
