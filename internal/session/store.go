package session

import (
	"errors"
	"fmt"
)

// Store persists sessions keyed by configured domain name.
type Store interface {
	Get(domain string) (*Session, error)
	Set(domain string, s *Session) error
	Delete(domain string) error
	// Backend names the storage in use, for auth_status and diagnostics.
	Backend() string
}

// ErrNotFound is returned by Get when no session is stored for a domain.
var ErrNotFound = errors.New("no stored session")

// ErrInsecureFile is returned when the session file's mode is wider than 0600.
var ErrInsecureFile = errors.New("session file is group- or world-accessible")

// Backend names.
const (
	BackendKeyring = "keyring"
	BackendFile    = "file"
	BackendMemory  = "memory"
)

// Warner receives the one-time notice emitted when `storage = "auto"` falls
// back from the OS keychain to the file backend.
type Warner interface {
	WarnOnce(key, format string, args ...any)
}

// Open selects a backend according to the storage setting.
//
//	"keyring" — keyring only; a missing keychain is a hard failure
//	"file"    — file only, no warning
//	"auto"    — keyring if a Set/Get round-trip works, else file plus one warning
func Open(storage, filePath string, warner Warner) (Store, error) {
	switch storage {
	case "keyring":
		ks := NewKeyringStore()
		if err := ks.probe(); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrKeyringUnavailable, err)
		}
		return ks, nil
	case "file":
		return NewFileStore(filePath), nil
	case "auto":
		ks := NewKeyringStore()
		if err := ks.probe(); err == nil {
			return ks, nil
		} else if warner != nil {
			warner.WarnOnce("storage-fallback",
				"OS keychain unavailable (%v); storing session cookies at %s with mode 0600. "+
					"Set storage = \"file\" in config to silence this.", err, filePath)
		}
		return NewFileStore(filePath), nil
	default:
		return nil, fmt.Errorf("unknown storage backend %q", storage)
	}
}

// ErrKeyringUnavailable is returned when storage = "keyring" but no OS
// keychain can be reached.
var ErrKeyringUnavailable = errors.New("keyring unavailable")

// MemoryStore is an in-memory Store, used by tests and by `config validate`.
type MemoryStore struct {
	sessions map[string]*Session
	// FailSet, when non-nil, is returned by Set. Tests use it to drive the
	// persistence-failure branch of the login path.
	FailSet error
}

// NewMemoryStore returns an empty in-memory store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{sessions: map[string]*Session{}}
}

// Get implements Store.
func (m *MemoryStore) Get(domain string) (*Session, error) {
	s, ok := m.sessions[domain]
	if !ok {
		return nil, ErrNotFound
	}
	return s, nil
}

// Set implements Store.
func (m *MemoryStore) Set(domain string, s *Session) error {
	if m.FailSet != nil {
		return m.FailSet
	}
	m.sessions[domain] = s
	return nil
}

// Delete implements Store.
func (m *MemoryStore) Delete(domain string) error {
	delete(m.sessions, domain)
	return nil
}

// Backend implements Store.
func (m *MemoryStore) Backend() string { return BackendMemory }
