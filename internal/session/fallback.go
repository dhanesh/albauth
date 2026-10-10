package session

import (
	"errors"
	"fmt"
)

// fallbackStore is what `storage = "auto"` uses when the OS keychain works.
// Sessions go to the keychain, except one the keychain refuses as too large:
// that domain's session is kept in the 0600 file store instead, with a
// one-time warning. A chunked session (two or more cookies, 4 KB and up) does
// not fit the macOS keychain, so without this the login would succeed and the
// session would be lost.
type fallbackStore struct {
	keyring *KeyringStore
	file    *FileStore
	warner  Warner
}

// Backend implements Store. It names the store's primary backend; BackendFor
// names the one holding a particular domain.
func (f *fallbackStore) Backend() string { return BackendKeyring }

// BackendFor reports BackendFile for a domain whose session lives in the file
// and BackendKeyring otherwise.
func (f *fallbackStore) BackendFor(domain string) string {
	if _, err := f.file.Get(domain); err == nil {
		return BackendFile
	}
	return BackendKeyring
}

// Get implements Store: the keychain first, then the file.
func (f *fallbackStore) Get(domain string) (*Session, error) {
	s, err := f.keyring.Get(domain)
	if !errors.Is(err, ErrNotFound) {
		return s, err
	}
	return f.file.Get(domain)
}

// Set implements Store.
func (f *fallbackStore) Set(domain string, s *Session) error {
	err := f.keyring.Set(domain, s)
	if err == nil {
		// The session fits again: drop any copy an earlier, larger session left
		// in the file so stale credentials do not linger there.
		if _, getErr := f.file.Get(domain); getErr == nil {
			return f.file.Delete(domain)
		}
		return nil
	}
	if !errors.Is(err, ErrSessionTooLarge) {
		return err
	}
	if err := f.file.Set(domain, s); err != nil {
		return err
	}
	// Nothing was written by the refused Set, but an older, smaller session
	// may still sit in the keychain and would shadow the file on Get.
	if err := f.keyring.Delete(domain); err != nil {
		return err
	}
	if f.warner != nil {
		f.warner.WarnOnce("storage-too-big:"+domain,
			"session for domain %q is too large for the OS keychain; storing it at %s with mode 0600. "+
				"Set storage = \"file\" in config to silence this.", domain, f.file.Path())
	}
	return nil
}

// Delete implements Store: it removes the session from both backends.
func (f *fallbackStore) Delete(domain string) error {
	if err := f.keyring.Delete(domain); err != nil {
		return err
	}
	_, err := f.file.Get(domain)
	switch {
	case errors.Is(err, ErrNotFound):
		// Never create the file just to delete from it.
		return nil
	case err != nil:
		return fmt.Errorf("check the session file: %w", err)
	}
	return f.file.Delete(domain)
}
