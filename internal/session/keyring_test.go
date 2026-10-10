package session

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zalando/go-keyring"
)

// fakeKeyring replaces the OS keychain for tests. A real one is unavailable on
// headless machines, which is precisely the condition the fallback exists for.
type fakeKeyring struct {
	entries map[string]string
	setErr  error
	getErr  error
	delErr  error
	// corruptProbe makes the probe read back the wrong value, exercising the
	// round-trip mismatch branch.
	corruptProbe bool
	// tooBig makes every Set except the probe's fail the way go-keyring does
	// when a value exceeds the OS keychain's limit: before writing anything.
	tooBig bool
}

func (f *fakeKeyring) install(t *testing.T) {
	t.Helper()
	if f.entries == nil {
		f.entries = map[string]string{}
	}
	origSet, origGet, origDel := keyringSet, keyringGet, keyringDelete
	t.Cleanup(func() { keyringSet, keyringGet, keyringDelete = origSet, origGet, origDel })

	keyringSet = func(service, user, password string) error {
		if f.setErr != nil {
			return f.setErr
		}
		if f.tooBig && user != probeUser {
			return keyring.ErrSetDataTooBig
		}
		if f.corruptProbe && user == probeUser {
			f.entries[service+"/"+user] = "wrong"
			return nil
		}
		f.entries[service+"/"+user] = password
		return nil
	}
	keyringGet = func(service, user string) (string, error) {
		if f.getErr != nil {
			return "", f.getErr
		}
		v, ok := f.entries[service+"/"+user]
		if !ok {
			return "", keyring.ErrNotFound
		}
		return v, nil
	}
	keyringDelete = func(service, user string) error {
		if f.delErr != nil {
			return f.delErr
		}
		if _, ok := f.entries[service+"/"+user]; !ok {
			return keyring.ErrNotFound
		}
		delete(f.entries, service+"/"+user)
		return nil
	}
}

func TestKeyringStoreRoundTrip(t *testing.T) {
	fake := &fakeKeyring{}
	fake.install(t)
	store := NewKeyringStore()

	if store.Backend() != BackendKeyring {
		t.Fatalf("Backend() = %q", store.Backend())
	}
	if _, err := store.Get("api"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get on an empty keychain = %v, want ErrNotFound", err)
	}
	if err := store.Set("api", sampleSession()); err != nil {
		t.Fatalf("Set: %v", err)
	}
	got, err := store.Get("api")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if len(got.Cookies) != 1 || got.Cookies[0].Value != "abc" {
		t.Fatalf("Get returned %+v", got)
	}
	if err := store.Delete("api"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	// Deleting a missing entry is a no-op, not an error.
	if err := store.Delete("api"); err != nil {
		t.Fatalf("second Delete: %v", err)
	}
}

func TestKeyringStoreTreatsACorruptEntryAsAMiss(t *testing.T) {
	fake := &fakeKeyring{entries: map[string]string{KeyringService + "/api": "{not json"}}
	fake.install(t)
	if _, err := NewKeyringStore().Get("api"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get on a corrupt entry = %v, want ErrNotFound", err)
	}
}

func TestKeyringStoreReportsBackendFailures(t *testing.T) {
	boom := errors.New("d-bus is not running")

	t.Run("get", func(t *testing.T) {
		(&fakeKeyring{getErr: boom}).install(t)
		if _, err := NewKeyringStore().Get("api"); !errors.Is(err, boom) {
			t.Fatalf("Get = %v, want the backend error", err)
		}
	})
	t.Run("set", func(t *testing.T) {
		(&fakeKeyring{setErr: boom}).install(t)
		if err := NewKeyringStore().Set("api", sampleSession()); !errors.Is(err, boom) {
			t.Fatalf("Set = %v, want the backend error", err)
		}
	})
	t.Run("delete", func(t *testing.T) {
		fake := &fakeKeyring{delErr: boom}
		fake.install(t)
		if err := NewKeyringStore().Delete("api"); !errors.Is(err, boom) {
			t.Fatalf("Delete = %v, want the backend error", err)
		}
	})
}

func TestKeyringStoreRejectsAnUnencodableSession(t *testing.T) {
	(&fakeKeyring{}).install(t)
	bad := &Session{Cookies: []Cookie{{Name: "a", Expires: badTime()}}}
	if err := NewKeyringStore().Set("api", bad); err == nil {
		t.Fatal("Set should reject a session that cannot be encoded")
	}
}

func TestKeyringProbe(t *testing.T) {
	t.Run("succeeds and cleans up after itself", func(t *testing.T) {
		fake := &fakeKeyring{}
		fake.install(t)
		if err := NewKeyringStore().probe(); err != nil {
			t.Fatalf("probe: %v", err)
		}
		if _, present := fake.entries[KeyringService+"/"+probeUser]; present {
			t.Fatal("the probe entry should not be left behind")
		}
	})
	t.Run("fails when the keychain rejects a write", func(t *testing.T) {
		(&fakeKeyring{setErr: errors.New("locked")}).install(t)
		if err := NewKeyringStore().probe(); err == nil {
			t.Fatal("probe should fail when Set fails")
		}
	})
	t.Run("fails when the keychain rejects a read", func(t *testing.T) {
		(&fakeKeyring{getErr: errors.New("locked")}).install(t)
		if err := NewKeyringStore().probe(); err == nil {
			t.Fatal("probe should fail when Get fails")
		}
	})
	t.Run("fails when the round-trip returns the wrong value", func(t *testing.T) {
		(&fakeKeyring{corruptProbe: true}).install(t)
		err := NewKeyringStore().probe()
		if err == nil || !strings.Contains(err.Error(), "round-trip") {
			t.Fatalf("probe = %v, want a round-trip mismatch", err)
		}
	})
}

// keychainReachable is the guard that keeps a macOS box with no keychain from
// raising a modal dialog at an MCP server nobody is looking at.
func TestKeychainReachable(t *testing.T) {
	origOS, origHome, origRead := goos, osUserHomeDir, osReadDir
	t.Cleanup(func() { goos, osUserHomeDir, osReadDir = origOS, origHome, origRead })

	t.Run("elsewhere the probe itself is the check", func(t *testing.T) {
		goos = "linux"
		if err := keychainReachable(); err != nil {
			t.Fatalf("keychainReachable() = %v, want nil off darwin", err)
		}
	})

	t.Run("a keychain is present", func(t *testing.T) {
		goos = "darwin"
		dir := t.TempDir()
		keychains := filepath.Join(dir, "Library", "Keychains")
		if err := os.MkdirAll(keychains, 0o700); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(filepath.Join(keychains, "login.keychain-db"), []byte("x"), 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
		osUserHomeDir = func() (string, error) { return dir, nil }
		osReadDir = os.ReadDir
		if err := keychainReachable(); err != nil {
			t.Fatalf("keychainReachable() = %v, want nil when a keychain exists", err)
		}
	})

	t.Run("the directory exists but holds no keychain", func(t *testing.T) {
		goos = "darwin"
		dir := t.TempDir()
		if err := os.MkdirAll(filepath.Join(dir, "Library", "Keychains"), 0o700); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		osUserHomeDir = func() (string, error) { return dir, nil }
		osReadDir = os.ReadDir
		if err := keychainReachable(); err == nil {
			t.Fatal("keychainReachable() accepted a directory with no keychain in it")
		}
	})

	t.Run("there is no keychain directory", func(t *testing.T) {
		goos = "darwin"
		osUserHomeDir = func() (string, error) { return t.TempDir(), nil }
		osReadDir = os.ReadDir
		if err := keychainReachable(); err == nil {
			t.Fatal("keychainReachable() accepted a home with no Keychains directory")
		}
	})

	t.Run("the home directory cannot be found", func(t *testing.T) {
		goos = "darwin"
		osUserHomeDir = func() (string, error) { return "", errors.New("no home") }
		if err := keychainReachable(); err == nil {
			t.Fatal("keychainReachable() accepted an unknown home directory")
		}
	})
}

func TestProbeStopsWhenThereIsNoKeychain(t *testing.T) {
	origOS, origHome := goos, osUserHomeDir
	t.Cleanup(func() { goos, osUserHomeDir = origOS, origHome })
	goos = "darwin"
	osUserHomeDir = func() (string, error) { return t.TempDir(), nil }

	origSet := keyringSet
	t.Cleanup(func() { keyringSet = origSet })
	called := false
	keyringSet = func(string, string, string) error { called = true; return nil }

	if err := (&KeyringStore{}).probe(); err == nil {
		t.Fatal("probe() succeeded with no keychain present")
	}
	if called {
		t.Fatal("probe() wrote to the keychain anyway; that is what raises the modal dialog")
	}
}
