package session

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func badTime() time.Time { return time.Date(-1, 1, 1, 0, 0, 0, 0, time.UTC) }

// recordingWarner captures WarnOnce calls so the one-time fallback notice can
// be asserted on.
type recordingWarner struct{ lines []string }

func (r *recordingWarner) WarnOnce(key, format string, args ...any) {
	r.lines = append(r.lines, key+": "+fmt.Sprintf(format, args...))
}

func TestOpenKeyringBackend(t *testing.T) {
	t.Run("uses the keychain when it works", func(t *testing.T) {
		(&fakeKeyring{}).install(t)
		store, err := Open("keyring", "/unused", nil)
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		if store.Backend() != BackendKeyring {
			t.Fatalf("Backend() = %q", store.Backend())
		}
	})
	t.Run("hard-fails when the keychain is absent", func(t *testing.T) {
		(&fakeKeyring{setErr: errors.New("no Secret Service")}).install(t)
		_, err := Open("keyring", "/unused", nil)
		if !errors.Is(err, ErrKeyringUnavailable) {
			t.Fatalf("Open = %v, want ErrKeyringUnavailable", err)
		}
	})
}

func TestOpenFileBackendIsSilent(t *testing.T) {
	warner := &recordingWarner{}
	path := filepath.Join(t.TempDir(), "sessions.json")
	store, err := Open("file", path, warner)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if store.Backend() != BackendFile {
		t.Fatalf("Backend() = %q", store.Backend())
	}
	if len(warner.lines) != 0 {
		t.Fatalf("an explicit file backend must not warn, got %v", warner.lines)
	}
}

func TestOpenAutoPrefersTheKeychain(t *testing.T) {
	(&fakeKeyring{}).install(t)
	warner := &recordingWarner{}
	store, err := Open("auto", "/unused", warner)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if store.Backend() != BackendKeyring {
		t.Fatalf("Backend() = %q, want keyring", store.Backend())
	}
	if len(warner.lines) != 0 {
		t.Fatalf("no warning is due when the keychain works, got %v", warner.lines)
	}
}

func TestOpenAutoFallsBackToFileWithOneWarning(t *testing.T) {
	(&fakeKeyring{setErr: errors.New("no Secret Service on this box")}).install(t)
	warner := &recordingWarner{}
	path := filepath.Join(t.TempDir(), "sessions.json")

	store, err := Open("auto", path, warner)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if store.Backend() != BackendFile {
		t.Fatalf("Backend() = %q, want file", store.Backend())
	}
	if len(warner.lines) != 1 {
		t.Fatalf("want exactly one warning, got %v", warner.lines)
	}
	warning := warner.lines[0]
	for _, needle := range []string{"OS keychain unavailable", "no Secret Service on this box", path, "0600", `storage = "file"`} {
		if !strings.Contains(warning, needle) {
			t.Fatalf("warning is missing %q: %s", needle, warning)
		}
	}
}

func TestOpenAutoFallsBackWithoutAWarner(t *testing.T) {
	(&fakeKeyring{setErr: errors.New("no Secret Service")}).install(t)
	store, err := Open("auto", filepath.Join(t.TempDir(), "sessions.json"), nil)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if store.Backend() != BackendFile {
		t.Fatalf("Backend() = %q, want file", store.Backend())
	}
}

func TestOpenRejectsAnUnknownBackend(t *testing.T) {
	if _, err := Open("magic", "/unused", nil); err == nil {
		t.Fatal("Open should reject an unknown backend")
	}
}

func TestMemoryStore(t *testing.T) {
	store := NewMemoryStore()
	if store.Backend() != BackendMemory {
		t.Fatalf("Backend() = %q", store.Backend())
	}
	if _, err := store.Get("api"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get = %v, want ErrNotFound", err)
	}
	if err := store.Set("api", sampleSession()); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if _, err := store.Get("api"); err != nil {
		t.Fatalf("Get: %v", err)
	}
	if err := store.Delete("api"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := store.Get("api"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get after Delete = %v, want ErrNotFound", err)
	}

	boom := errors.New("disk full")
	store.FailSet = boom
	if err := store.Set("api", sampleSession()); !errors.Is(err, boom) {
		t.Fatalf("Set with FailSet = %v, want the injected error", err)
	}
}
