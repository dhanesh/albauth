package session

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// bigSession is a two-chunk session the size a real ALB issues once the
// identity provider's claims spill past one 4 KB cookie.
func bigSession() *Session {
	exp := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	return &Session{
		Cookies: []Cookie{
			{Name: "AWSELBAuthSessionCookie-0", Value: strings.Repeat("a", 4000), Domain: "api.example.com", Path: "/", Expires: exp, Secure: true, HTTPOnly: true},
			{Name: "AWSELBAuthSessionCookie-1", Value: strings.Repeat("b", 1500), Domain: "api.example.com", Path: "/", Expires: exp, Secure: true, HTTPOnly: true},
		},
		AcquiredAt: exp.Add(-time.Hour),
	}
}

// openAuto opens storage = "auto" over a working fake keychain.
func openAuto(t *testing.T, fake *fakeKeyring, warner Warner) (Store, string) {
	t.Helper()
	fake.install(t)
	path := filepath.Join(t.TempDir(), "state", "sessions.json")
	store, err := Open("auto", path, warner)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return store, path
}

func TestKeyringTooBigFallsBackToFile(t *testing.T) {
	fake := &fakeKeyring{tooBig: true}
	warner := &recordingWarner{}
	store, path := openAuto(t, fake, warner)
	// A smaller session from an earlier login is still in the keychain.
	fake.entries[KeyringService+"/api"] = `{"cookies":[]}`

	if err := store.Set("api", bigSession()); err != nil {
		t.Fatalf("Set of an oversized session: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("the session file was not written: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("session file mode = %#o, want 0600", perm)
	}
	if dir, _ := os.Stat(filepath.Dir(path)); dir.Mode().Perm() != 0o700 {
		t.Fatalf("state dir mode = %#o, want 0700", dir.Mode().Perm())
	}
	if _, stale := fake.entries[KeyringService+"/api"]; stale {
		t.Fatal("the stale keychain entry should have been removed")
	}

	// A second oversized save must not warn again.
	if err := store.Set("api", bigSession()); err != nil {
		t.Fatalf("second Set: %v", err)
	}
	if len(warner.lines) != 2 || warner.lines[0] != warner.lines[1] {
		t.Fatalf("want the same once-keyed warning for both saves, got %v", warner.lines)
	}
	if !strings.HasPrefix(warner.lines[0], "storage-too-big:api: ") {
		t.Fatalf("warning is not keyed per domain: %s", warner.lines[0])
	}
	for _, needle := range []string{`"api"`, "too large for the OS keychain", path, "0600", `storage = "file"`} {
		if !strings.Contains(warner.lines[0], needle) {
			t.Fatalf("warning is missing %q: %s", needle, warner.lines[0])
		}
	}
	if strings.Contains(warner.lines[0], "aaaa") || strings.Contains(warner.lines[0], "bbbb") {
		t.Fatalf("warning leaked a cookie value: %s", warner.lines[0])
	}

	got, err := store.Get("api")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if len(got.Cookies) != 2 || len(got.Cookies[0].Value) != 4000 || len(got.Cookies[1].Value) != 1500 {
		t.Fatalf("Get returned the wrong session: %d cookies", len(got.Cookies))
	}
	if b := BackendFor(store, "api"); b != BackendFile {
		t.Fatalf("BackendFor(api) = %q, want file", b)
	}
	if b := BackendFor(store, "other"); b != BackendKeyring {
		t.Fatalf("BackendFor(other) = %q, want keyring", b)
	}

	// Leave something in the keychain too, so Delete has two places to clear.
	fake.entries[KeyringService+"/api"] = `{"cookies":[]}`
	if err := store.Delete("api"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, left := fake.entries[KeyringService+"/api"]; left {
		t.Fatal("Delete left the keychain entry")
	}
	if _, err := NewFileStore(path).Get("api"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Delete left the file entry: %v", err)
	}
	if _, err := store.Get("api"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get after Delete = %v, want ErrNotFound", err)
	}
}

// T5 (auto with a working keychain) must behave exactly as the keychain does
// for a session that fits, and must not create the session file.
func TestAutoKeepsSessionsThatFitInTheKeychain(t *testing.T) {
	fake := &fakeKeyring{}
	store, path := openAuto(t, fake, &recordingWarner{})
	if store.Backend() != BackendKeyring {
		t.Fatalf("Backend() = %q", store.Backend())
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
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the session file should never have been created: %v", err)
	}
}

func TestAutoDropsTheFileCopyWhenASessionFitsAgain(t *testing.T) {
	fake := &fakeKeyring{tooBig: true}
	store, path := openAuto(t, fake, nil) // no warner: the fallback still works
	if err := store.Set("api", bigSession()); err != nil {
		t.Fatalf("Set: %v", err)
	}
	fake.tooBig = false
	if err := store.Set("api", sampleSession()); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if _, err := NewFileStore(path).Get("api"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("the file still holds the old session: %v", err)
	}
	if BackendFor(store, "api") != BackendKeyring {
		t.Fatal("the session should be back in the keychain")
	}
}

func TestAutoFallbackFailures(t *testing.T) {
	boom := errors.New("keychain locked")

	t.Run("a keychain read error is reported, not masked by the file", func(t *testing.T) {
		fake := &fakeKeyring{}
		store, _ := openAuto(t, fake, nil)
		fake.getErr = boom
		if _, err := store.Get("api"); !errors.Is(err, boom) {
			t.Fatalf("Get = %v, want the keychain error", err)
		}
	})
	t.Run("any other keychain write error is not a fallback", func(t *testing.T) {
		fake := &fakeKeyring{}
		store, path := openAuto(t, fake, nil)
		fake.setErr = boom
		if err := store.Set("api", bigSession()); !errors.Is(err, boom) {
			t.Fatalf("Set = %v, want the keychain error", err)
		}
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("a non-size failure must not write the file")
		}
	})
	t.Run("the file write fails", func(t *testing.T) {
		fake := &fakeKeyring{tooBig: true}
		fake.install(t)
		blocker := filepath.Join(t.TempDir(), "not-a-dir")
		if err := os.WriteFile(blocker, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		store, err := Open("auto", filepath.Join(blocker, "sessions.json"), nil)
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		if err := store.Set("api", bigSession()); err == nil {
			t.Fatal("Set should report the file write failure")
		}
	})
	t.Run("the stale keychain entry cannot be removed", func(t *testing.T) {
		fake := &fakeKeyring{tooBig: true}
		store, _ := openAuto(t, fake, nil)
		fake.delErr = boom
		if err := store.Set("api", bigSession()); !errors.Is(err, boom) {
			t.Fatalf("Set = %v, want the keychain delete error", err)
		}
	})
	t.Run("delete reports a keychain failure", func(t *testing.T) {
		fake := &fakeKeyring{}
		store, _ := openAuto(t, fake, nil)
		fake.delErr = boom
		if err := store.Delete("api"); !errors.Is(err, boom) {
			t.Fatalf("Delete = %v, want the keychain error", err)
		}
	})
	t.Run("delete reports an unreadable session file", func(t *testing.T) {
		fake := &fakeKeyring{}
		store, path := openAuto(t, fake, nil)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("{}"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := store.Delete("api"); !errors.Is(err, ErrInsecureFile) {
			t.Fatalf("Delete = %v, want ErrInsecureFile", err)
		}
	})
}

// With storage = "keyring" there is no fallback: the refusal is a storage
// error that says why.
func TestHardKeyringReportsATooLargeSession(t *testing.T) {
	(&fakeKeyring{tooBig: true}).install(t)
	store, err := Open("keyring", "/unused", nil)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	err = store.Set("api", bigSession())
	if !errors.Is(err, ErrSessionTooLarge) {
		t.Fatalf("Set = %v, want ErrSessionTooLarge", err)
	}
	if strings.Contains(err.Error(), "aaaa") {
		t.Fatalf("error leaked a cookie value: %v", err)
	}
	if BackendFor(store, "api") != BackendKeyring {
		t.Fatal("a plain keychain store reports its single backend")
	}
}
