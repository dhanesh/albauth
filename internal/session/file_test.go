package session

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

func tempStore(t *testing.T) (*FileStore, string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "state", "sessions.json")
	return NewFileStore(path), path
}

func sampleSession() *Session {
	return &Session{
		Cookies:    []Cookie{{Name: "AWSELBAuthSessionCookie-0", Value: "abc", Expires: base}},
		AcquiredAt: base,
		LastUsedAt: base,
	}
}

func TestFileStoreRoundTrip(t *testing.T) {
	store, path := tempStore(t)
	if store.Path() != path {
		t.Fatalf("Path() = %q, want %q", store.Path(), path)
	}
	if store.Backend() != BackendFile {
		t.Fatalf("Backend() = %q", store.Backend())
	}

	if _, err := store.Get("missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get on an empty store = %v, want ErrNotFound", err)
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
	if _, err := store.Get("api"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get after Delete = %v, want ErrNotFound", err)
	}
	// Deleting something that was never there is not an error.
	if err := store.Delete("api"); err != nil {
		t.Fatalf("second Delete: %v", err)
	}
}

func TestFileStoreWritesOwnerOnlyPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX file modes are not meaningful on Windows")
	}
	store, path := tempStore(t)
	if err := store.Set("api", sampleSession()); err != nil {
		t.Fatalf("Set: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != fileMode {
		t.Fatalf("session file mode = %#o, want %#o", perm, fileMode)
	}
	dirInfo, err := os.Stat(filepath.Dir(path))
	if err != nil {
		t.Fatalf("stat dir: %v", err)
	}
	if perm := dirInfo.Mode().Perm(); perm != dirMode {
		t.Fatalf("state dir mode = %#o, want %#o", perm, dirMode)
	}
}

func TestFileStoreRefusesAWorldReadableFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX file modes are not meaningful on Windows")
	}
	store, path := tempStore(t)
	if err := store.Set("api", sampleSession()); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatalf("chmod: %v", err)
	}

	_, err := store.Get("api")
	if !errors.Is(err, ErrInsecureFile) {
		t.Fatalf("Get on a 0644 file = %v, want ErrInsecureFile", err)
	}
	if !strings.Contains(err.Error(), "chmod 600") {
		t.Fatalf("error should tell the user how to fix it, got: %v", err)
	}
	// Set and Delete load first, so they refuse too rather than rewriting a
	// file whose permissions were loosened behind our back.
	if err := store.Set("api", sampleSession()); !errors.Is(err, ErrInsecureFile) {
		t.Fatalf("Set on a 0644 file = %v, want ErrInsecureFile", err)
	}
	if err := store.Delete("api"); !errors.Is(err, ErrInsecureFile) {
		t.Fatalf("Delete on a 0644 file = %v, want ErrInsecureFile", err)
	}
}

func TestFileStoreRecoversFromCorruptJSON(t *testing.T) {
	store, path := tempStore(t)
	if err := os.MkdirAll(filepath.Dir(path), dirMode); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, []byte("{not json at all"), fileMode); err != nil {
		t.Fatalf("write: %v", err)
	}

	// A corrupt file is a cache miss, not a fatal error: the cookies inside can
	// always be rebuilt by logging in again.
	if _, err := store.Get("api"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get on corrupt JSON = %v, want ErrNotFound", err)
	}
	if err := store.Set("api", sampleSession()); err != nil {
		t.Fatalf("Set over corrupt JSON: %v", err)
	}
	if _, err := store.Get("api"); err != nil {
		t.Fatalf("Get after recovery: %v", err)
	}
}

func TestFileStoreHandlesNullDomainsMap(t *testing.T) {
	store, path := tempStore(t)
	if err := os.MkdirAll(filepath.Dir(path), dirMode); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, []byte(`{"version":1,"domains":null}`), fileMode); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := store.Get("api"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get = %v, want ErrNotFound", err)
	}
	if err := store.Set("api", sampleSession()); err != nil {
		t.Fatalf("Set: %v", err)
	}
}

func TestFileStoreTreatsAnExplicitNullSessionAsMissing(t *testing.T) {
	store, path := tempStore(t)
	if err := os.MkdirAll(filepath.Dir(path), dirMode); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, []byte(`{"version":1,"domains":{"api":null}}`), fileMode); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := store.Get("api"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get = %v, want ErrNotFound", err)
	}
}

func TestFileStoreWriteIsAtomic(t *testing.T) {
	store, path := tempStore(t)
	if err := store.Set("api", sampleSession()); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if _, err := os.Stat(path + ".tmp"); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("the temp file should not survive a successful write")
	}

	// The persisted shape is the documented one.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var parsed File
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("persisted file is not valid JSON: %v", err)
	}
	if parsed.Version != FileVersion {
		t.Fatalf("version = %d, want %d", parsed.Version, FileVersion)
	}
	if _, ok := parsed.Domains["api"]; !ok {
		t.Fatalf("domain missing from persisted file: %s", data)
	}
}

func TestFileStoreReportsStatFailure(t *testing.T) {
	// A path whose parent is a regular file cannot be stat'd as a directory
	// entry, which drives the non-ErrNotExist stat branch.
	dir := t.TempDir()
	notADir := filepath.Join(dir, "file")
	if err := os.WriteFile(notADir, []byte("x"), fileMode); err != nil {
		t.Fatalf("write: %v", err)
	}
	store := NewFileStore(filepath.Join(notADir, "sessions.json"))
	if _, err := store.Get("api"); err == nil {
		t.Fatal("Get should fail when the path is unusable")
	}
}

func TestFileStoreReportsUnwritableDirectory(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX directory permissions are not meaningful on Windows")
	}
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	dir := t.TempDir()
	readOnly := filepath.Join(dir, "readonly")
	if err := os.Mkdir(readOnly, 0o500); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(readOnly, 0o700) })

	store := NewFileStore(filepath.Join(readOnly, "nested", "sessions.json"))
	if err := store.Set("api", sampleSession()); err == nil {
		t.Fatal("Set should fail when the state directory cannot be created")
	}
}

func TestFileStoreReportsUnreadableFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX file modes are not meaningful on Windows")
	}
	if os.Geteuid() == 0 {
		t.Skip("root ignores file permissions")
	}
	store, path := tempStore(t)
	if err := store.Set("api", sampleSession()); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if err := os.Chmod(path, 0o200); err != nil { // owner-write only: mode check passes, read fails
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(path, fileMode) })

	if _, err := store.Get("api"); err == nil {
		t.Fatal("Get should fail when the file cannot be read")
	}
}

func TestFileStoreReportsUnwritableTempFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX directory permissions are not meaningful on Windows")
	}
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	dir := t.TempDir()
	store := NewFileStore(filepath.Join(dir, "sessions.json"))
	if err := store.Set("api", sampleSession()); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	if err := store.Set("api", sampleSession()); err == nil {
		t.Fatal("Set should fail when the temp file cannot be created")
	}
}

func TestFileStoreRejectsUnencodableSession(t *testing.T) {
	store, _ := tempStore(t)
	// time.Time marshals fine, so drive the encode failure through save directly
	// with a value json cannot represent.
	err := store.save(&File{Version: FileVersion, Domains: map[string]*Session{
		"api": {Cookies: []Cookie{{Name: "a", Expires: time.Date(-1, 1, 1, 0, 0, 0, 0, time.UTC)}}},
	}})
	if err == nil {
		t.Fatal("save should reject a session that cannot be encoded")
	}
}

func TestFileStoreIsConcurrencySafe(t *testing.T) {
	store, _ := tempStore(t)
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			_ = store.Set("api", sampleSession())
			_, _ = store.Get("api")
		})
	}
	wg.Wait()
	if _, err := store.Get("api"); err != nil {
		t.Fatalf("store is inconsistent after concurrent use: %v", err)
	}
}
