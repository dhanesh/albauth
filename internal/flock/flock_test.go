package flock

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestTryLockExcludesASecondHolder(t *testing.T) {
	path := filepath.Join(t.TempDir(), "locks", "api.lock")
	first, ok, err := TryLock(path)
	if err != nil || !ok {
		t.Fatalf("first TryLock = %v, %v", ok, err)
	}
	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("lock file = %v, %v; want mode 0600", info, err)
	}
	if _, ok, err := TryLock(path); err != nil || ok {
		t.Fatalf("second TryLock = %v, %v; want busy", ok, err)
	}
	if err := first.Unlock(); err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	again, ok, err := TryLock(path)
	if err != nil || !ok {
		t.Fatalf("TryLock after Unlock = %v, %v", ok, err)
	}
	_ = again.Unlock()
}

func TestAcquireWaitsForTheHolder(t *testing.T) {
	path := filepath.Join(t.TempDir(), "api.lock")
	held, _, _ := TryLock(path)
	go func() {
		time.Sleep(3 * pollInterval)
		_ = held.Unlock()
	}()
	l, err := Acquire(context.Background(), path)
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	_ = l.Unlock()
}

func TestAcquireStopsWithItsContext(t *testing.T) {
	path := filepath.Join(t.TempDir(), "api.lock")
	held, _, _ := TryLock(path)
	defer func() { _ = held.Unlock() }()
	ctx, cancel := context.WithTimeout(context.Background(), 2*pollInterval)
	defer cancel()
	if _, err := Acquire(ctx, path); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Acquire = %v, want the context's deadline", err)
	}
}

func TestTryLockReportsAnUnusablePath(t *testing.T) {
	dir := t.TempDir()
	blocker := filepath.Join(dir, "file")
	if err := os.WriteFile(blocker, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	// A directory cannot be created under a regular file.
	if _, _, err := TryLock(filepath.Join(blocker, "sub", "x.lock")); err == nil {
		t.Fatal("want an error for a lock directory under a file")
	}
	// A directory cannot be opened read-write as the lock file.
	if _, _, err := TryLock(dir); err == nil {
		t.Fatal("want an error for a lock path that is a directory")
	}
	if _, err := Acquire(context.Background(), dir); err == nil {
		t.Fatal("Acquire should return TryLock's error")
	}
}

func TestTryLockReportsAFailedLockCall(t *testing.T) {
	orig := lock
	t.Cleanup(func() { lock = orig })
	lock = func(*os.File) error { return errors.New("no locks on this filesystem") }
	if _, ok, err := TryLock(filepath.Join(t.TempDir(), "api.lock")); ok || err == nil {
		t.Fatalf("TryLock = %v, %v; want the lock error", ok, err)
	}
}
