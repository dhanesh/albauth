package session

import (
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"albauth/internal/flock"
)

// Two FileStores on one path stand in for two albauth processes: each has its
// own mutex, so only the file lock keeps their writes from losing each other's
// domains.
func TestFileStoresSharingAFileLoseNoUpdate(t *testing.T) {
	path := t.TempDir() + "/sessions.json"
	stores := []*FileStore{NewFileStore(path), NewFileStore(path)}
	var wg sync.WaitGroup
	errs := make(chan error, 40)
	for i := range 40 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s := &Session{Cookies: []Cookie{{Name: "c", Value: fmt.Sprint(i)}}}
			errs <- stores[i%2].Set(fmt.Sprintf("d%d", i), s)
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("Set: %v", err)
		}
	}
	for i := range 40 {
		if _, err := stores[0].Get(fmt.Sprintf("d%d", i)); err != nil {
			t.Fatalf("d%d lost: %v", i, err)
		}
	}
}

func TestFileStoreWriteGivesUpOnAStuckLock(t *testing.T) {
	path := t.TempDir() + "/sessions.json"
	held, ok, err := flock.TryLock(path + ".lock")
	if err != nil || !ok {
		t.Fatalf("TryLock = %v, %v", ok, err)
	}
	defer func() { _ = held.Unlock() }()
	orig := lockWait
	lockWait = 100 * time.Millisecond
	t.Cleanup(func() { lockWait = orig })

	f := NewFileStore(path)
	for name, op := range map[string]func() error{
		"Set":    func() error { return f.Set("d", &Session{}) },
		"Delete": func() error { return f.Delete("d") },
	} {
		if err := op(); err == nil || !strings.Contains(err.Error(), "another albauth process") {
			t.Fatalf("%s = %v, want a stuck-lock error", name, err)
		}
	}
}
