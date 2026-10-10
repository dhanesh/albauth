// Package flock provides an advisory, exclusive lock on a file, shared by
// every albauth process on the machine.
//
// Two MCP clients each start their own `albauth serve`, and the CLI can run
// beside them. They share one session store, so without a lock between them
// two processes can each open a browser for the same expired session, or
// write the session file at the same moment and lose one of the updates.
//
// The lock is released when the process exits, however it exits, so a crash
// never leaves a domain locked.
package flock

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// pollInterval is how often Lock retries a lock another process holds.
var pollInterval = 50 * time.Millisecond

// Lock is a held lock. Unlock releases it.
type Lock struct{ file *os.File }

// TryLock takes the lock at path if no other holder has it. It reports false,
// with no error, when another holder does. The file is created 0600 (and its
// directory 0700) if missing.
func TryLock(path string) (*Lock, bool, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, false, fmt.Errorf("create lock directory: %w", err)
	}
	file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600) // #nosec G304 -- path is state-dir-derived
	if err != nil {
		return nil, false, fmt.Errorf("open lock %s: %w", path, err)
	}
	if err := lock(file); err != nil {
		_ = file.Close()
		if errors.Is(err, errBusy) {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("lock %s: %w", path, err)
	}
	return &Lock{file: file}, true, nil
}

// Acquire waits for the lock at path until ctx is done. A ctx that ends first
// returns ctx's error.
func Acquire(ctx context.Context, path string) (*Lock, error) {
	for {
		l, ok, err := TryLock(path)
		if err != nil || ok {
			return l, err
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(pollInterval):
		}
	}
}

// Unlock releases the lock. Closing the file releases it; the file itself is
// left in place, because removing it would race a process about to lock it.
func (l *Lock) Unlock() error { return l.file.Close() }

// lock is lockFile, named so a test can drive a lock call that fails outright,
// which a real filesystem will not do on demand.
var lock = lockFile

// errBusy is what lockFile returns when another holder has the lock.
var errBusy = errors.New("lock held by another holder")
