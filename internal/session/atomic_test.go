package session

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// flakyFile fails one chosen step of the atomic write.
type flakyFile struct {
	writeErr error
	syncErr  error
	closeErr error
}

func (f *flakyFile) Write(p []byte) (int, error) {
	if f.writeErr != nil {
		return 0, f.writeErr
	}
	return len(p), nil
}
func (f *flakyFile) Sync() error  { return f.syncErr }
func (f *flakyFile) Close() error { return f.closeErr }

func withTempFile(t *testing.T, file tempFile, openErr error) {
	t.Helper()
	orig := openTemp
	t.Cleanup(func() { openTemp = orig })
	openTemp = func(string) (tempFile, error) {
		if openErr != nil {
			return nil, openErr
		}
		return file, nil
	}
}

// Every step of the atomic write reports its own failure, and none of them
// leaves a half-written temp file behind for the next read to pick up.
func TestAtomicWriteFailures(t *testing.T) {
	boom := errors.New("io error")
	tests := []struct {
		name    string
		file    tempFile
		openErr error
		wantIn  string
	}{
		{"create fails", nil, boom, "create"},
		{"write fails", &flakyFile{writeErr: boom}, nil, "write"},
		{"fsync fails", &flakyFile{syncErr: boom}, nil, "fsync"},
		{"close fails", &flakyFile{closeErr: boom}, nil, "close"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "sessions.json")
			withTempFile(t, tc.file, tc.openErr)
			err := NewFileStore(path).Set("api", sampleSession())
			if err == nil || !strings.Contains(err.Error(), tc.wantIn) {
				t.Fatalf("Set = %v, want an error mentioning %q", err, tc.wantIn)
			}
			if _, statErr := os.Stat(path); !errors.Is(statErr, os.ErrNotExist) {
				t.Fatal("a failed write must not leave the target file in place")
			}
		})
	}
}

func TestAtomicWriteRenameFailure(t *testing.T) {
	boom := errors.New("cross-device link")
	orig := renameFile
	t.Cleanup(func() { renameFile = orig })
	renameFile = func(string, string) error { return boom }

	path := filepath.Join(t.TempDir(), "sessions.json")
	err := NewFileStore(path).Set("api", sampleSession())
	if err == nil || !strings.Contains(err.Error(), "rename") {
		t.Fatalf("Set = %v, want a rename error", err)
	}
	if _, statErr := os.Stat(path + ".tmp"); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatal("a failed rename must clean up its temp file")
	}
}
