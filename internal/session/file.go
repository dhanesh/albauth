package session

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"sync"
	"time"

	"albauth/internal/flock"
)

// File permissions. The session file holds live credentials, so the directory
// is owner-only too — a 0700 directory stops another user enumerating it even
// if the file mode were ever loosened by an editor.
const (
	dirMode  fs.FileMode = 0o700
	fileMode fs.FileMode = 0o600
)

// FileStore persists sessions as a single 0600 JSON file.
type FileStore struct {
	mu   sync.Mutex
	path string
}

// NewFileStore returns a FileStore backed by the file at path.
func NewFileStore(path string) *FileStore { return &FileStore{path: path} }

// Path is the file this store reads and writes.
func (f *FileStore) Path() string { return f.path }

// Backend implements Store.
func (f *FileStore) Backend() string { return BackendFile }

// load reads the session file. A missing file yields an empty set; a corrupt
// file is recovered from rather than fatal — the cookies inside are a cache
// that can be rebuilt by logging in again, so a parse error costs one login,
// not a broken install.
func (f *FileStore) load() (*File, error) {
	info, err := os.Stat(f.path)
	if errors.Is(err, fs.ErrNotExist) {
		return &File{Version: FileVersion, Domains: map[string]*Session{}}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("stat %s: %w", f.path, err)
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return nil, fmt.Errorf("%w: %s has mode %#o, want 0600 (chmod 600 %s)",
			ErrInsecureFile, f.path, perm, f.path)
	}
	data, err := os.ReadFile(f.path) // #nosec G304 -- path is config-derived
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", f.path, err)
	}
	var parsed File
	if err := json.Unmarshal(data, &parsed); err != nil {
		return &File{Version: FileVersion, Domains: map[string]*Session{}}, nil
	}
	if parsed.Domains == nil {
		parsed.Domains = map[string]*Session{}
	}
	return &parsed, nil
}

// Get implements Store.
func (f *FileStore) Get(domain string) (*Session, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	parsed, err := f.load()
	if err != nil {
		return nil, err
	}
	s, ok := parsed.Domains[domain]
	if !ok || s == nil {
		return nil, ErrNotFound
	}
	return s, nil
}

// lockWait bounds how long a write waits for another albauth process to finish
// its own write of the session file. A write takes milliseconds, so a wait this
// long means the other process is stuck.
var lockWait = 10 * time.Second

// lockFile takes the cross-process lock that guards the file's
// read-modify-write. Without it, two processes writing different domains at
// once would each save the file they read, and one update would be lost; they
// would also share the one temp file.
func (f *FileStore) lockFile() (*flock.Lock, error) {
	ctx, cancel := context.WithTimeout(context.Background(), lockWait)
	defer cancel()
	l, err := flock.Acquire(ctx, f.path+".lock")
	if err != nil {
		return nil, fmt.Errorf("lock %s for writing (another albauth process may be stuck): %w", f.path, err)
	}
	return l, nil
}

// Set implements Store.
func (f *FileStore) Set(domain string, s *Session) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	l, err := f.lockFile()
	if err != nil {
		return err
	}
	defer func() { _ = l.Unlock() }()
	parsed, err := f.load()
	if err != nil {
		return err
	}
	parsed.Version = FileVersion
	parsed.Domains[domain] = s
	return f.save(parsed)
}

// Delete implements Store.
func (f *FileStore) Delete(domain string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	l, err := f.lockFile()
	if err != nil {
		return err
	}
	defer func() { _ = l.Unlock() }()
	parsed, err := f.load()
	if err != nil {
		return err
	}
	delete(parsed.Domains, domain)
	return f.save(parsed)
}

// save writes the file atomically: a temp file in the same directory, fsynced,
// then renamed over the target. A crash mid-write leaves the previous file
// intact rather than a truncated one.
func (f *FileStore) save(parsed *File) error {
	// The directory exists: lockFile created it (0700) to hold the lock file.
	data, err := json.MarshalIndent(parsed, "", "  ")
	if err != nil {
		return fmt.Errorf("encode sessions: %w", err)
	}
	tmp := f.path + ".tmp"
	handle, err := openTemp(tmp)
	if err != nil {
		return fmt.Errorf("create %s: %w", tmp, err)
	}
	if _, err := handle.Write(data); err != nil {
		_ = handle.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("write %s: %w", tmp, err)
	}
	if err := handle.Sync(); err != nil {
		_ = handle.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("fsync %s: %w", tmp, err)
	}
	if err := handle.Close(); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("close %s: %w", tmp, err)
	}
	if err := renameFile(tmp, f.path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("rename %s: %w", tmp, err)
	}
	return nil
}

// tempFile is the subset of *os.File the atomic write uses. Naming it lets the
// tests drive the write, fsync, close and rename failures that a real
// filesystem will not reproduce on demand.
type tempFile interface {
	Write([]byte) (int, error)
	Sync() error
	Close() error
}

var (
	openTemp = func(path string) (tempFile, error) {
		return os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, fileMode) // #nosec G304
	}
	renameFile = os.Rename
)
