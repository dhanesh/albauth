package auth

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"albauth/internal/config"
	"albauth/internal/flock"
	"albauth/internal/session"
)

// twoProcesses returns two managers that share a store and a lock directory
// but nothing in memory, as two albauth processes on one machine do.
func twoProcesses(t *testing.T, loginer Loginer) (a, b *Manager, store session.Store) {
	t.Helper()
	// One FileStore each, on one path: nothing shared but the files.
	dir := t.TempDir()
	path := filepath.Join(dir, "sessions.json")
	mk := func(s session.Store) *Manager {
		return NewManager(ManagerOptions{Store: s, Loginer: loginer, Log: &capturingLogger{},
			Now: func() time.Time { return now }, LockDir: filepath.Join(dir, "locks")})
	}
	store = session.NewFileStore(path)
	return mk(store), mk(session.NewFileStore(path)), store
}

func holdLock(t *testing.T, dir, domain string) {
	t.Helper()
	l, ok, err := flock.TryLock(filepath.Join(dir, domain+".lock"))
	if err != nil || !ok {
		t.Fatalf("TryLock = %v, %v", ok, err)
	}
	t.Cleanup(func() { _ = l.Unlock() })
}

func TestTwoProcessesOpenOneBrowserForOneDomain(t *testing.T) {
	var logins atomic.Int32
	loginer := LoginerFunc(func(context.Context, *config.Domain, string) ([]session.Cookie, error) {
		logins.Add(1)
		time.Sleep(200 * time.Millisecond) // the user is still in the browser
		return albCookies("fresh"), nil
	})
	a, b, _ := twoProcesses(t, loginer)
	var wg sync.WaitGroup
	got := make([]*session.Session, 2)
	for i, m := range []*Manager{a, b} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s, err := m.Ensure(t.Context(), loginDomain())
			if err != nil {
				t.Errorf("Ensure: %v", err)
			}
			got[i] = s
		}()
	}
	wg.Wait()
	if n := logins.Load(); n != 1 {
		t.Fatalf("%d browser logins, want 1", n)
	}
	if got[0] == nil || got[1] == nil || !sameSession(got[0], got[1]) {
		t.Fatalf("the processes ended with different sessions: %+v / %+v", got[0], got[1])
	}
}

func TestALoginGivesUpWaitingForAStuckProcess(t *testing.T) {
	orig := loginSlack
	loginSlack = 100 * time.Millisecond
	t.Cleanup(func() { loginSlack = orig })
	loginer := LoginerFunc(func(context.Context, *config.Domain, string) ([]session.Cookie, error) {
		t.Fatal("the browser opened while another process held the domain")
		return nil, nil
	})
	a, _, _ := twoProcesses(t, loginer)
	holdLock(t, a.lockDir, "api")
	d := loginDomain()
	d.LoginTimeoutSeconds = 0

	for name, call := range map[string]func() error{
		"Ensure":     func() error { _, err := a.Ensure(t.Context(), d); return err },
		"ForceLogin": func() error { _, err := a.ForceLogin(t.Context(), d); return err },
	} {
		var coded *Error
		if err := call(); !errors.As(err, &coded) || coded.Code != CodeLoginTimeout ||
			!strings.Contains(coded.Hint, "another albauth process") {
			t.Fatalf("%s = %v, want login_timeout naming the other process", name, err)
		}
	}
	if lines := a.log.(*capturingLogger).lines; !slices.ContainsFunc(lines, func(l string) bool {
		return strings.Contains(l, "waiting for it")
	}) {
		t.Fatalf("no waiting message in %q", lines)
	}
}

func TestLogoutAndSaveWaitForAnotherProcess(t *testing.T) {
	orig := storeWait
	storeWait = 100 * time.Millisecond
	t.Cleanup(func() { storeWait = orig })
	a, _, store := twoProcesses(t, nil)
	_ = store.Set("api", &session.Session{Cookies: albCookies("v")})
	holdLock(t, a.lockDir, "api")

	if err := a.Logout("api"); err == nil || !strings.Contains(err.Error(), "another albauth process") {
		t.Fatalf("Logout = %v, want a busy error", err)
	}
	if err := a.Save("api", &session.Session{}); err == nil {
		t.Fatal("Save should report the busy domain")
	}
	if _, err := store.Get("api"); err != nil {
		t.Fatalf("the session changed while another process held it: %v", err)
	}
}

func TestBackgroundUpdatesSkipABusyDomain(t *testing.T) {
	cases := map[string]func(t *testing.T, m *Manager){
		"held by another process": func(t *testing.T, m *Manager) { holdLock(t, m.lockDir, "api") },
		"held in this process": func(t *testing.T, m *Manager) {
			mu := m.lockFor("api")
			mu.Lock()
			t.Cleanup(mu.Unlock)
		},
	}
	for name, hold := range cases {
		t.Run(name, func(t *testing.T) {
			inner := session.NewMemoryStore()
			_ = inner.Set("api", &session.Session{Cookies: albCookies("v")})
			// A store that refuses writes proves no write was attempted.
			store := &writeFailingStore{Store: inner, err: errors.New("written")}
			m := NewManager(ManagerOptions{Store: store, Log: &capturingLogger{},
				Now: func() time.Time { return now }, LockDir: t.TempDir()})
			hold(t, m)
			m.Remember(loginDomain(), "api.example.com", nil)
			m.Touch(loginDomain())
			for _, l := range m.log.(*capturingLogger).lines {
				if strings.Contains(l, "could not") {
					t.Fatalf("a write was attempted: %q", l)
				}
			}
		})
	}
}

// An unusable lock directory must not break albauth: it falls back to the
// in-process lock, says so, and carries on.
func TestAnUnusableLockDirectoryFallsBackToTheProcessLock(t *testing.T) {
	blocker := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(blocker, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	store := session.NewMemoryStore()
	log := &capturingLogger{}
	m := NewManager(ManagerOptions{Store: store, Log: log, Now: func() time.Time { return now },
		LockDir: filepath.Join(blocker, "locks"),
		Loginer: LoginerFunc(func(context.Context, *config.Domain, string) ([]session.Cookie, error) {
			return albCookies("fresh"), nil
		})})
	if _, err := m.Ensure(t.Context(), loginDomain()); err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	if !slices.ContainsFunc(log.lines, func(l string) bool { return strings.Contains(l, "cannot take the shared lock") }) {
		t.Fatalf("no fallback warning in %q", log.lines)
	}
	m.Touch(loginDomain())
	if s, _ := store.Get("api"); !s.LastUsedAt.Equal(now) {
		t.Fatalf("Touch did not write under the fallback: %+v", s)
	}
}

func TestBackgroundUpdatesWriteWhenTheDomainIsFree(t *testing.T) {
	a, _, store := twoProcesses(t, nil)
	_ = store.Set("api", &session.Session{Cookies: albCookies("v")})
	a.Touch(loginDomain())
	if s, _ := store.Get("api"); !s.LastUsedAt.Equal(now) {
		t.Fatalf("last_used_at = %v, want it written under the shared lock", s.LastUsedAt)
	}
	// The lock was released: another process can take it straight away.
	l, ok, err := flock.TryLock(filepath.Join(a.lockDir, "api.lock"))
	if err != nil || !ok {
		t.Fatalf("lock still held after Touch: %v, %v", ok, err)
	}
	_ = l.Unlock()
}

func TestNopLoggerDiscardsEverything(t *testing.T) {
	var l nopLogger
	l.Info("x")
	l.Debug("x")
	l.Warn("x")
	l.AddSecret("x")
}
