package auth

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"albauth/internal/config"
	"albauth/internal/session"
)

var now = time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)

func loginDomain() *config.Domain {
	return &config.Domain{
		Name:                "api",
		BaseURL:             "https://api.example.com",
		CookieNamePrefix:    "AWSELBAuthSessionCookie",
		LoginProbePath:      "/healthz",
		LoginTimeoutSeconds: 180,
	}
}

func albCookies(value string) []session.Cookie {
	return []session.Cookie{
		{Name: "AWSELBAuthSessionCookie-0", Value: value + "-0", Expires: now.Add(time.Hour)},
		{Name: "AWSELBAuthSessionCookie-1", Value: value + "-1", Expires: now.Add(time.Hour)},
	}
}

// countingLoginer records how many browser logins were actually performed.
type countingLoginer struct {
	calls      atomic.Int32
	cookies    []session.Cookie
	err        error
	delay      time.Duration
	profileDir atomic.Value
}

func (c *countingLoginer) Login(ctx context.Context, d *config.Domain, profileDir string) ([]session.Cookie, error) {
	c.calls.Add(1)
	c.profileDir.Store(profileDir)
	if c.delay > 0 {
		select {
		case <-time.After(c.delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if c.err != nil {
		return nil, c.err
	}
	return c.cookies, nil
}

// capturingLogger records every secret registered with it.
type capturingLogger struct {
	mu      sync.Mutex
	secrets []string
	lines   []string
}

func (l *capturingLogger) Info(format string, args ...any)  { l.record(format) }
func (l *capturingLogger) Debug(format string, args ...any) { l.record(format) }
func (l *capturingLogger) Warn(format string, args ...any)  { l.record(format) }
func (l *capturingLogger) AddSecret(secret string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.secrets = append(l.secrets, secret)
}
func (l *capturingLogger) record(line string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lines = append(l.lines, line)
}

func newManager(t *testing.T, loginer Loginer, store session.Store) (*Manager, *capturingLogger) {
	t.Helper()
	log := &capturingLogger{}
	if store == nil {
		store = session.NewMemoryStore()
	}
	return NewManager(ManagerOptions{
		Store:      store,
		Loginer:    loginer,
		Log:        log,
		Now:        func() time.Time { return now },
		ProfileDir: func(name string) (string, error) { return "/state/browser/" + name, nil },
	}), log
}

func TestNewManagerFillsInOptionalHooks(t *testing.T) {
	m := NewManager(ManagerOptions{Store: session.NewMemoryStore()})
	if m.now == nil || m.log == nil || m.profileDir == nil {
		t.Fatal("NewManager should default its optional hooks")
	}
	dir, err := m.profileDir("api")
	if dir != "" || err != nil {
		t.Fatalf("default profileDir = %q, %v", dir, err)
	}
	// The default logger must accept every call without doing anything.
	m.log.Info("x")
	m.log.Debug("x")
	m.log.Warn("x")
	m.log.AddSecret("x")
	if m.now().IsZero() {
		t.Fatal("default now() should return a real time")
	}
}

func TestEnsureLogsInWhenThereIsNoSession(t *testing.T) {
	loginer := &countingLoginer{cookies: albCookies("v1")}
	m, log := newManager(t, loginer, nil)

	s, err := m.Ensure(t.Context(), loginDomain())
	if err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	if len(s.Cookies) != 2 {
		t.Fatalf("got %d cookies, want both chunks", len(s.Cookies))
	}
	if !s.AcquiredAt.Equal(now) || !s.LastUsedAt.Equal(now) {
		t.Fatalf("timestamps = %v, %v", s.AcquiredAt, s.LastUsedAt)
	}
	if got := loginer.profileDir.Load(); got != "/state/browser/api" {
		t.Fatalf("profile dir = %v", got)
	}
	// Every captured cookie value is registered so no log line can print one.
	if len(log.secrets) != 2 {
		t.Fatalf("registered %d secrets, want 2", len(log.secrets))
	}
	if s.ExpiresAt().IsZero() {
		t.Fatal("expiry should be carried through from the browser cookies")
	}
}

func TestEnsureReusesAValidSession(t *testing.T) {
	loginer := &countingLoginer{cookies: albCookies("v1")}
	m, _ := newManager(t, loginer, nil)

	for i := range 3 {
		if _, err := m.Ensure(t.Context(), loginDomain()); err != nil {
			t.Fatalf("Ensure #%d: %v", i, err)
		}
	}
	if got := loginer.calls.Load(); got != 1 {
		t.Fatalf("performed %d logins, want 1 — a valid session must be reused", got)
	}
}

func TestEnsureLogsInAgainWhenTheSessionHasExpired(t *testing.T) {
	store := session.NewMemoryStore()
	if err := store.Set("api", &session.Session{
		Cookies: []session.Cookie{{Name: "AWSELBAuthSessionCookie-0", Value: "old", Expires: now.Add(-time.Hour)}},
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	loginer := &countingLoginer{cookies: albCookies("fresh")}
	m, _ := newManager(t, loginer, store)

	s, err := m.Ensure(t.Context(), loginDomain())
	if err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	if s.Cookies[0].Value != "fresh-0" {
		t.Fatalf("expired session was not replaced: %v", s.Cookies[0].Value)
	}
	if got := loginer.calls.Load(); got != 1 {
		t.Fatalf("performed %d logins, want 1", got)
	}
}

// A burst of callers hitting an expired session must produce exactly one
// browser window, not one per caller.
func TestConcurrentRefreshesTriggerASingleLogin(t *testing.T) {
	loginer := &countingLoginer{cookies: albCookies("fresh"), delay: 30 * time.Millisecond}
	m, _ := newManager(t, loginer, nil)
	stale := &session.Session{
		Cookies: []session.Cookie{{Name: "AWSELBAuthSessionCookie-0", Value: "stale", Expires: now.Add(-time.Hour)}},
	}

	const callers = 12
	var wg sync.WaitGroup
	results := make([]*session.Session, callers)
	errs := make([]error, callers)
	for n := range callers {
		wg.Go(func() {
			results[n], errs[n] = m.Refresh(t.Context(), loginDomain(), stale)
		})
	}
	wg.Wait()

	if got := loginer.calls.Load(); got != 1 {
		t.Fatalf("performed %d logins for %d concurrent callers, want exactly 1", got, callers)
	}
	for i := range results {
		if errs[i] != nil {
			t.Fatalf("caller %d: %v", i, errs[i])
		}
		if results[i].Cookies[0].Value != "fresh-0" {
			t.Fatalf("caller %d got %q, want the freshly acquired session", i, results[i].Cookies[0].Value)
		}
	}
}

func TestRefreshLogsInWhenTheStoredSessionIsTheStaleOne(t *testing.T) {
	stale := &session.Session{Cookies: albCookies("stale")}
	store := session.NewMemoryStore()
	if err := store.Set("api", stale); err != nil {
		t.Fatalf("seed: %v", err)
	}
	loginer := &countingLoginer{cookies: albCookies("fresh")}
	m, _ := newManager(t, loginer, store)

	s, err := m.Refresh(t.Context(), loginDomain(), stale)
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if s.Cookies[0].Value != "fresh-0" || loginer.calls.Load() != 1 {
		t.Fatalf("Refresh did not re-authenticate: %v, %d calls", s.Cookies[0].Value, loginer.calls.Load())
	}
}

func TestForceLoginDiscardsTheStoredSession(t *testing.T) {
	store := session.NewMemoryStore()
	if err := store.Set("api", &session.Session{Cookies: albCookies("old")}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	loginer := &countingLoginer{cookies: albCookies("new")}
	m, _ := newManager(t, loginer, store)

	s, err := m.ForceLogin(t.Context(), loginDomain())
	if err != nil {
		t.Fatalf("ForceLogin: %v", err)
	}
	if s.Cookies[0].Value != "new-0" {
		t.Fatalf("ForceLogin returned %q", s.Cookies[0].Value)
	}
	if loginer.calls.Load() != 1 {
		t.Fatalf("performed %d logins, want 1", loginer.calls.Load())
	}
}

func TestLoginFailures(t *testing.T) {
	t.Run("no loginer configured", func(t *testing.T) {
		m, _ := newManager(t, nil, nil)
		_, err := m.Ensure(t.Context(), loginDomain())
		assertCode(t, err, CodeNoBrowser)
		if !strings.Contains(err.Error(), "albauth auth import api") {
			t.Fatalf("the hint should name the fallback command, got: %v", err)
		}
	})

	t.Run("the flow completes but no session cookie appears", func(t *testing.T) {
		loginer := &countingLoginer{cookies: []session.Cookie{{Name: "unrelated", Value: "x"}}}
		m, _ := newManager(t, loginer, nil)
		_, err := m.Ensure(t.Context(), loginDomain())
		assertCode(t, err, CodeLoginFailed)
	})

	t.Run("the browser flow times out", func(t *testing.T) {
		loginer := &countingLoginer{err: context.DeadlineExceeded}
		m, _ := newManager(t, loginer, nil)
		_, err := m.Ensure(t.Context(), loginDomain())
		assertCode(t, err, CodeLoginTimeout)
		if !strings.Contains(err.Error(), "login_timeout_seconds") {
			t.Fatalf("the hint should name the config key, got: %v", err)
		}
	})

	t.Run("the loginer fails for some other reason", func(t *testing.T) {
		loginer := &countingLoginer{err: errors.New("chrome crashed")}
		m, _ := newManager(t, loginer, nil)
		_, err := m.Ensure(t.Context(), loginDomain())
		assertCode(t, err, CodeLoginFailed)
	})

	t.Run("the loginer returns an already-coded error", func(t *testing.T) {
		loginer := &countingLoginer{err: Errorf(CodeNoBrowser, "install Chrome", "no browser")}
		m, _ := newManager(t, loginer, nil)
		_, err := m.Ensure(t.Context(), loginDomain())
		assertCode(t, err, CodeNoBrowser)
	})

	t.Run("the profile directory cannot be resolved", func(t *testing.T) {
		m := NewManager(ManagerOptions{
			Store:      session.NewMemoryStore(),
			Loginer:    &countingLoginer{cookies: albCookies("v")},
			Now:        func() time.Time { return now },
			ProfileDir: func(string) (string, error) { return "", errors.New("no HOME") },
		})
		_, err := m.Ensure(t.Context(), loginDomain())
		assertCode(t, err, CodeLoginFailed)
	})

	t.Run("the session cannot be persisted", func(t *testing.T) {
		store := session.NewMemoryStore()
		store.FailSet = errors.New("disk full")
		m, _ := newManager(t, &countingLoginer{cookies: albCookies("v")}, store)
		_, err := m.Ensure(t.Context(), loginDomain())
		assertCode(t, err, CodeStorageUnavailable)
	})
}

func TestCurrentReportsStorageProblems(t *testing.T) {
	t.Run("a missing session is not an error", func(t *testing.T) {
		m, _ := newManager(t, nil, nil)
		s, err := m.Current("api")
		if s != nil || err != nil {
			t.Fatalf("Current = %v, %v; want nil, nil", s, err)
		}
	})
	t.Run("an insecure session file is surfaced", func(t *testing.T) {
		m, _ := newManager(t, nil, &failingStore{err: session.ErrInsecureFile})
		_, err := m.Current("api")
		assertCode(t, err, CodeStorageInsecure)
	})
	t.Run("a missing keychain is surfaced", func(t *testing.T) {
		m, _ := newManager(t, nil, &failingStore{err: session.ErrKeyringUnavailable})
		_, err := m.Current("api")
		assertCode(t, err, CodeStorageUnavailable)
	})
	t.Run("an already-coded storage error passes through", func(t *testing.T) {
		coded := Errorf(CodeStorageInsecure, "chmod 600", "bad mode")
		m, _ := newManager(t, nil, &failingStore{err: coded})
		_, err := m.Current("api")
		assertCode(t, err, CodeStorageInsecure)
	})
}

func TestEnsurePropagatesAStorageFailure(t *testing.T) {
	m, _ := newManager(t, &countingLoginer{cookies: albCookies("v")}, &failingStore{err: session.ErrInsecureFile})
	_, err := m.Ensure(t.Context(), loginDomain())
	assertCode(t, err, CodeStorageInsecure)
}

func TestLogout(t *testing.T) {
	store := session.NewMemoryStore()
	if err := store.Set("api", &session.Session{Cookies: albCookies("v")}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	m, _ := newManager(t, nil, store)
	if err := m.Logout("api"); err != nil {
		t.Fatalf("Logout: %v", err)
	}
	if s, _ := m.Current("api"); s != nil {
		t.Fatal("Logout did not remove the session")
	}

	failing, _ := newManager(t, nil, &failingStore{err: errors.New("read-only")})
	assertCode(t, failing.Logout("api"), CodeStorageUnavailable)
}

func TestForceLoginReportsADeleteFailure(t *testing.T) {
	m, _ := newManager(t, &countingLoginer{cookies: albCookies("v")}, &failingStore{err: errors.New("read-only")})
	_, err := m.ForceLogin(t.Context(), loginDomain())
	assertCode(t, err, CodeStorageUnavailable)
}

func TestSave(t *testing.T) {
	m, log := newManager(t, nil, nil)
	s := &session.Session{Cookies: albCookies("imported"), AcquiredAt: now}
	if err := m.Save("api", s); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := m.Current("api")
	if err != nil || got == nil || got.Cookies[0].Value != "imported-0" {
		t.Fatalf("Current after Save = %v, %v", got, err)
	}
	if len(log.secrets) == 0 {
		t.Fatal("Save should register the imported cookie values as secrets")
	}

	failing, _ := newManager(t, nil, &failingStore{err: errors.New("read-only")})
	assertCode(t, failing.Save("api", s), CodeStorageUnavailable)
}

func TestStoreAccessor(t *testing.T) {
	store := session.NewMemoryStore()
	m, _ := newManager(t, nil, store)
	if m.Store() != store {
		t.Fatal("Store() should expose the underlying store")
	}
}

func TestSameSession(t *testing.T) {
	a := &session.Session{Cookies: albCookies("v")}
	tests := []struct {
		name string
		x, y *session.Session
		want bool
	}{
		{"both nil", nil, nil, true},
		{"one nil", a, nil, false},
		{"other nil", nil, a, false},
		{"identical", a, &session.Session{Cookies: albCookies("v")}, true},
		{"different values", a, &session.Session{Cookies: albCookies("w")}, false},
		{"different lengths", a, &session.Session{Cookies: albCookies("v")[:1]}, false},
		{"different names", a, &session.Session{Cookies: []session.Cookie{
			{Name: "other-0", Value: "v-0"}, {Name: "AWSELBAuthSessionCookie-1", Value: "v-1"},
		}}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := sameSession(tc.x, tc.y); got != tc.want {
				t.Fatalf("sameSession = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestFormatExpiry(t *testing.T) {
	if got := formatExpiry(time.Time{}); got != "unknown" {
		t.Fatalf("formatExpiry(zero) = %q", got)
	}
	if got := formatExpiry(now); got != "2026-08-26T12:00:00Z" {
		t.Fatalf("formatExpiry = %q", got)
	}
}

func TestLoginerFunc(t *testing.T) {
	called := false
	var f Loginer = LoginerFunc(func(ctx context.Context, d *config.Domain, dir string) ([]session.Cookie, error) {
		called = true
		return albCookies("v"), nil
	})
	if _, err := f.Login(t.Context(), loginDomain(), "/dir"); err != nil || !called {
		t.Fatalf("LoginerFunc did not delegate: %v, %v", err, called)
	}
}

// failingStore returns the same error from every operation.
type failingStore struct{ err error }

func (f *failingStore) Get(string) (*session.Session, error) { return nil, f.err }
func (f *failingStore) Set(string, *session.Session) error   { return f.err }
func (f *failingStore) Delete(string) error                  { return f.err }
func (f *failingStore) Backend() string                      { return "failing" }

func assertCode(t *testing.T, err error, want string) {
	t.Helper()
	coded, ok := errors.AsType[*Error](err)
	if !ok {
		t.Fatalf("error %v is not a coded *auth.Error", err)
	}
	if coded.Code != want {
		t.Fatalf("error code = %q, want %q (%v)", coded.Code, want, err)
	}
}
