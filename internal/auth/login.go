package auth

import (
	"context"
	"errors"
	"sync"
	"time"

	"albauth/internal/config"
	"albauth/internal/session"
)

// Loginer performs one interactive login for a domain and returns the ALB
// session cookies it captured.
//
// The browser implementation lives behind this interface so the whole
// authentication flow can be tested without Chrome; the real driver is
// internal/browser.
type Loginer interface {
	Login(ctx context.Context, d *config.Domain, profileDir string) ([]session.Cookie, error)
}

// LoginerFunc adapts a function to the Loginer interface.
type LoginerFunc func(ctx context.Context, d *config.Domain, profileDir string) ([]session.Cookie, error)

// Login implements Loginer.
func (f LoginerFunc) Login(ctx context.Context, d *config.Domain, profileDir string) ([]session.Cookie, error) {
	return f(ctx, d, profileDir)
}

// Logger is the subset of the logger the manager needs.
type Logger interface {
	Info(format string, args ...any)
	Debug(format string, args ...any)
	Warn(format string, args ...any)
	AddSecret(secret string)
}

// Manager owns session acquisition and refresh for every configured domain.
type Manager struct {
	store      session.Store
	loginer    Loginer
	log        Logger
	profileDir func(domainName string) (string, error)
	now        func() time.Time

	mu    sync.Mutex
	locks map[string]*sync.Mutex
}

// ManagerOptions configures a Manager. Only Store and Loginer are required.
type ManagerOptions struct {
	Store      session.Store
	Loginer    Loginer
	Log        Logger
	ProfileDir func(domainName string) (string, error)
	Now        func() time.Time
}

// NewManager builds a Manager, filling in defaults for the optional hooks.
func NewManager(opts ManagerOptions) *Manager {
	m := &Manager{
		store:      opts.Store,
		loginer:    opts.Loginer,
		log:        opts.Log,
		profileDir: opts.ProfileDir,
		now:        opts.Now,
		locks:      map[string]*sync.Mutex{},
	}
	if m.now == nil {
		m.now = time.Now
	}
	if m.log == nil {
		m.log = nopLogger{}
	}
	if m.profileDir == nil {
		m.profileDir = func(string) (string, error) { return "", nil }
	}
	return m
}

// Store exposes the underlying store, for auth_status.
func (m *Manager) Store() session.Store { return m.store }

// lockFor returns the per-domain login mutex, creating it on first use.
//
// Serialising per domain is what stops a burst of concurrent requests hitting
// an expired session from each spawning its own browser window.
func (m *Manager) lockFor(domainName string) *sync.Mutex {
	m.mu.Lock()
	defer m.mu.Unlock()
	if l, ok := m.locks[domainName]; ok {
		return l
	}
	l := &sync.Mutex{}
	m.locks[domainName] = l
	return l
}

// Current returns the stored session for a domain, or nil if there is none.
// A storage-level failure other than "not found" is reported, because an
// insecure session file must surface rather than look like a cache miss.
func (m *Manager) Current(domainName string) (*session.Session, error) {
	s, err := m.store.Get(domainName)
	if errors.Is(err, session.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, storageError(err)
	}
	m.registerSecrets(s)
	return s, nil
}

// Ensure returns a valid session for the domain, logging in if there is no
// usable one. It is the pre-request path: an expired cookie triggers the login
// before the request rather than after a failure.
func (m *Manager) Ensure(ctx context.Context, d *config.Domain) (*session.Session, error) {
	s, err := m.Current(d.Name)
	if err != nil {
		return nil, err
	}
	if s.Valid(m.now()) {
		return s, nil
	}
	return m.login(ctx, d, s)
}

// Refresh re-authenticates after a request was judged unauthenticated.
//
// stale is the session that was just rejected. If another goroutine has already
// replaced it while this one waited for the lock, that new session is returned
// and no second browser window opens.
func (m *Manager) Refresh(ctx context.Context, d *config.Domain, stale *session.Session) (*session.Session, error) {
	return m.login(ctx, d, stale)
}

// ForceLogin discards any stored session and authenticates from scratch.
func (m *Manager) ForceLogin(ctx context.Context, d *config.Domain) (*session.Session, error) {
	lock := m.lockFor(d.Name)
	lock.Lock()
	defer lock.Unlock()
	if err := m.store.Delete(d.Name); err != nil {
		return nil, storageError(err)
	}
	return m.doLogin(ctx, d)
}

// login serialises per domain and collapses concurrent attempts.
func (m *Manager) login(ctx context.Context, d *config.Domain, stale *session.Session) (*session.Session, error) {
	lock := m.lockFor(d.Name)
	lock.Lock()
	defer lock.Unlock()

	// Another caller may have logged in while we waited. Anything newer than
	// what we were handed is good enough; take it and skip the browser.
	if current, err := m.Current(d.Name); err == nil && current.Valid(m.now()) && !sameSession(current, stale) {
		m.log.Debug("domain %s: reusing session acquired by a concurrent request", d.Name)
		return current, nil
	}
	return m.doLogin(ctx, d)
}

// doLogin runs the browser flow and persists the result. Callers hold the lock.
func (m *Manager) doLogin(ctx context.Context, d *config.Domain) (*session.Session, error) {
	if m.loginer == nil {
		return nil, Errorf(CodeNoBrowser,
			"install Chrome or Chromium, or run `albauth auth import "+d.Name+"`",
			"no browser login is available for domain %q", d.Name)
	}
	profileDir, err := m.profileDir(d.Name)
	if err != nil {
		return nil, Wrap(err, CodeLoginFailed, "check that the state directory is writable",
			"cannot determine browser profile directory for %q", d.Name)
	}

	timeout := time.Duration(d.LoginTimeoutSeconds) * time.Second
	loginCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	m.log.Info("domain %s: opening browser for interactive login (timeout %s)", d.Name, timeout)
	cookies, err := m.loginer.Login(loginCtx, d, profileDir)
	if err != nil {
		return nil, asCodedError(err, d)
	}

	cookies = session.FilterByPrefix(cookies, d.CookieNamePrefix)
	if len(cookies) == 0 {
		return nil, Errorf(CodeLoginFailed,
			"check idp_hostnames and that the ALB listener rule covers "+d.LoginProbePath,
			"login for %q completed but no %s* cookie appeared", d.Name, d.CookieNamePrefix)
	}

	now := m.now()
	s := &session.Session{Cookies: cookies, AcquiredAt: now, LastUsedAt: now}
	if err := m.store.Set(d.Name, s); err != nil {
		return nil, storageError(err)
	}
	m.registerSecrets(s)
	m.log.Info("domain %s: session acquired (%d cookie(s), expires %s)",
		d.Name, len(cookies), formatExpiry(s.ExpiresAt()))
	return s, nil
}

// Logout deletes the stored session for a domain.
func (m *Manager) Logout(domainName string) error {
	lock := m.lockFor(domainName)
	lock.Lock()
	defer lock.Unlock()
	if err := m.store.Delete(domainName); err != nil {
		return storageError(err)
	}
	return nil
}

// Save persists a session directly. `auth import` uses it for the headless path.
func (m *Manager) Save(domainName string, s *session.Session) error {
	lock := m.lockFor(domainName)
	lock.Lock()
	defer lock.Unlock()
	if err := m.store.Set(domainName, s); err != nil {
		return storageError(err)
	}
	m.registerSecrets(s)
	return nil
}

// registerSecrets teaches the logger every live cookie value so that no code
// path can print one, even by accident, from a string assembled elsewhere.
func (m *Manager) registerSecrets(s *session.Session) {
	for _, v := range s.CookieValues() {
		m.log.AddSecret(v)
	}
}

func formatExpiry(t time.Time) string {
	if t.IsZero() {
		return "unknown"
	}
	return t.UTC().Format(time.RFC3339)
}

// sameSession reports whether two sessions carry identical cookie values.
func sameSession(a, b *session.Session) bool {
	if a == nil || b == nil {
		return a == b
	}
	if len(a.Cookies) != len(b.Cookies) {
		return false
	}
	for i := range a.Cookies {
		if a.Cookies[i].Name != b.Cookies[i].Name || a.Cookies[i].Value != b.Cookies[i].Value {
			return false
		}
	}
	return true
}

// storageError maps a storage failure onto the documented error codes.
func storageError(err error) error {
	if coded, ok := errors.AsType[*Error](err); ok {
		return coded
	}
	switch {
	case errors.Is(err, session.ErrInsecureFile):
		return Wrap(err, CodeStorageInsecure, "chmod 600 the session file", "%v", err)
	case errors.Is(err, session.ErrKeyringUnavailable):
		return Wrap(err, CodeStorageUnavailable, `set storage = "file" in config`, "%v", err)
	case errors.Is(err, session.ErrSessionTooLarge):
		return Wrap(err, CodeStorageUnavailable,
			`the session is too large for the OS keychain; set storage = "auto" (keeps oversized sessions in the 0600 file) or storage = "file" in config`,
			"%v", err)
	default:
		return Wrap(err, CodeStorageUnavailable, "check the session store is readable and writable", "%v", err)
	}
}

// asCodedError maps a Loginer failure onto the documented error codes.
func asCodedError(err error, d *config.Domain) error {
	if coded, ok := errors.AsType[*Error](err); ok {
		return coded
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return Wrap(err, CodeLoginTimeout,
			"raise login_timeout_seconds for this domain",
			"browser flow for %q did not complete within %ds", d.Name, d.LoginTimeoutSeconds)
	}
	return Wrap(err, CodeLoginFailed,
		"check idp_hostnames and the ALB listener rule scope",
		"login for %q failed: %v", d.Name, err)
}

type nopLogger struct{}

func (nopLogger) Info(string, ...any)  {}
func (nopLogger) Debug(string, ...any) {}
func (nopLogger) Warn(string, ...any)  {}
func (nopLogger) AddSecret(string)     {}
