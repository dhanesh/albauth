package auth

import (
	"context"
	"path/filepath"
	"time"

	"albauth/internal/config"
	"albauth/internal/flock"
)

// storeWait bounds how long a logout or an import waits for another albauth
// process to finish with the same domain. loginSlack is how much longer than
// its own login timeout a login waits for another process's login, which gives
// up after that same timeout. Both are variables for the tests.
var (
	storeWait  = 2 * time.Minute
	loginSlack = 30 * time.Second
)

// acquire takes a domain's lock: the in-process mutex, then, when the manager
// has a lock directory, the lock file every albauth process on the machine
// shares. It waits until ctx is done.
//
// The shared lock is what stops two processes (two MCP clients, or the CLI
// beside a server) each opening a browser for the same expired session: the
// second waits, then finds the first one's session in the store. If the lock
// file cannot be used at all (an unwritable state directory), the caller
// carries on under the in-process mutex alone and a warning says so; that is
// how albauth behaved before the shared lock existed.
func (m *Manager) acquire(ctx context.Context, domainName string) (release func(), err error) {
	mu := m.lockFor(domainName)
	mu.Lock()
	if m.lockDir == "" {
		return mu.Unlock, nil
	}
	path := m.lockPath(domainName)
	l, ok, err := flock.TryLock(path)
	if err == nil && !ok {
		m.log.Info("domain %s: another albauth process is using this domain's session; waiting for it", domainName)
		l, err = flock.Acquire(ctx, path)
	}
	if err != nil {
		if ctx.Err() != nil {
			mu.Unlock()
			return nil, err
		}
		m.log.Warn("domain %s: cannot take the shared lock, so another albauth process could log in at the same time: %v",
			domainName, err)
		return mu.Unlock, nil
	}
	return func() { _ = l.Unlock(); mu.Unlock() }, nil
}

// tryAcquire takes a domain's lock only if no other holder, in this process
// or another, has it. Background updates (a refreshed cookie, last_used_at) use
// it: one that finds the domain busy is skipped rather than made to wait for
// another process's browser window, and the session that process is about to
// store is not overwritten with an older copy.
func (m *Manager) tryAcquire(domainName string) (release func(), ok bool) {
	mu := m.lockFor(domainName)
	if !mu.TryLock() {
		return nil, false
	}
	if m.lockDir == "" {
		return mu.Unlock, true
	}
	l, ok, err := flock.TryLock(m.lockPath(domainName))
	if err != nil {
		// As in acquire: an unusable lock file must not stop the update.
		return mu.Unlock, true
	}
	if !ok {
		mu.Unlock()
		return nil, false
	}
	return func() { _ = l.Unlock(); mu.Unlock() }, true
}

func (m *Manager) lockPath(domainName string) string {
	// Domain names are validated to [a-z0-9._-], so one is a safe file name.
	return filepath.Join(m.lockDir, domainName+".lock")
}

// loginWait bounds how long a login waits for another process's login of the
// same domain: that one gives up after its own login timeout.
func loginWait(ctx context.Context, d *config.Domain) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, time.Duration(d.LoginTimeoutSeconds)*time.Second+loginSlack)
}

// busyError is the error when a login gave up waiting for another process.
func busyError(d *config.Domain) error {
	return Errorf(CodeLoginTimeout,
		"another albauth process is logging in to this domain; finish or close its browser window, then retry",
		"timed out waiting for another albauth process's login to %q", d.Name)
}
