package auth

import (
	"errors"
	"net/http"
	"time"

	"albauth/internal/config"
	"albauth/internal/session"
)

// Remember keeps the session cookies a login proxy reissued on a response.
//
// Proxies refresh their session in place — oauth2-proxy with --cookie-refresh,
// an ALB re-issuing its chunks — by setting a new value under the same name on
// an ordinary response. Unless that value reaches the store, albauth keeps
// sending the old one until the proxy stops accepting it.
//
// set is the response's Set-Cookie entries and host the request's host, used
// as the domain of a cookie that names none. Only cookies in the domain's
// session family are considered. The merge runs against the session stored
// now, under the per-domain lock, so a concurrent login or update is not
// overwritten with an older copy. A response that changes nothing writes
// nothing, and with no stored session there is nothing to refresh.
//
// A storage failure is logged rather than returned: the request it came from
// has already reached the application, and failing it would invite the caller
// to send a write twice. The old session stays in place and works as long as
// the proxy still accepts it.
func (m *Manager) Remember(d *config.Domain, host string, set []*http.Cookie) {
	release, ok := m.tryAcquire(d.Name)
	if !ok {
		// A login or another update holds the domain; its session wins.
		m.log.Debug("domain %s: the session is busy elsewhere, so a refreshed cookie was not kept", d.Name)
		return
	}
	defer release()

	current, err := m.store.Get(d.Name)
	if errors.Is(err, session.ErrNotFound) {
		return
	}
	if err != nil {
		m.log.Warn("domain %s: the proxy refreshed its session cookie but the stored session could not be read: %v",
			d.Name, storageError(err))
		return
	}
	updated, changed := ApplySetCookies(current, set, d.CookieNamePrefix, host, m.now())
	if !changed {
		return
	}
	// Before anything else can print a value: the store's own warnings, or a
	// later log line assembled from the session.
	m.registerSecrets(updated)

	if len(updated.Cookies) == 0 {
		err = m.store.Delete(d.Name)
	} else {
		err = m.store.Set(d.Name, updated)
	}
	if err != nil {
		m.log.Warn("domain %s: the proxy refreshed its session cookie but it could not be stored: %v",
			d.Name, storageError(err))
		return
	}
	m.log.Debug("domain %s: kept the session cookie the proxy refreshed (%d cookie(s) stored)",
		d.Name, len(updated.Cookies))
}

// ApplySetCookies merges a response's Set-Cookie entries into a session and
// reports whether anything changed. s itself is left untouched.
//
// Only cookies in the session family (prefix) count. A cookie of a stored name
// replaces it in place — value, expiry, path, flags, and domain when the
// response names one. A new name, such as an extra chunk of a session that
// grew, is appended. A cookie the response deletes — Max-Age=0 or an expiry
// already past — is dropped.
func ApplySetCookies(s *session.Session, set []*http.Cookie, prefix, host string, now time.Time) (*session.Session, bool) {
	out := *s
	out.Cookies = append([]session.Cookie(nil), s.Cookies...)
	changed := false
	for _, c := range set {
		if !session.InFamily(c.Name, prefix) {
			continue
		}
		i := indexOf(out.Cookies, c.Name)
		if deletes(c, now) {
			if i >= 0 {
				out.Cookies = append(out.Cookies[:i], out.Cookies[i+1:]...)
				changed = true
			}
			continue
		}
		next := session.Cookie{
			Name: c.Name, Value: c.Value, Domain: c.Domain, Path: c.Path,
			Expires: expiry(c, now), Secure: c.Secure, HTTPOnly: c.HttpOnly,
		}
		if i < 0 {
			if next.Domain == "" {
				next.Domain = host
			}
			if next.Path == "" {
				next.Path = "/"
			}
			out.Cookies = append(out.Cookies, next)
			changed = true
			continue
		}
		old := out.Cookies[i]
		if next.Domain == "" {
			next.Domain = old.Domain
		}
		if next.Path == "" {
			next.Path = old.Path
		}
		if !sameCookie(old, next) {
			out.Cookies[i] = next
			changed = true
		}
	}
	return &out, changed
}

// deletes reports whether a Set-Cookie entry removes the cookie. Go parses
// Max-Age=0 (and any negative Max-Age) as -1; 0 means no Max-Age was given.
func deletes(c *http.Cookie, now time.Time) bool {
	return c.MaxAge < 0 || (c.MaxAge == 0 && !c.Expires.IsZero() && !c.Expires.After(now))
}

// expiry is when a Set-Cookie entry lapses. Max-Age wins over Expires, as in a
// browser; neither means a cookie that lives as long as the session.
func expiry(c *http.Cookie, now time.Time) time.Time {
	if c.MaxAge > 0 {
		return now.Add(time.Duration(c.MaxAge) * time.Second)
	}
	return c.Expires
}

func indexOf(cookies []session.Cookie, name string) int {
	for i := range cookies {
		if cookies[i].Name == name {
			return i
		}
	}
	return -1
}

func sameCookie(a, b session.Cookie) bool {
	return a.Name == b.Name && a.Value == b.Value && a.Domain == b.Domain && a.Path == b.Path &&
		a.Expires.Equal(b.Expires) && a.Secure == b.Secure && a.HTTPOnly == b.HTTPOnly
}

// TouchInterval is the least time between two writes of a domain's
// last_used_at. Writing it on every request would put a keychain write on
// every request, so the stored value is accurate to within this interval.
const TouchInterval = 5 * time.Minute

// Touch records that a domain's session was just accepted, as the stored
// session's last_used_at. It writes at most once per TouchInterval per domain
// in this process. Like Remember, it logs a storage failure rather than
// returning it: the request has already succeeded.
func (m *Manager) Touch(d *config.Domain) {
	now := m.now()
	m.mu.Lock()
	last, seen := m.touched[d.Name]
	if seen && now.Sub(last) < TouchInterval {
		m.mu.Unlock()
		return
	}
	m.touched[d.Name] = now
	m.mu.Unlock()

	release, ok := m.tryAcquire(d.Name)
	if !ok {
		return
	}
	defer release()

	current, err := m.store.Get(d.Name)
	if err != nil {
		// No session (a logout raced the request) or an unreadable store:
		// there is nothing to stamp, and a store problem surfaces elsewhere.
		return
	}
	updated := *current
	updated.LastUsedAt = now
	if err := m.store.Set(d.Name, &updated); err != nil {
		m.log.Warn("domain %s: could not record when the session was last used: %v", d.Name, storageError(err))
	}
}
