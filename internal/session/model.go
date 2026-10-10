// Package session stores and retrieves ALB session cookies.
package session

import (
	"strings"
	"time"
)

// ExpirySkew is subtracted from a cookie's expiry before comparing it to now.
//
// A cookie that expires in the next minute is treated as already expired, so
// the login runs before the request instead of after a failure.
const ExpirySkew = 60 * time.Second

// Cookie is one persisted ALB session cookie.
type Cookie struct {
	Name     string    `json:"name"`
	Value    string    `json:"value"`
	Domain   string    `json:"domain"`
	Path     string    `json:"path"`
	Expires  time.Time `json:"expires"`
	Secure   bool      `json:"secure"`
	HTTPOnly bool      `json:"http_only"`
}

// Session is the stored state for one configured domain.
//
// ALB chunks a large session across several cookies (-0, -1, -2, …), so this
// is always a list, never a single value.
type Session struct {
	Cookies    []Cookie  `json:"cookies"`
	AcquiredAt time.Time `json:"acquired_at"`
	LastUsedAt time.Time `json:"last_used_at"`
}

// File is the on-disk shape of the file backend, and the value shape stored
// under a single keyring entry.
type File struct {
	Version int                 `json:"version"`
	Domains map[string]*Session `json:"domains"`
}

// FileVersion is the current schema version of the persisted blob.
const FileVersion = 1

// ExpiresAt is the earliest expiry among the session's cookies.
//
// The session is only as good as its shortest-lived chunk: if one chunk of a
// split cookie has expired the ALB cannot reassemble the session.
func (s *Session) ExpiresAt() time.Time {
	var earliest time.Time
	for _, c := range s.Cookies {
		if c.Expires.IsZero() {
			continue
		}
		if earliest.IsZero() || c.Expires.Before(earliest) {
			earliest = c.Expires
		}
	}
	return earliest
}

// Expired reports whether the session should be treated as unusable at now,
// applying ExpirySkew. A session with no cookies is always expired; a session
// whose cookies carry no expiry is treated as still valid, and §5.2 detection
// catches it if the ALB disagrees.
func (s *Session) Expired(now time.Time) bool {
	if s == nil || len(s.Cookies) == 0 {
		return true
	}
	expiry := s.ExpiresAt()
	if expiry.IsZero() {
		return false
	}
	return !now.Before(expiry.Add(-ExpirySkew))
}

// Valid reports whether the session is present and unexpired at now.
func (s *Session) Valid(now time.Time) bool { return !s.Expired(now) }

// CookieValues returns the raw cookie values, for registering as logger
// secrets. It is the one place values leave the session deliberately.
func (s *Session) CookieValues() []string {
	if s == nil {
		return nil
	}
	values := make([]string, 0, len(s.Cookies))
	for _, c := range s.Cookies {
		values = append(values, c.Value)
	}
	return values
}

// FilterByPrefix returns the cookies whose names start with prefix.
func FilterByPrefix(cookies []Cookie, prefix string) []Cookie {
	out := make([]Cookie, 0, len(cookies))
	for _, c := range cookies {
		if strings.HasPrefix(c.Name, prefix) {
			out = append(out, c)
		}
	}
	return out
}

// InFamily reports whether a cookie name belongs to a domain's session cookie
// family: the cookies the login proxy uses for its session, as opposed to the
// application's own. An empty prefix names no family at all, so it matches
// nothing rather than everything.
func InFamily(name, prefix string) bool {
	return prefix != "" && strings.HasPrefix(name, prefix)
}
