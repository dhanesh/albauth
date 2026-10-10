package auth

import (
	"errors"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"albauth/internal/session"
)

const prefix = "AWSELBAuthSessionCookie"

// writeFailingStore reads from a real store but refuses every write.
type writeFailingStore struct {
	session.Store
	err error
}

func (w *writeFailingStore) Set(string, *session.Session) error { return w.err }
func (w *writeFailingStore) Delete(string) error                { return w.err }

func storedSession(t *testing.T, store session.Store) *session.Session {
	t.Helper()
	s, err := store.Get("api")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	return s
}

func TestRememberStoresAReissuedSessionCookie(t *testing.T) {
	store := session.NewMemoryStore()
	_ = store.Set("api", &session.Session{Cookies: albCookies("old"), AcquiredAt: now})
	m, log := newManager(t, nil, store)

	m.Remember(loginDomain(), "api.example.com", []*http.Cookie{
		{Name: prefix + "-0", Value: "new-0", MaxAge: 600, HttpOnly: true},
		{Name: "app_csrf", Value: "not-a-session-cookie"},
	})

	s := storedSession(t, store)
	if got := s.Cookies[0]; got.Value != "new-0" || !got.HTTPOnly || !got.Expires.Equal(now.Add(10*time.Minute)) {
		t.Fatalf("cookie -0 = %+v, want the reissued value with its new expiry", got)
	}
	if s.Cookies[1].Value != "old-1" || len(s.Cookies) != 2 {
		t.Fatalf("cookies = %+v, want -1 untouched and nothing added", s.Cookies)
	}
	if !s.AcquiredAt.Equal(now) {
		t.Fatalf("acquired_at = %v, want the login time kept", s.AcquiredAt)
	}
	if !slices.Contains(log.secrets, "new-0") {
		t.Fatalf("the new value was not registered as a secret: %v", log.secrets)
	}
	if slices.Contains(log.secrets, "not-a-session-cookie") {
		t.Fatal("an application cookie was taken into the session")
	}
}

func TestRememberLeavesTheStoreAloneWhenNothingChanges(t *testing.T) {
	t.Run("no stored session", func(t *testing.T) {
		store := session.NewMemoryStore()
		m, _ := newManager(t, nil, store)
		m.Remember(loginDomain(), "api.example.com", []*http.Cookie{{Name: prefix + "-0", Value: "v"}})
		if _, err := store.Get("api"); !errors.Is(err, session.ErrNotFound) {
			t.Fatalf("Get = %v, want nothing stored after a logout", err)
		}
	})
	t.Run("same cookie again", func(t *testing.T) {
		// A store that refuses writes proves no write was attempted.
		inner := session.NewMemoryStore()
		_ = inner.Set("api", &session.Session{Cookies: albCookies("v")})
		m, log := newManager(t, nil, &writeFailingStore{Store: inner, err: errors.New("read-only")})
		m.Remember(loginDomain(), "api.example.com", []*http.Cookie{
			{Name: prefix + "-0", Value: "v-0", Expires: now.Add(time.Hour)},
			{Name: prefix + "-7", MaxAge: -1},
		})
		if len(log.lines) != 0 {
			t.Fatalf("logged %v for a response that changed nothing", log.lines)
		}
	})
}

func TestRememberDeletesTheSessionWhenEveryCookieIsCleared(t *testing.T) {
	store := session.NewMemoryStore()
	_ = store.Set("api", &session.Session{Cookies: albCookies("v")})
	m, _ := newManager(t, nil, store)
	m.Remember(loginDomain(), "api.example.com", []*http.Cookie{
		{Name: prefix + "-0", MaxAge: -1},
		{Name: prefix + "-1", Expires: now.Add(-time.Hour)},
	})
	if _, err := store.Get("api"); !errors.Is(err, session.ErrNotFound) {
		t.Fatalf("Get = %v, want the emptied session deleted", err)
	}
}

func TestRememberWarnsOnAStorageFailure(t *testing.T) {
	readOnly := errors.New("read-only")
	cases := map[string]struct {
		store session.Store
		set   *http.Cookie
	}{
		"read":   {&failingStore{err: session.ErrInsecureFile}, &http.Cookie{Name: prefix + "-0", Value: "new"}},
		"set":    {&writeFailingStore{Store: memoryWith(albCookies("v")), err: readOnly}, &http.Cookie{Name: prefix + "-0", Value: "new"}},
		"delete": {&writeFailingStore{Store: memoryWith(albCookies("v")[:1]), err: readOnly}, &http.Cookie{Name: prefix + "-0", MaxAge: -1}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			m, log := newManager(t, nil, tc.store)
			m.Remember(loginDomain(), "api.example.com", []*http.Cookie{tc.set})
			if len(log.lines) != 1 || !strings.Contains(log.lines[0], "refreshed its session cookie") {
				t.Fatalf("log = %v, want one warning", log.lines)
			}
		})
	}
}

func memoryWith(cookies []session.Cookie) session.Store {
	s := session.NewMemoryStore()
	_ = s.Set("api", &session.Session{Cookies: cookies})
	return s
}

func TestApplySetCookies(t *testing.T) {
	base := &session.Session{Cookies: []session.Cookie{
		{Name: prefix + "-0", Value: "a", Domain: "api.example.com", Path: "/api", Expires: now.Add(time.Hour)},
	}}

	t.Run("a new chunk takes the request host and the root path", func(t *testing.T) {
		got, changed := ApplySetCookies(base, []*http.Cookie{
			{Name: prefix + "-1", Value: "b", Secure: true, Expires: now.Add(2 * time.Hour)},
		}, prefix, "api.example.com", now)
		want := session.Cookie{Name: prefix + "-1", Value: "b", Domain: "api.example.com", Path: "/",
			Expires: now.Add(2 * time.Hour), Secure: true}
		if !changed || len(got.Cookies) != 2 || !sameCookie(got.Cookies[1], want) {
			t.Fatalf("cookies = %+v (changed %v), want %+v appended", got.Cookies, changed, want)
		}
		if len(base.Cookies) != 1 {
			t.Fatal("the input session was modified")
		}
	})
	t.Run("a replacement keeps the stored domain and path unless it names its own", func(t *testing.T) {
		got, _ := ApplySetCookies(base, []*http.Cookie{{Name: prefix + "-0", Value: "a2"}}, prefix, "other", now)
		if c := got.Cookies[0]; c.Domain != "api.example.com" || c.Path != "/api" || !c.Expires.IsZero() {
			t.Fatalf("cookie = %+v, want stored domain and path kept and no expiry", c)
		}
		got, _ = ApplySetCookies(base, []*http.Cookie{
			{Name: prefix + "-0", Value: "a2", Domain: "example.com", Path: "/"}}, prefix, "other", now)
		if c := got.Cookies[0]; c.Domain != "example.com" || c.Path != "/" {
			t.Fatalf("cookie = %+v, want the response's domain and path", c)
		}
	})
	t.Run("an empty prefix names no session family", func(t *testing.T) {
		if _, changed := ApplySetCookies(base, []*http.Cookie{{Name: prefix + "-0", Value: "x"}}, "", "h", now); changed {
			t.Fatal("an empty prefix matched a cookie")
		}
	})
}

func TestTouchRecordsLastUseAtMostOncePerInterval(t *testing.T) {
	store := session.NewMemoryStore()
	acquired := now.Add(-time.Hour)
	_ = store.Set("api", &session.Session{Cookies: albCookies("v"), AcquiredAt: acquired, LastUsedAt: acquired})
	m, _ := newManager(t, nil, store)
	clock := now
	m.now = func() time.Time { return clock }

	m.Touch(loginDomain())
	if s := storedSession(t, store); !s.LastUsedAt.Equal(now) || !s.AcquiredAt.Equal(acquired) {
		t.Fatalf("after the first use: last_used_at = %v, acquired_at = %v", s.LastUsedAt, s.AcquiredAt)
	}

	clock = now.Add(TouchInterval - time.Second)
	m.Touch(loginDomain())
	if s := storedSession(t, store); !s.LastUsedAt.Equal(now) {
		t.Fatalf("a use inside the interval was written: last_used_at = %v", s.LastUsedAt)
	}

	clock = now.Add(TouchInterval)
	m.Touch(loginDomain())
	if s := storedSession(t, store); !s.LastUsedAt.Equal(clock) {
		t.Fatalf("a use after the interval was not written: last_used_at = %v", s.LastUsedAt)
	}
	if got := storedSession(t, store).Cookies; len(got) != 2 || got[0].Value != "v-0" {
		t.Fatalf("Touch changed the cookies: %+v", got)
	}
}

func TestTouchWithNoSessionStoresNothing(t *testing.T) {
	store := session.NewMemoryStore()
	m, log := newManager(t, nil, store)
	m.Touch(loginDomain())
	if _, err := store.Get("api"); !errors.Is(err, session.ErrNotFound) {
		t.Fatalf("Get = %v, want nothing stored after a logout", err)
	}
	if len(log.lines) != 0 {
		t.Fatalf("logged %q", log.lines)
	}
}

func TestTouchLogsAStoreThatRefusesTheWrite(t *testing.T) {
	inner := session.NewMemoryStore()
	_ = inner.Set("api", &session.Session{Cookies: albCookies("v")})
	m, log := newManager(t, nil, &writeFailingStore{Store: inner, err: errors.New("keychain locked")})
	m.Touch(loginDomain())
	if len(log.lines) != 1 || !strings.Contains(log.lines[0], "last used") {
		t.Fatalf("log = %q", log.lines)
	}
}
