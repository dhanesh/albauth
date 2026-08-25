package session

import (
	"testing"
	"time"
)

var base = time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)

func cookie(name string, expires time.Time) Cookie {
	return Cookie{Name: name, Value: "value-of-" + name, Expires: expires}
}

func TestSessionExpiresAt(t *testing.T) {
	tests := []struct {
		name string
		in   *Session
		want time.Time
	}{
		{"no cookies", &Session{}, time.Time{}},
		{"single", &Session{Cookies: []Cookie{cookie("a", base)}}, base},
		{
			// A chunked session is only as good as its shortest-lived chunk.
			name: "earliest of several wins",
			in: &Session{Cookies: []Cookie{
				cookie("a", base.Add(2*time.Hour)),
				cookie("b", base),
				cookie("c", base.Add(time.Hour)),
			}},
			want: base,
		},
		{"zero expiries ignored", &Session{Cookies: []Cookie{
			cookie("a", time.Time{}), cookie("b", base),
		}}, base},
		{"all zero", &Session{Cookies: []Cookie{cookie("a", time.Time{})}}, time.Time{}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.in.ExpiresAt(); !got.Equal(tc.want) {
				t.Fatalf("ExpiresAt() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestSessionExpiryUsesSkewBuffer(t *testing.T) {
	expiry := base.Add(time.Hour)
	s := &Session{Cookies: []Cookie{cookie("a", expiry)}}

	tests := []struct {
		name        string
		now         time.Time
		wantExpired bool
	}{
		{"well before expiry", expiry.Add(-10 * time.Minute), false},
		{"just outside the skew window", expiry.Add(-ExpirySkew - time.Second), false},
		{"exactly at the skew boundary", expiry.Add(-ExpirySkew), true},
		{"inside the skew window", expiry.Add(-30 * time.Second), true},
		{"at expiry", expiry, true},
		{"after expiry", expiry.Add(time.Second), true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := s.Expired(tc.now); got != tc.wantExpired {
				t.Fatalf("Expired(%v) = %v, want %v", tc.now, got, tc.wantExpired)
			}
			if got := s.Valid(tc.now); got == tc.wantExpired {
				t.Fatalf("Valid(%v) = %v, should be the inverse of Expired", tc.now, got)
			}
		})
	}
}

func TestSessionExpiredEdgeCases(t *testing.T) {
	var nilSession *Session
	if !nilSession.Expired(base) {
		t.Fatal("a nil session must be treated as expired")
	}
	if !(&Session{}).Expired(base) {
		t.Fatal("a session with no cookies must be treated as expired")
	}
	// No readable expiry: trust it, and let response detection catch it.
	noExpiry := &Session{Cookies: []Cookie{cookie("a", time.Time{})}}
	if noExpiry.Expired(base) {
		t.Fatal("a session with no expiry must not be treated as expired")
	}
}

func TestCookieValues(t *testing.T) {
	var nilSession *Session
	if got := nilSession.CookieValues(); got != nil {
		t.Fatalf("nil session CookieValues() = %v, want nil", got)
	}
	s := &Session{Cookies: []Cookie{cookie("a", base), cookie("b", base)}}
	got := s.CookieValues()
	if len(got) != 2 || got[0] != "value-of-a" || got[1] != "value-of-b" {
		t.Fatalf("CookieValues() = %v", got)
	}
}

func TestFilterByPrefix(t *testing.T) {
	in := []Cookie{
		cookie("AWSELBAuthSessionCookie-0", base),
		cookie("session_id", base),
		cookie("AWSELBAuthSessionCookie-1", base),
	}
	got := FilterByPrefix(in, "AWSELBAuthSessionCookie")
	if len(got) != 2 {
		t.Fatalf("FilterByPrefix returned %d cookies, want 2", len(got))
	}
	if got[0].Name != "AWSELBAuthSessionCookie-0" || got[1].Name != "AWSELBAuthSessionCookie-1" {
		t.Fatalf("FilterByPrefix returned %v", got)
	}
	if len(FilterByPrefix(in, "nomatch")) != 0 {
		t.Fatal("FilterByPrefix should return an empty slice when nothing matches")
	}
}
