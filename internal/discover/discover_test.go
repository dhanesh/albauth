package discover

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"albauth/internal/config"
)

// --- the probe itself -------------------------------------------------------

func TestDetectIDPHost(t *testing.T) {
	t.Run("reads the host from the redirect", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Location", "https://login.example.net/authorize?client_id=x")
			w.WriteHeader(http.StatusFound)
		}))
		t.Cleanup(srv.Close)

		host, err := DetectIDPHost(srv.URL, "/healthz", 5*time.Second)
		if err != nil || host != "login.example.net" {
			t.Fatalf("DetectIDPHost = %q, %v", host, err)
		}
	})

	t.Run("accepts a 303 as well", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Location", "https://login.example.net/authorize")
			w.WriteHeader(http.StatusSeeOther)
		}))
		t.Cleanup(srv.Close)
		if host, err := DetectIDPHost(srv.URL, "/", 5*time.Second); err != nil || host != "login.example.net" {
			t.Fatalf("DetectIDPHost = %q, %v", host, err)
		}
	})

	t.Run("a 200 means the path is not behind the rule", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		t.Cleanup(srv.Close)
		_, err := DetectIDPHost(srv.URL, "/healthz", 5*time.Second)
		if err == nil || !strings.Contains(err.Error(), "rather than redirecting") {
			t.Fatalf("err = %v", err)
		}
	})

	t.Run("a redirect with no Location is unusable", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusFound)
		}))
		t.Cleanup(srv.Close)
		if _, err := DetectIDPHost(srv.URL, "/", 5*time.Second); err == nil {
			t.Fatal("expected a failure")
		}
	})

	t.Run("a same-host redirect is not an identity provider", func(t *testing.T) {
		var srv *httptest.Server
		srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Location", srv.URL+"/login")
			w.WriteHeader(http.StatusFound)
		}))
		t.Cleanup(srv.Close)
		_, err := DetectIDPHost(srv.URL, "/", 5*time.Second)
		if err == nil || !strings.Contains(err.Error(), "redirected to itself") {
			t.Fatalf("err = %v", err)
		}
	})

	t.Run("an unreachable host fails", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
		url := srv.URL
		srv.Close()
		if _, err := DetectIDPHost(url, "/", 2*time.Second); err == nil {
			t.Fatal("expected a connection failure")
		}
	})

	t.Run("an unbuildable request fails", func(t *testing.T) {
		if _, err := DetectIDPHost("http://exa mple.com", "/", time.Second); err == nil {
			t.Fatal("expected a request-construction failure")
		}
	})
}

func TestHostOf(t *testing.T) {
	if got := HostOf("https://api.example.com:8443/x"); got != "api.example.com:8443" {
		t.Fatalf("HostOf = %q", got)
	}
	if got := HostOf("://nonsense"); got != "" {
		t.Fatalf("HostOf on an invalid URL = %q, want empty", got)
	}
}

// A proxy doing forward auth answers 401 and keeps its login route elsewhere.
// The probe has to follow that lead, because the three settings it produces are
// ones nobody guesses on a first run.
func TestProbeDomainFollowsAForwardAuthProxy(t *testing.T) {
	idp := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer idp.Close()

	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth2/start" {
			http.Redirect(w, r, idp.URL+"/auth?client_id=x", http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	found, err := Probe(DetectIDPHost, srv.URL, "/", 5*time.Second)
	if err != nil {
		t.Fatalf("Probe(DetectIDPHost, ) = %v", err)
	}
	if !found.Saw401 {
		t.Error("saw401 = false; the probe path answered 401")
	}
	if found.LoginPath != "/oauth2/start" {
		t.Errorf("loginPath = %q, want /oauth2/start", found.LoginPath)
	}
	if found.CookiePrefix != "_oauth2_proxy" {
		t.Errorf("cookiePrefix = %q; without it albauth waits for a cookie that never arrives", found.CookiePrefix)
	}
	if found.IDPHost == "" {
		t.Error("idpHost is empty; the redirect from the start path names the provider")
	}
}

func TestProbeDomainReportsA401ItCannotFollow(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	found, err := Probe(DetectIDPHost, srv.URL, "/", 5*time.Second)
	if err == nil {
		t.Fatal("Probe(DetectIDPHost, ) succeeded with no login route to find")
	}
	if !found.Saw401 {
		t.Error("saw401 = false; the 401 is still worth reporting")
	}
	if found.LoginPath != "" || found.IDPHost != "" {
		t.Errorf("invented a login route: %+v", found)
	}
	if got := (UnauthorizedError{Target: "u"}).Error(); !strings.Contains(got, "401") {
		t.Errorf("Error() = %q, want it to mention the 401", got)
	}
}

func TestProbeDomainPassesThroughOtherFailures(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	found, err := Probe(DetectIDPHost, srv.URL, "/", 5*time.Second)
	if err == nil {
		t.Fatal("Probe(DetectIDPHost, ) succeeded against a 500")
	}
	if found.Saw401 {
		t.Error("saw401 = true for a 500")
	}
}

func TestProbeReturnsARedirectingProxyAtOnce(t *testing.T) {
	calls := 0
	detect := func(string, string, time.Duration) (string, error) {
		calls++
		return "login.example.net", nil
	}
	found, err := Probe(detect, "https://api.example.com", "/", time.Second)
	if err != nil || found.IDPHost != "login.example.net" || found.Saw401 || calls != 1 {
		t.Fatalf("Probe() = %+v, %v after %d calls", found, err, calls)
	}
	if !found.LoginWall() {
		t.Error("a redirect to an identity provider is a login wall")
	}
	if (Findings{Saw401: true}).LoginWall() {
		t.Error("a bare 401 with no login route is not a login wall")
	}
}

func TestApplyToFillsOnlyWhatIsMissing(t *testing.T) {
	forwardAuth := Findings{IDPHost: "login.example.net", LoginPath: "/oauth2/start",
		CookiePrefix: "_oauth2_proxy", SessionCheck: "/oauth2/auth", Saw401: true}

	var d config.Domain
	if got := forwardAuth.ApplyTo(&d); got != (Applied{true, true, true, true, true}) {
		t.Errorf("Applied = %+v", got)
	}
	if d.IDPHostnames[0] != "login.example.net" || d.LoginProbePath != "/oauth2/start" || !d.Treat401AsExpired ||
		d.CookieNamePrefix != "_oauth2_proxy" || d.SessionCheckPath != "/oauth2/auth" {
		t.Errorf("domain = %+v", d)
	}

	explicit := config.Domain{IDPHostnames: []string{"mine"}, Treat401AsExpired: true,
		CookieNamePrefix: "own", SessionCheckPath: "/own"}
	if got := forwardAuth.ApplyTo(&explicit); got != (Applied{LoginPath: true}) {
		t.Errorf("Applied over explicit settings = %+v", got)
	}
	if explicit.IDPHostnames[0] != "mine" || explicit.CookieNamePrefix != "own" || explicit.SessionCheckPath != "/own" {
		t.Errorf("explicit settings overwritten: %+v", explicit)
	}

	given := config.Domain{LoginProbePath: "/start-here"}
	if got := forwardAuth.ApplyTo(&given); got.LoginPath || given.Treat401AsExpired {
		t.Errorf("a given login path must keep the forward-auth settings off: %+v %+v", got, given)
	}
	if got := (Findings{}).ApplyTo(&config.Domain{}); got != (Applied{}) {
		t.Errorf("nothing found, yet Applied = %+v", got)
	}
}
