package mcpserver

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"albauth/internal/auth"
	"albauth/internal/config"
	"albauth/internal/discover"
)

// probeTimeout bounds each request the unknown_domain probe makes, so a host
// that does not answer cannot hold up the reply to http_request for long.
const probeTimeout = 10 * time.Second

// Suggestion is what the unknown_domain error carries when the host it names
// sits behind a login albauth can handle. Its fields are add_domain's
// arguments, so an agent the user has said yes to passes them straight through.
type Suggestion struct {
	Name              string   `json:"name"`
	BaseURL           string   `json:"base_url"`
	IDPHostnames      []string `json:"idp_hostnames"`
	LoginProbePath    string   `json:"login_probe_path,omitempty"`
	CookieNamePrefix  string   `json:"cookie_name_prefix,omitempty"`
	Treat401AsExpired bool     `json:"treat_401_as_expired,omitempty"`
	SessionCheckPath  string   `json:"session_check_path,omitempty"`
	Note              string   `json:"note"`
}

// suggestedError is an unknown_domain error with a suggestion attached. It
// unwraps to the coded error, so everything that inspects the code still sees
// it; RenderError adds the suggestion to the payload.
type suggestedError struct {
	coded      *auth.Error
	Suggestion *Suggestion
}

func (e *suggestedError) Error() string { return e.coded.Error() }
func (e *suggestedError) Unwrap() error { return e.coded }

// suggestFor probes the host of an absolute URL that no domain matches and,
// when it finds a login wall, returns err with a suggestion attached. Anything
// else — another error, a relative URL, no probe configured, a host that
// answers without a login, a probe that fails — returns err unchanged: the
// probe can only add information, never turn the answer into a worse one.
//
// The probe is discover.Probe against the origin's "/": GET only, no cookies,
// none of the caller's or any domain's headers, no redirect followed.
func (d *Deps) suggestFor(err error, rawURL string) error {
	coded, ok := codedError(err)
	if !ok || coded.Code != auth.CodeUnknownDomain || d.Probe == nil {
		return err
	}
	parsed, parseErr := url.Parse(rawURL)
	if parseErr != nil || parsed.Host == "" {
		// A relative URL naming an unknown domain: there is no host to ask.
		return err
	}
	origin := strings.ToLower(parsed.Scheme) + "://" + parsed.Host
	found, probeErr := discover.Probe(d.Probe, origin, "/", probeTimeout)
	if probeErr != nil || !found.LoginWall() {
		return err
	}

	s := &Suggestion{
		Name:         proposeName(d.config(), parsed),
		BaseURL:      origin,
		IDPHostnames: []string{found.IDPHost},
		Note: "This API sits behind a login that albauth can handle, but it is not configured. " +
			"Ask the user whether to add it; only after they say yes, call add_domain with these " +
			"fields (it is added read-only), then retry the request.",
	}
	if found.LoginPath != "" {
		// A forward-auth proxy: the browser starts elsewhere, a 401 means "no
		// session", and the session cookie is not the ALB's.
		s.LoginProbePath = found.LoginPath
		s.CookieNamePrefix = found.CookiePrefix
		s.Treat401AsExpired = true
		s.SessionCheckPath = found.SessionCheck
	}
	hinted := *coded
	hinted.Hint = "this host is behind a login albauth can handle; ask the user before adding it " +
		"with add_domain (see suggestion); configured domains: " + joinNames(d.config().DomainNames())
	return &suggestedError{coded: &hinted, Suggestion: s}
}

// proposeName derives a domain name from a URL's host that passes config
// validation and is not already taken.
func proposeName(cfg *config.Config, u *url.URL) string {
	raw := strings.ToLower(u.Hostname())
	if port := u.Port(); port != "" {
		raw += "-" + port
	}
	name := strings.TrimLeft(strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '.' || r == '_' || r == '-' {
			return r
		}
		return '-'
	}, raw), "-._")
	if !config.ValidName(name) {
		name = "api"
	}
	candidate := name
	for n := 2; ; n++ {
		if _, taken := cfg.Lookup(candidate); !taken {
			return candidate
		}
		candidate = name + "-" + strconv.Itoa(n)
	}
}

// readOnlyMethods are the only methods add_domain grants. Letting the model
// write to an API is the user's decision, made outside the chat.
var readOnlyMethods = map[string]bool{http.MethodGet: true, http.MethodHead: true, http.MethodOptions: true}

// Indirected so the tests can drive the write and reload failures.
var (
	writeDomain  = config.AddDomain
	reloadConfig = config.LoadServing
)

// addDomain adds a domain to the user's config file and makes it usable in
// this server at once. The agent calls it only after the user has said yes.
func (d *Deps) addDomain(args map[string]any) (any, error) {
	name, err := stringArg(args, "name", true)
	if err != nil {
		return nil, err
	}
	baseURL, err := stringArg(args, "base_url", true)
	if err != nil {
		return nil, err
	}
	idpHostnames, err := stringListArg(args, "idp_hostnames")
	if err != nil {
		return nil, err
	}
	allowMethods, err := stringListArg(args, "allow_methods")
	if err != nil {
		return nil, err
	}
	optional := map[string]string{}
	for _, key := range []string{"login_probe_path", "cookie_name_prefix", "session_check_path"} {
		if optional[key], err = stringArg(args, key, false); err != nil {
			return nil, err
		}
	}
	treat401, err := boolArg(args, "treat_401_as_expired")
	if err != nil {
		return nil, err
	}

	// Refused before anything is read or written: granting writes is never the
	// agent's call.
	for i, m := range allowMethods {
		allowMethods[i] = strings.ToUpper(strings.TrimSpace(m))
		if !readOnlyMethods[allowMethods[i]] {
			return nil, auth.Errorf(auth.CodeMethodNotAllowed,
				fmt.Sprintf("add_domain only adds read-only domains (GET, HEAD, OPTIONS). To allow "+
					"writes, the user widens allow_methods themselves: from a terminal with `albauth config "+
					"add-domain %s --base-url <url> --allow-method GET --allow-method %s`, or by editing "+
					"allow_methods in the config file (`albauth config path` prints where) and restarting albauth", name, allowMethods[i]),
				"add_domain cannot grant method %s; nothing was written", allowMethods[i])
		}
	}

	d.addMu.Lock()
	defer d.addMu.Unlock()

	path := d.config().Path
	domain := &config.Domain{
		Name:              name,
		BaseURL:           strings.TrimRight(baseURL, "/"),
		IDPHostnames:      idpHostnames,
		AllowMethods:      allowMethods,
		LoginProbePath:    optional["login_probe_path"],
		CookieNamePrefix:  optional["cookie_name_prefix"],
		SessionCheckPath:  optional["session_check_path"],
		Treat401AsExpired: treat401,
	}
	if err := writeDomain(path, domain); err != nil {
		hint := "check the domain's fields; the config file was not changed"
		if _, invalid := errors.AsType[*config.Error](err); !invalid {
			hint = "the config file could not be written; check its directory and permissions"
		}
		return nil, auth.Wrap(err, auth.CodeConfigInvalid, hint, "could not add domain %q: %v", name, err)
	}

	reloaded, err := reloadConfig(path)
	if err != nil {
		return nil, auth.Wrap(err, auth.CodeConfigInvalid,
			"the domain was written, but the config file no longer loads; fix it and restart albauth",
			"could not reload the config after adding %q: %v", name, err)
	}
	d.mu.Lock()
	d.Config = reloaded
	d.mu.Unlock()

	// The write succeeded and the reload validated it, so the domain is there.
	added, _ := reloaded.Lookup(name)
	if d.AddCookiePrefix != nil {
		d.AddCookiePrefix(added.CookieNamePrefix)
	}
	return entryFor(added), nil
}

func stringListArg(args map[string]any, key string) ([]string, error) {
	raw, present := args[key]
	if !present || raw == nil {
		return nil, nil
	}
	list, ok := raw.([]any)
	if !ok {
		return nil, auth.Errorf(auth.CodeInvalidRequest, "", "%q must be an array of strings, got %T", key, raw)
	}
	out := make([]string, 0, len(list))
	for i, v := range list {
		s, ok := v.(string)
		if !ok {
			return nil, auth.Errorf(auth.CodeInvalidRequest, "", "%q[%d] must be a string, got %T", key, i, v)
		}
		out = append(out, s)
	}
	return out, nil
}
