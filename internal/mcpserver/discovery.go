package mcpserver

import (
	"cmp"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"albauth/internal/auth"
	"albauth/internal/config"
	"albauth/internal/discover"
)

// probeTimeout bounds each probe request, so a host that does not answer
// cannot hold up the reply for long.
const probeTimeout = 10 * time.Second

// What the single unknown_domain probe saw, as Suggestion.Found reports it.
const (
	FoundIdentityProviderRedirect = "identity_provider_redirect"
	FoundUnauthorized401          = "answered_401"
)

// Suggestion is what the unknown_domain error carries when the host it names
// appears to sit behind a login albauth can handle. Its name, base_url and
// idp_hostnames are add_domain's arguments, so an agent the user has said yes
// to passes them straight through; add_domain works out the rest.
type Suggestion struct {
	Name         string   `json:"name"`
	BaseURL      string   `json:"base_url"`
	Found        string   `json:"found"`
	IDPHostnames []string `json:"idp_hostnames,omitempty"`
	Note         string   `json:"note"`
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

// suggestFor asks the host of an absolute URL that no domain matches whether
// it sits behind a login and, when it appears to, returns err with a
// suggestion attached. Anything else — another error, a relative URL, no probe
// configured, a host that answers without a login, a probe that fails —
// returns err unchanged: the probe can only add information, never turn the
// answer into a worse one.
//
// The user has agreed to nothing yet, so this is exactly one request: a GET of
// the origin's "/", with no cookies, none of the caller's or any domain's
// headers, and no redirect followed. A cross-host redirect names the identity
// provider. A 401 is what a forward-auth proxy such as oauth2-proxy answers;
// finding its login route takes more requests, so add_domain does that, after
// the user has said yes.
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
	cfg := d.config()
	s := &Suggestion{Name: proposeName(cfg, parsed), BaseURL: origin}

	idpHost, probeErr := d.Probe(origin, "/", probeTimeout)
	switch {
	case probeErr == nil:
		s.Found = FoundIdentityProviderRedirect
		s.IDPHostnames = []string{idpHost}
		s.Note = "This API redirects to an identity provider, so it sits behind a login albauth can " +
			"handle, but it is not configured. Ask the user whether to add it; only after they say " +
			"yes, call add_domain with name, base_url and idp_hostnames (it is added read-only), " +
			"then retry the request."
	case errors.As(probeErr, new(discover.UnauthorizedError)):
		s.Found = FoundUnauthorized401
		s.Note = "This API answered 401 the way a forward-auth login proxy (such as oauth2-proxy) " +
			"does, so it probably sits behind a login albauth can handle, but it is not configured. " +
			"It may instead be an API that wants its own credential. Ask the user whether to add " +
			"it; only after they say yes, call add_domain with name and base_url — it finds the " +
			"proxy's login route and finishes the setup (read-only) — then retry the request."
	default:
		return err
	}
	hinted := *coded
	hinted.Hint = "this host looks like it is behind a login albauth can handle; ask the user before " +
		"adding it with add_domain (see suggestion); configured domains: " + joinNames(cfg.DomainNames())
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
	allowMethods, err := readOnlyMethodsArg(args, name)
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
	// The user has said yes, so albauth may now ask the host the follow-up
	// questions the CLI's add-domain asks: where a forward-auth proxy starts
	// its login, what its cookie is called, how it says a session is live.
	// Explicit arguments win, and a probe that fails is not fatal.
	if len(domain.IDPHostnames) == 0 && d.Probe != nil {
		probePath := cmp.Or(domain.LoginProbePath, config.DefaultLoginProbePath)
		found, _ := discover.Probe(d.Probe, domain.BaseURL, probePath, probeTimeout)
		found.ApplyTo(domain)
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

// readOnlyMethodsArg reads add_domain's allow_methods and refuses, before
// anything is read or written, any entry that is not a read-only method:
// granting writes is never the agent's call. The result is upper-cased and
// de-duplicated; nil (the config default, GET) when none are given.
func readOnlyMethodsArg(args map[string]any, name string) ([]string, error) {
	given, err := stringListArg(args, "allow_methods")
	if err != nil {
		coded, _ := errors.AsType[*auth.Error](err)
		coded.Hint = widenHint(name, "<METHOD>")
		return nil, coded
	}
	var methods []string
	for _, m := range given {
		upper := strings.ToUpper(strings.TrimSpace(m))
		if !readOnlyMethods[upper] {
			example := "<METHOD>"
			if config.ValidMethod(upper) {
				example = upper
			}
			return nil, auth.Errorf(auth.CodeMethodNotAllowed, widenHint(name, example),
				"add_domain cannot grant method %q; nothing was written", clip(m))
		}
		if !slices.Contains(methods, upper) {
			methods = append(methods, upper)
		}
	}
	return methods, nil
}

// widenHint tells the user how to allow a write method themselves.
func widenHint(name, method string) string {
	return fmt.Sprintf("add_domain only adds read-only domains (GET, HEAD, OPTIONS). To allow "+
		"writes, the user widens allow_methods themselves: from a terminal with `albauth config "+
		"add-domain %s --base-url <url> --allow-method GET --allow-method %s`, or by editing "+
		"allow_methods in the config file (`albauth config path` prints where) and restarting albauth", name, method)
}

// clip shortens an agent-supplied value before it is echoed in an error.
func clip(s string) string {
	const max = 32
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
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
