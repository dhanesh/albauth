// Package mcpserver exposes albauth's tools over the MCP stdio transport.
//
// Every handler in this file is a plain function over a decoded argument map,
// returning a value to be JSON-encoded. Keeping the mcp-go types at the edge
// (server.go) means the whole tool surface is unit-testable without a
// transport, and the adapter that remains is small enough to read in one go.
package mcpserver

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"sync"
	"time"

	"albauth/internal/auth"
	"albauth/internal/config"
	"albauth/internal/discover"
	"albauth/internal/httpx"
	"albauth/internal/session"
)

// Tool names, as advertised to the client.
const (
	ToolHTTPRequest = "http_request"
	ToolAuthLogin   = "auth_login"
	ToolAuthStatus  = "auth_status"
	ToolAuthLogout  = "auth_logout"
	ToolListDomains = "list_domains"
	ToolAddDomain   = "add_domain"
)

// Deps are the collaborators the handlers need.
type Deps struct {
	// Config is the configuration the handlers start with. add_domain replaces
	// it while the server runs, so handlers read it through config(), never
	// directly.
	Config *config.Config
	Auth   *auth.Manager
	Client *httpx.Client
	Now    func() time.Time

	// ClearBrowserProfile removes a domain's persistent browser profile. It is
	// injected so auth_logout can be tested without touching the real
	// state directory.
	ClearBrowserProfile func(domainName string) error

	// Probe asks an unconfigured host whether it sits behind a login, for the
	// unknown_domain suggestion. Nil means unconfigured hosts are not probed.
	Probe discover.Detector

	// AddCookiePrefix registers the cookie family of a domain added while the
	// server runs, so the logger redacts it like every configured one.
	AddCookiePrefix func(prefix string)

	mu    sync.RWMutex // guards Config
	addMu sync.Mutex   // serialises add_domain's read-modify-write of the file
}

// config returns the current configuration. The value it returns is never
// modified afterwards — add_domain swaps in a new one — so a handler may keep
// using it for the rest of the call without holding the lock.
func (d *Deps) config() *config.Config {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.Config
}

func (d *Deps) now() time.Time {
	if d.Now != nil {
		return d.Now()
	}
	return time.Now()
}

// Handle dispatches a decoded tool call. It is the single entry point the
// transport adapter and the tests share.
func (d *Deps) Handle(ctx context.Context, tool string, args map[string]any) (any, error) {
	switch tool {
	case ToolHTTPRequest:
		return d.httpRequest(ctx, args)
	case ToolAuthLogin:
		return d.authLogin(ctx, args)
	case ToolAuthStatus:
		return d.authStatus(args)
	case ToolAuthLogout:
		return d.authLogout(args)
	case ToolListDomains:
		return d.listDomains(), nil
	case ToolAddDomain:
		return d.addDomain(args)
	default:
		return nil, auth.Errorf(auth.CodeInvalidRequest, "", "unknown tool %q", tool)
	}
}

func (d *Deps) httpRequest(ctx context.Context, args map[string]any) (any, error) {
	rawURL, err := stringArg(args, "url", true)
	if err != nil {
		return nil, err
	}
	domainName, err := stringArg(args, "domain", false)
	if err != nil {
		return nil, err
	}
	method, err := stringArg(args, "method", false)
	if err != nil {
		return nil, err
	}
	query, err := stringMapArg(args, "query")
	if err != nil {
		return nil, err
	}
	headers, err := stringMapArg(args, "headers")
	if err != nil {
		return nil, err
	}
	body, err := stringArg(args, "body", false)
	if err != nil {
		return nil, err
	}

	domain, target, err := httpx.Resolve(d.config(), rawURL, domainName, method)
	if err != nil {
		return nil, d.suggestFor(err, rawURL)
	}
	if method == "" {
		method = "GET"
	}
	return d.Client.Do(ctx, &httpx.Request{
		Domain:  domain,
		Method:  method,
		URL:     target,
		Query:   query,
		Headers: headers,
		Body:    body,
	})
}

// LoginResult is the auth_login response.
type LoginResult struct {
	Domain        string `json:"domain"`
	Authenticated bool   `json:"authenticated"`
	ExpiresAt     string `json:"expires_at"`
}

func (d *Deps) authLogin(ctx context.Context, args map[string]any) (any, error) {
	domainName, err := stringArg(args, "domain", true)
	if err != nil {
		return nil, err
	}
	domain, err := d.lookup(domainName)
	if err != nil {
		return nil, err
	}
	force, err := boolArg(args, "force")
	if err != nil {
		return nil, err
	}

	var s *session.Session
	if force {
		s, err = d.Auth.ForceLogin(ctx, domain)
	} else {
		s, err = d.Auth.Ensure(ctx, domain)
	}
	if err != nil {
		return nil, err
	}
	return &LoginResult{
		Domain:        domain.Name,
		Authenticated: true,
		ExpiresAt:     formatTime(s.ExpiresAt()),
	}, nil
}

// StatusEntry is one domain's authentication state. It deliberately carries no
// cookie value — only the metadata a model needs to decide what to do next.
type StatusEntry struct {
	Domain         string   `json:"domain"`
	BaseURL        string   `json:"base_url"`
	Authenticated  bool     `json:"authenticated"`
	ExpiresAt      string   `json:"expires_at"`
	AcquiredAt     string   `json:"acquired_at"`
	LastUsedAt     string   `json:"last_used_at"`
	StorageBackend string   `json:"storage_backend"`
	AllowMethods   []string `json:"allow_methods"`
	Error          string   `json:"error,omitempty"`
}

func (d *Deps) authStatus(args map[string]any) (any, error) {
	domainName, err := stringArg(args, "domain", false)
	if err != nil {
		return nil, err
	}

	domains := d.config().Domains
	if domainName != "" {
		found, lookupErr := d.lookup(domainName)
		if lookupErr != nil {
			return nil, lookupErr
		}
		domains = []config.Domain{*found}
	}

	store := d.Auth.Store()
	out := make([]StatusEntry, 0, len(domains))
	for i := range domains {
		domain := &domains[i]
		entry := StatusEntry{
			Domain:         domain.Name,
			BaseURL:        domain.BaseURL,
			StorageBackend: session.BackendFor(store, domain.Name),
			AllowMethods:   domain.AllowMethods,
		}
		s, storeErr := d.Auth.Current(domain.Name)
		switch {
		case storeErr != nil:
			// A broken store for one domain must not hide the others: report it
			// inline rather than failing the whole call.
			entry.Error = storeErr.Error()
		case s != nil:
			entry.Authenticated = s.Valid(d.now())
			entry.ExpiresAt = formatTime(s.ExpiresAt())
			entry.AcquiredAt = formatTime(s.AcquiredAt)
			entry.LastUsedAt = formatTime(s.LastUsedAt)
		}
		out = append(out, entry)
	}
	return out, nil
}

// LogoutResult is the auth_logout response.
type LogoutResult struct {
	Domain                string `json:"domain"`
	Authenticated         bool   `json:"authenticated"`
	BrowserProfileCleared bool   `json:"browser_profile_cleared"`
}

func (d *Deps) authLogout(args map[string]any) (any, error) {
	domainName, err := stringArg(args, "domain", true)
	if err != nil {
		return nil, err
	}
	domain, err := d.lookup(domainName)
	if err != nil {
		return nil, err
	}
	clearProfile, err := boolArg(args, "clear_browser_profile")
	if err != nil {
		return nil, err
	}
	if err := d.Auth.Logout(domain.Name); err != nil {
		return nil, err
	}
	// Drop any application cookies too: logging out of the load balancer while
	// the application still believes the caller is signed in would be a
	// confusing half-state.
	if d.Client != nil {
		d.Client.ForgetCookies(domain.Name)
	}
	cleared := false
	if clearProfile && d.ClearBrowserProfile != nil {
		if err := d.ClearBrowserProfile(domain.Name); err != nil {
			return nil, auth.Wrap(err, auth.CodeStorageUnavailable,
				"remove the browser profile directory by hand",
				"could not clear browser profile for %q: %v", domain.Name, err)
		}
		cleared = true
	}
	return &LogoutResult{Domain: domain.Name, Authenticated: false, BrowserProfileCleared: cleared}, nil
}

// DomainEntry is one row of list_domains.
type DomainEntry struct {
	Name         string   `json:"name"`
	BaseURL      string   `json:"base_url"`
	Match        []string `json:"match"`
	AllowMethods []string `json:"allow_methods"`
}

func (d *Deps) listDomains() []DomainEntry {
	cfg := d.config()
	out := make([]DomainEntry, 0, len(cfg.Domains))
	for i := range cfg.Domains {
		out = append(out, entryFor(&cfg.Domains[i]))
	}
	slices.SortFunc(out, func(a, b DomainEntry) int { return cmp.Compare(a.Name, b.Name) })
	return out
}

// entryFor is a domain as list_domains (and add_domain) shows it.
func entryFor(domain *config.Domain) DomainEntry {
	return DomainEntry{
		Name:         domain.Name,
		BaseURL:      domain.BaseURL,
		Match:        domain.Match,
		AllowMethods: domain.AllowMethods,
	}
}

func (d *Deps) lookup(name string) (*config.Domain, error) {
	cfg := d.config()
	domain, ok := cfg.Lookup(name)
	if !ok {
		return nil, auth.Errorf(auth.CodeUnknownDomain,
			"configured domains: "+joinNames(cfg.DomainNames()),
			"unknown domain %q", name)
	}
	return domain, nil
}

func joinNames(names []string) string {
	return cmp.Or(strings.Join(names, ", "), "(none configured)")
}

func formatTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

// --- argument decoding -------------------------------------------------------
//
// Tool arguments arrive as free-form JSON. Each accessor validates type at the
// point of use and reports a coded error, so a malformed call never reaches the
// HTTP layer as a zero value.

func stringArg(args map[string]any, key string, required bool) (string, error) {
	raw, present := args[key]
	if !present || raw == nil {
		if required {
			return "", auth.Errorf(auth.CodeInvalidRequest, "", "%q is required", key)
		}
		return "", nil
	}
	s, ok := raw.(string)
	if !ok {
		return "", auth.Errorf(auth.CodeInvalidRequest, "", "%q must be a string, got %T", key, raw)
	}
	return s, nil
}

func boolArg(args map[string]any, key string) (bool, error) {
	raw, present := args[key]
	if !present || raw == nil {
		return false, nil
	}
	b, ok := raw.(bool)
	if !ok {
		return false, auth.Errorf(auth.CodeInvalidRequest, "", "%q must be a boolean, got %T", key, raw)
	}
	return b, nil
}

func stringMapArg(args map[string]any, key string) (map[string]string, error) {
	raw, present := args[key]
	if !present || raw == nil {
		return nil, nil
	}
	m, ok := raw.(map[string]any)
	if !ok {
		return nil, auth.Errorf(auth.CodeInvalidRequest, "", "%q must be an object, got %T", key, raw)
	}
	out := make(map[string]string, len(m))
	for k, v := range m {
		s, ok := v.(string)
		if !ok {
			return nil, auth.Errorf(auth.CodeInvalidRequest, "",
				"%q[%s] must be a string, got %T", key, k, v)
		}
		out[k] = s
	}
	return out, nil
}

// RenderError turns any error into the documented {error, message, hint} JSON,
// plus a suggestion when the error carries one (an unknown_domain whose host
// sits behind a login).
//
// An uncoded error would leak an internal Go message to the model, so anything
// that is not already an auth.Error is mapped to a generic code.
func RenderError(err error) string {
	coded := &auth.Error{Code: auth.CodeUpstreamError, Message: err.Error()}
	if typed, ok := codedError(err); ok {
		coded = typed
	}
	payload := map[string]any{"error": coded.Code, "message": coded.Message}
	if coded.Hint != "" {
		payload["hint"] = coded.Hint
	}
	if suggested, ok := errors.AsType[*suggestedError](err); ok {
		payload["suggestion"] = suggested.Suggestion
	}
	// The payload is strings and a struct of strings, lists and a bool, so it
	// always marshals and there is no failure to handle.
	data, _ := json.Marshal(payload)
	return string(data)
}
