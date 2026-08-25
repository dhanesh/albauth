package config

import (
	"fmt"
	"net"
	"net/url"
	"path"
	"regexp"
	"slices"
	"strings"

	"albauth/internal/logx"
)

var (
	nameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]*$`)

	// validMethods is the set http_request may issue. It is deliberately closed:
	// allow_methods fails closed, so an unrecognised verb is a config error
	// rather than something quietly forwarded upstream.
	validMethods = map[string]bool{
		"GET": true, "POST": true, "PUT": true, "PATCH": true,
		"DELETE": true, "HEAD": true, "OPTIONS": true,
	}

	validStorage = map[string]bool{
		StorageAuto: true, StorageKeyring: true, StorageFile: true,
	}
)

// Validate returns every problem with the config, in a stable order.
//
// It never stops at the first failure: a user editing a config file should see
// the whole list, which is what acceptance criterion §13.8 asks for.
func (c *Config) Validate() []string {
	var problems []string

	if !validStorage[c.Settings.Storage] {
		problems = append(problems, fmt.Sprintf(
			"settings.storage: %q is not one of auto, keyring, file", c.Settings.Storage))
	}
	if c.Settings.MaxResponseBytes < 0 {
		problems = append(problems, fmt.Sprintf(
			"settings.max_response_bytes: must not be negative (got %d)", c.Settings.MaxResponseBytes))
	}
	if _, err := logx.ParseLevel(c.Settings.LogLevel); err != nil {
		problems = append(problems, "settings.log_level: "+err.Error())
	}
	if len(c.Domains) == 0 {
		problems = append(problems, "no [[domain]] blocks configured: albauth has nothing to authenticate against")
	}

	seenNames := map[string]int{}
	type claim struct {
		pattern string
		domain  string
	}
	var claims []claim

	for i := range c.Domains {
		d := &c.Domains[i]
		label := fmt.Sprintf("domain[%d]", i)
		if d.Name != "" {
			label = fmt.Sprintf("domain %q", d.Name)
		}

		switch {
		case d.Name == "":
			problems = append(problems, label+": name is required")
		case !nameRE.MatchString(d.Name):
			problems = append(problems, fmt.Sprintf(
				"%s: name must match %s", label, nameRE.String()))
		}
		if first, dup := seenNames[d.Name]; dup && d.Name != "" {
			problems = append(problems, fmt.Sprintf(
				"%s: duplicate name (also used by domain[%d])", label, first))
		} else if d.Name != "" {
			seenNames[d.Name] = i
		}

		host, baseProblems := validateBaseURL(label, d.BaseURL)
		problems = append(problems, baseProblems...)

		if !strings.HasPrefix(d.LoginProbePath, "/") {
			problems = append(problems, fmt.Sprintf(
				"%s: login_probe_path must start with '/' (got %q)", label, d.LoginProbePath))
		}
		if d.CookieNamePrefix == "" {
			problems = append(problems, label+": cookie_name_prefix must not be empty")
		}
		if d.TimeoutSeconds <= 0 {
			problems = append(problems, fmt.Sprintf(
				"%s: timeout_seconds must be positive (got %d)", label, d.TimeoutSeconds))
		}
		if d.LoginTimeoutSeconds <= 0 {
			problems = append(problems, fmt.Sprintf(
				"%s: login_timeout_seconds must be positive (got %d)", label, d.LoginTimeoutSeconds))
		}

		for j, m := range d.AllowMethods {
			upper := strings.ToUpper(strings.TrimSpace(m))
			if !validMethods[upper] {
				problems = append(problems, fmt.Sprintf(
					"%s: allow_methods[%d]: %q is not a supported HTTP method", label, j, m))
				continue
			}
			d.AllowMethods[j] = upper
		}

		if len(d.Match) == 0 && host != "" {
			d.Match = []string{host}
		}
		for j, pattern := range d.Match {
			if _, err := path.Match(pattern, "probe"); err != nil {
				problems = append(problems, fmt.Sprintf(
					"%s: match[%d]: %q is not a valid glob: %v", label, j, pattern, err))
				continue
			}
			claims = append(claims, claim{pattern: pattern, domain: d.Name})
		}
	}

	// Ambiguous routing is a config error, not a silent first-wins race: two
	// domains claiming the same host makes http_request non-deterministic.
	for i := 0; i < len(claims); i++ {
		for j := i + 1; j < len(claims); j++ {
			if claims[i].domain == claims[j].domain {
				continue
			}
			if patternsOverlap(claims[i].pattern, claims[j].pattern) {
				problems = append(problems, fmt.Sprintf(
					"ambiguous routing: match pattern %q (domain %q) overlaps %q (domain %q)",
					claims[i].pattern, claims[i].domain, claims[j].pattern, claims[j].domain))
			}
		}
	}

	return problems
}

func validateBaseURL(label, raw string) (host string, problems []string) {
	if raw == "" {
		return "", []string{label + ": base_url is required"}
	}
	if strings.HasSuffix(raw, "/") {
		problems = append(problems, fmt.Sprintf(
			"%s: base_url must not have a trailing slash (got %q)", label, raw))
		raw = strings.TrimRight(raw, "/")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", append(problems, fmt.Sprintf("%s: base_url is not a valid URL: %v", label, err))
	}
	if u.Host == "" {
		return "", append(problems, fmt.Sprintf("%s: base_url %q has no host", label, raw))
	}
	switch u.Scheme {
	case "https":
	case "http":
		if !isLoopback(u.Hostname()) {
			problems = append(problems, fmt.Sprintf(
				"%s: base_url scheme http is only allowed for localhost/127.0.0.1 (got %q)", label, raw))
		}
	default:
		problems = append(problems, fmt.Sprintf(
			"%s: base_url scheme must be https (got %q)", label, u.Scheme))
	}
	return u.Host, problems
}

// isLoopback reports whether a hostname always resolves to this machine.
//
// RFC 6761 §6.3 reserves the whole ".localhost" TLD, not just the bare label,
// so "anything.localhost" is loopback too — which is how browsers treat it, and
// how local development tools that give each service its own subdomain expect
// it to be treated.
func isLoopback(hostname string) bool {
	hostname = strings.ToLower(hostname)
	if hostname == "localhost" || strings.HasSuffix(hostname, ".localhost") {
		return true
	}
	ip := net.ParseIP(hostname)
	return ip != nil && ip.IsLoopback()
}

// patternsOverlap reports whether two host globs can both match some host.
//
// Exact overlap detection for arbitrary globs is undecidable in general; this
// covers the cases that occur in practice — identical patterns, and a wildcard
// pattern that swallows another pattern's literal skeleton (so "*.example.com"
// is correctly reported as overlapping "api.example.com").
func patternsOverlap(a, b string) bool {
	if a == b {
		return true
	}
	return globCovers(a, b) || globCovers(b, a)
}

func globCovers(pattern, other string) bool {
	// Replace the other pattern's wildcards with a placeholder that a real
	// hostname could contain, then ask whether pattern matches that witness.
	witness := strings.NewReplacer("*", "wildcard", "?", "w", "[", "", "]", "").Replace(other)
	ok, err := path.Match(pattern, witness)
	return err == nil && ok
}

// MatchHost reports whether host is claimed by this domain's match patterns.
func (d *Domain) MatchHost(host string) bool {
	host = strings.ToLower(host)
	return slices.ContainsFunc(d.Match, func(pattern string) bool {
		ok, err := path.Match(strings.ToLower(pattern), host)
		return err == nil && ok
	})
}

// MethodAllowed reports whether the domain permits the given HTTP method.
func (d *Domain) MethodAllowed(method string) bool {
	return slices.Contains(d.AllowMethods, strings.ToUpper(method))
}

// IsIDPHost reports whether host belongs to a configured identity provider.
func (d *Domain) IsIDPHost(host string) bool {
	return slices.ContainsFunc(d.IDPHostnames, func(h string) bool {
		return strings.EqualFold(h, host)
	})
}

// BaseHost is the host (with port, if any) of the domain's base_url.
func (d *Domain) BaseHost() string {
	u, err := url.Parse(d.BaseURL)
	if err != nil {
		return ""
	}
	return u.Host
}
