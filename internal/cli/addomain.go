package cli

import (
	"errors"
	"flag"
	"fmt"
	"net/http"
	"strings"
	"time"

	"albauth/internal/config"
	"albauth/internal/discover"
)

// stringList collects a flag that may be repeated.
type stringList []string

func (s *stringList) String() string { return strings.Join(*s, ",") }

func (s *stringList) Set(value string) error {
	if value == "" {
		return errors.New("value must not be empty")
	}
	*s = append(*s, value)
	return nil
}

// probeIDPHost is indirected so tests never reach the network.
var probeIDPHost discover.Detector = discover.DetectIDPHost

// probeDomain works out how a domain sends an unauthenticated caller to log
// in; see discover.Probe.
func probeDomain(baseURL, probePath string, timeout time.Duration) (discover.Findings, error) {
	return discover.Probe(probeIDPHost, baseURL, probePath, timeout)
}

// configAddDomain implements `albauth config add-domain`.
func (a *app) configAddDomain(args []string) error {
	set := flag.NewFlagSet("config add-domain", flag.ContinueOnError)
	set.SetOutput(a.env.Stderr)

	baseURL := set.String("base-url", "", "scheme and host of the API, e.g. https://api.example.com")
	loginProbePath := set.String("login-probe-path", "", "cheap path behind the same listener rule (default \"/\")")
	cookiePrefix := set.String("cookie-prefix", "", "session cookie family (default \""+config.DefaultCookieNamePrefix+"\")")
	sessionCheckPath := set.String("session-check-path", "",
		"path that answers 2xx for a live session, asked before a 401 means expired (e.g. /oauth2/auth)")
	timeoutSeconds := set.Int("timeout-seconds", 0, "per-request timeout (default 30)")
	loginTimeoutSeconds := set.Int("login-timeout-seconds", 0, "seconds to wait for the browser login (default 180)")
	noProbe := set.Bool("no-probe", false, "skip contacting the domain to detect its identity provider")
	treat401 := set.Bool("treat-401-as-expired", false,
		"treat a 401 as an expired load-balancer session (only for OnUnauthenticatedRequest=deny)")

	var match, idpHostnames, allowMethods, headers stringList
	set.Var(&match, "match", "host pattern this domain claims (repeatable)")
	set.Var(&idpHostnames, "idp-hostname", "identity provider hostname (repeatable; probed if omitted)")
	set.Var(&allowMethods, "allow-method", "HTTP method the model may use (repeatable; default GET)")
	set.Var(&headers, "header", "header added to every request, as NAME=VALUE (repeatable)")

	// The name is taken before flag parsing rather than after. Go's flag
	// package stops at the first non-flag argument, so `add-domain api
	// --base-url …` would otherwise leave every flag unparsed and report a
	// missing --base-url, which is a baffling way to be told about argument
	// order.
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return usagef("config add-domain needs a domain name before its flags")
	}
	name := args[0]

	if err := set.Parse(args[1:]); err != nil {
		return err
	}
	if set.NArg() != 0 {
		return usagef("unexpected argument %q after the flags", set.Arg(0))
	}
	if *baseURL == "" {
		return usagef("config add-domain needs --base-url")
	}

	parsedHeaders, err := parseHeaderFlags(headers)
	if err != nil {
		return err
	}

	domain := &config.Domain{
		Name:                name,
		BaseURL:             strings.TrimRight(*baseURL, "/"),
		Match:               match,
		LoginProbePath:      *loginProbePath,
		CookieNamePrefix:    *cookiePrefix,
		SessionCheckPath:    *sessionCheckPath,
		IDPHostnames:        idpHostnames,
		AllowMethods:        upperAll(allowMethods),
		Treat401AsExpired:   *treat401,
		TimeoutSeconds:      *timeoutSeconds,
		LoginTimeoutSeconds: *loginTimeoutSeconds,
		Headers:             parsedHeaders,
	}

	// The identity provider is the field people get wrong, so ask the load
	// balancer rather than making them look it up. Never fatal: it is an
	// optional key, and the domain may be unreachable from here.
	if len(domain.IDPHostnames) == 0 && !*noProbe {
		probePath := domain.LoginProbePath
		if probePath == "" {
			probePath = config.DefaultLoginProbePath
		}
		fmt.Fprintf(a.env.Stderr, "probing %s to detect the identity provider…\n", domain.BaseURL)
		found, probeErr := probeDomain(domain.BaseURL, probePath, 10*time.Second)
		switch {
		case found.IDPHost == "":
			fmt.Fprintf(a.env.Stderr,
				"could not detect it (%v)\n"+
					"  the domain will still work; expiry detection just falls back to treating a\n"+
					"  cross-host authorization redirect as expired. Add it later with idp_hostnames.\n", probeErr)
		default:
			domain.IDPHostnames = []string{found.IDPHost}
			fmt.Fprintf(a.env.Stderr, "detected identity provider: %s\n", found.IDPHost)
		}
		// A proxy that answers 401 and keeps its login route elsewhere needs two
		// settings that nobody guesses on a first run: where the browser starts,
		// and that a 401 here means "not logged in" rather than "refused". Both
		// are set from what the probe actually observed, not assumed. An explicit
		// flag always wins.
		if found.LoginPath != "" && domain.LoginProbePath == "" {
			domain.LoginProbePath = found.LoginPath
			fmt.Fprintf(a.env.Stderr,
				"this domain answers 401 instead of redirecting, so login starts at %s\n",
				found.LoginPath)
			if !domain.Treat401AsExpired {
				domain.Treat401AsExpired = true
				fmt.Fprintf(a.env.Stderr,
					"  and treat_401_as_expired was turned on to match\n")
			}
			if domain.CookieNamePrefix == "" && found.CookiePrefix != "" {
				domain.CookieNamePrefix = found.CookiePrefix
				fmt.Fprintf(a.env.Stderr,
					"  session cookie family set to %q (the default is the AWS load balancer's)\n",
					found.CookiePrefix)
			}
			if domain.SessionCheckPath == "" && found.SessionCheck != "" {
				domain.SessionCheckPath = found.SessionCheck
				fmt.Fprintf(a.env.Stderr,
					"  session_check_path set to %s, so an application's own 401 is not mistaken\n"+
						"  for an expired session (the proxy answers 2xx there while the session is live)\n",
					found.SessionCheck)
			}
		}
	}

	path, err := configResolvePath(a.configPath, a.env.Getenv)
	if err != nil {
		return err
	}
	if err := configAddDomain(path, domain); err != nil {
		return err
	}

	fmt.Fprintf(a.env.Stdout, "added domain %q to %s\n", name, path)
	fmt.Fprintf(a.env.Stdout, "\nNext:\n  albauth auth login %s\n", name)
	if len(domain.AllowMethods) == 0 || allowMethodsAreReadOnly(domain.AllowMethods) {
		fmt.Fprintf(a.env.Stdout,
			"\nThis domain is read-only. To let the model write to it, re-add it with\n"+
				"--allow-method GET --allow-method POST (and so on), or edit allow_methods.\n")
	}
	return nil
}

// configAddDomain is indirected so the tests can drive a write failure.
var configAddDomain = config.AddDomain

func allowMethodsAreReadOnly(methods []string) bool {
	for _, m := range methods {
		if m != http.MethodGet && m != http.MethodHead && m != http.MethodOptions {
			return false
		}
	}
	return true
}

func upperAll(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	out := make([]string, len(values))
	for i, v := range values {
		out[i] = strings.ToUpper(strings.TrimSpace(v))
	}
	return out
}

func parseHeaderFlags(values []string) (map[string]string, error) {
	if len(values) == 0 {
		return nil, nil
	}
	out := make(map[string]string, len(values))
	for _, raw := range values {
		name, value, ok := strings.Cut(raw, "=")
		name = strings.TrimSpace(name)
		if !ok || name == "" {
			return nil, fmt.Errorf("--header %q is not NAME=VALUE", raw)
		}
		out[name] = strings.TrimSpace(value)
	}
	return out, nil
}

// configRemoveDomain implements `albauth config remove-domain`.
func (a *app) configRemoveDomain(args []string) error {
	set := flag.NewFlagSet("config remove-domain", flag.ContinueOnError)
	set.SetOutput(a.env.Stderr)
	keepSession := set.Bool("keep-session", false,
		"leave the stored session in place instead of deleting it")

	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return usagef("config remove-domain needs a domain name before its flags")
	}
	name := args[0]
	if err := set.Parse(args[1:]); err != nil {
		return err
	}
	if set.NArg() != 0 {
		return usagef("unexpected argument %q after the flags", set.Arg(0))
	}

	path, err := configResolvePath(a.configPath, a.env.Getenv)
	if err != nil {
		return err
	}
	if err := configRemoveDomain(path, name); err != nil {
		return err
	}
	fmt.Fprintf(a.env.Stdout, "removed domain %q from %s\n", name, path)

	// A session for a domain that no longer exists cannot be used and cannot be
	// inspected, so leaving it in the keychain is just litter.
	if !*keepSession {
		if rt, buildErr := a.build(); buildErr == nil {
			if err := rt.mgr.Logout(name); err == nil {
				fmt.Fprintf(a.env.Stdout, "deleted its stored session\n")
			}
			rt.deps.Client.ForgetCookies(name)
		}
	}
	return nil
}

// configRemoveDomain is indirected so the tests can drive a write failure.
var configRemoveDomain = config.RemoveDomain
