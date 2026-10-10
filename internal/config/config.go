// Package config loads, defaults and validates the albauth TOML configuration.
package config

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/BurntSushi/toml"
)

// Default values applied to any domain field the user leaves unset.
const (
	DefaultLoginProbePath     = "/"
	DefaultCookieNamePrefix   = "AWSELBAuthSessionCookie"
	DefaultTimeoutSeconds     = 30
	DefaultLoginTimeoutSecs   = 180
	DefaultMaxResponseBytes   = 1048576
	DefaultLogLevel           = "info"
	DefaultStorage            = StorageAuto
	DefaultImportedSessionTTL = 8 * 60 * 60 // seconds; see `auth import`
)

// Storage backend selectors for the [settings] storage key.
const (
	StorageAuto    = "auto"
	StorageKeyring = "keyring"
	StorageFile    = "file"
)

// Domain is one configured host behind an ALB OIDC listener rule.
type Domain struct {
	Name             string   `toml:"name"`
	BaseURL          string   `toml:"base_url"`
	Match            []string `toml:"match"`
	LoginProbePath   string   `toml:"login_probe_path"`
	CookieNamePrefix string   `toml:"cookie_name_prefix"`
	IDPHostnames     []string `toml:"idp_hostnames"`
	AllowMethods     []string `toml:"allow_methods"`
	// Treat401AsExpired makes a 401 count as an expired load-balancer session.
	//
	// Off by default, which is a deliberate departure from "any 401 means
	// re-authenticate". Almost every API behind a load balancer also
	// authenticates its own callers, so a 401 is usually the application
	// refusing the request — and re-running the identity-provider flow opens a
	// browser, blocks for up to login_timeout_seconds, and cannot possibly fix
	// it. An expired load-balancer session redirects; that is what the other
	// rules catch. Turn this on for a listener rule configured with
	// OnUnauthenticatedRequest = "deny", where the load balancer itself answers
	// 401.
	Treat401AsExpired bool `toml:"treat_401_as_expired"`
	// SessionCheckPath, when set, is asked before a 401 is treated as an
	// expired session: albauth sends GET base_url + SessionCheckPath carrying
	// only the session cookies. A 2xx means the proxy still accepts the
	// session, so the 401 came from the application refusing the request and
	// is returned as it is, without a re-login. Anything else — another
	// status, a redirect, an error, a timeout — falls back to re-logging in,
	// so a wrong path can never keep a dead session in use. oauth2-proxy's
	// /oauth2/auth is the endpoint this is for. Empty by default.
	SessionCheckPath    string            `toml:"session_check_path"`
	TimeoutSeconds      int               `toml:"timeout_seconds"`
	LoginTimeoutSeconds int               `toml:"login_timeout_seconds"`
	Headers             map[string]string `toml:"headers"`
}

// Settings holds the global [settings] table.
type Settings struct {
	Storage          string `toml:"storage"`
	MaxResponseBytes int    `toml:"max_response_bytes"`
	LogLevel         string `toml:"log_level"`
}

// Config is a parsed and defaulted configuration file.
type Config struct {
	Domains  []Domain `toml:"domain"`
	Settings Settings `toml:"settings"`

	// Path is where this config was read from, for diagnostics.
	Path string `toml:"-"`
}

// Lookup returns the domain with the given name.
func (c *Config) Lookup(name string) (*Domain, bool) {
	for i := range c.Domains {
		if c.Domains[i].Name == name {
			return &c.Domains[i], true
		}
	}
	return nil, false
}

// DomainNames lists configured domain names in file order, for error hints.
func (c *Config) DomainNames() []string {
	names := make([]string, 0, len(c.Domains))
	for i := range c.Domains {
		names = append(names, c.Domains[i].Name)
	}
	return names
}

// osUserConfigDir is indirected so tests can exercise the failure branch.
var osUserConfigDir = os.UserConfigDir

// statFile is indirected so the search-path logic can be tested.
var statFile = os.Stat

// DefaultConfigName is the config file in the user's home directory.
//
// One name, one location, every platform. albauth has exactly one config file,
// so it does not need a directory of its own, and a single unchanging path is
// the one thing a user can always find. It also avoids macOS's
// "~/Library/Application Support", whose space makes the obvious
// `cat $(albauth config path)` fail with "No such file or directory" for two
// half-paths — reading as though the file were missing when it is not.
const DefaultConfigName = ".albauth.toml"

// ResolvePath returns the config path.
//
// Precedence: an explicit --config, then $ALBAUTH_CONFIG, then the first file
// that already exists among the known locations, then the default. Searching
// before defaulting is what lets someone who keeps configuration under
// $XDG_CONFIG_HOME carry on doing so, and what stops an upgrade appearing to
// lose a config written by an earlier version.
func ResolvePath(flagValue string, getenv func(string) string) (string, error) {
	if flagValue != "" {
		return flagValue, nil
	}
	if env := getenv("ALBAUTH_CONFIG"); env != "" {
		return env, nil
	}

	candidates, err := configCandidates(getenv)
	if err != nil {
		return "", err
	}
	for _, path := range candidates {
		if _, err := statFile(path); err == nil {
			return path, nil
		}
	}
	return candidates[0], nil
}

// configCandidates lists the locations a config may live, most preferred first.
// The first entry is also where a new one is created.
func configCandidates(getenv func(string) string) ([]string, error) {
	home, err := osUserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("cannot determine home directory: %w", err)
	}
	candidates := []string{filepath.Join(home, DefaultConfigName)}

	// Honour an explicit XDG choice, and the conventional directory beneath it.
	if xdg := getenv("XDG_CONFIG_HOME"); xdg != "" {
		candidates = append(candidates, filepath.Join(xdg, "albauth", "config.toml"))
	} else {
		candidates = append(candidates, filepath.Join(home, ".config", "albauth", "config.toml"))
	}

	// Where versions before this one wrote it: %APPDATA% on Windows,
	// ~/Library/Application Support on macOS.
	if dir, err := osUserConfigDir(); err == nil {
		legacy := filepath.Join(dir, "albauth", "config.toml")
		if legacy != candidates[len(candidates)-1] {
			candidates = append(candidates, legacy)
		}
	}
	return candidates, nil
}

// Load reads, defaults and validates the config at path.
//
// Validation errors are aggregated: the returned error lists every problem in
// the file, not just the first, so a user fixes one round of edits rather than
// discovering mistakes one at a time.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- path is user-supplied by design
	if err != nil {
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}
	return Parse(data, path)
}

// LoadServing loads the config for `albauth serve`.
//
// Someone who has just installed albauth is in one of two states the strict
// Load rejects: no config file at all, or a file with no domains in it yet.
// The MCP server has to start anyway. If it exits, the client reports a dead
// server and the agent is left with no albauth tools at all — including the
// ones it would use to walk the user through adding their first domain.
//
// A malformed file is still an error. Quietly ignoring a typo would strand the
// user in a worse place: a server that starts but cannot see the domain they
// think they configured.
func LoadServing(path string) (*Config, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- path is user-supplied by design
	if errors.Is(err, fs.ErrNotExist) {
		cfg := &Config{Path: path}
		cfg.applyDefaults()
		return cfg, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}
	return parse(data, path, false)
}

// Parse defaults and validates already-read config bytes.
func Parse(data []byte, path string) (*Config, error) { return parse(data, path, true) }

func parse(data []byte, path string, requireDomain bool) (*Config, error) {
	var cfg Config
	if _, err := toml.Decode(string(data), &cfg); err != nil {
		return nil, &Error{Path: path, Problems: []string{"parse error: " + err.Error()}}
	}
	cfg.Path = path
	cfg.applyDefaults()
	problems := cfg.Validate()
	if !requireDomain {
		problems = cfg.validateServing()
	}
	if len(problems) > 0 {
		return nil, &Error{Path: path, Problems: problems}
	}
	return &cfg, nil
}

func (c *Config) applyDefaults() {
	if c.Settings.Storage == "" {
		c.Settings.Storage = DefaultStorage
	}
	if c.Settings.MaxResponseBytes == 0 {
		c.Settings.MaxResponseBytes = DefaultMaxResponseBytes
	}
	if c.Settings.LogLevel == "" {
		c.Settings.LogLevel = DefaultLogLevel
	}
	for i := range c.Domains {
		d := &c.Domains[i]
		if d.LoginProbePath == "" {
			d.LoginProbePath = DefaultLoginProbePath
		}
		if d.CookieNamePrefix == "" {
			d.CookieNamePrefix = DefaultCookieNamePrefix
		}
		if d.TimeoutSeconds == 0 {
			d.TimeoutSeconds = DefaultTimeoutSeconds
		}
		if d.LoginTimeoutSeconds == 0 {
			d.LoginTimeoutSeconds = DefaultLoginTimeoutSecs
		}
		if len(d.AllowMethods) == 0 {
			d.AllowMethods = []string{"GET"}
		}
	}
}

// Error is a config failure carrying every problem found in one pass.
type Error struct {
	Path     string
	Problems []string
}

func (e *Error) Error() string {
	out := fmt.Sprintf("invalid config %s (%d problem(s)):", e.Path, len(e.Problems))
	for _, p := range e.Problems {
		out += "\n  - " + p
	}
	return out
}
