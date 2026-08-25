package config

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// File modes for the config. It names internal hosts and, in the headers table,
// possibly a token, so it is owner-only like the session store.
const (
	configDirMode  os.FileMode = 0o700
	configFileMode os.FileMode = 0o600
)

// RenderDomain renders a domain as a [[domain]] block.
//
// Values matching the documented defaults are omitted: a generated file that
// spells out every default is harder to read than one that shows only what was
// chosen, and it silently freezes today's defaults into the user's config.
func RenderDomain(d *Domain) string {
	var b strings.Builder
	b.WriteString("\n[[domain]]\n")
	fmt.Fprintf(&b, "name = %q\n", d.Name)
	fmt.Fprintf(&b, "base_url = %q\n", d.BaseURL)

	if len(d.Match) > 0 && !matchIsJustHost(d) {
		fmt.Fprintf(&b, "match = %s\n", renderStringList(d.Match))
	}
	if d.LoginProbePath != "" && d.LoginProbePath != DefaultLoginProbePath {
		fmt.Fprintf(&b, "login_probe_path = %q\n", d.LoginProbePath)
	}
	if d.CookieNamePrefix != "" && d.CookieNamePrefix != DefaultCookieNamePrefix {
		fmt.Fprintf(&b, "cookie_name_prefix = %q\n", d.CookieNamePrefix)
	}
	if len(d.IDPHostnames) > 0 {
		fmt.Fprintf(&b, "idp_hostnames = %s\n", renderStringList(d.IDPHostnames))
	}
	if !allowMethodsAreDefault(d.AllowMethods) {
		fmt.Fprintf(&b, "allow_methods = %s\n", renderStringList(d.AllowMethods))
	}
	if d.TimeoutSeconds != 0 && d.TimeoutSeconds != DefaultTimeoutSeconds {
		fmt.Fprintf(&b, "timeout_seconds = %d\n", d.TimeoutSeconds)
	}
	if d.LoginTimeoutSeconds != 0 && d.LoginTimeoutSeconds != DefaultLoginTimeoutSecs {
		fmt.Fprintf(&b, "login_timeout_seconds = %d\n", d.LoginTimeoutSeconds)
	}
	if len(d.Headers) > 0 {
		fmt.Fprintf(&b, "\n[domain.headers]\n")
		for _, k := range sortedKeys(d.Headers) {
			fmt.Fprintf(&b, "%q = %q\n", k, d.Headers[k])
		}
	}
	return b.String()
}

// matchIsJustHost reports whether match holds nothing the default would not.
func matchIsJustHost(d *Domain) bool {
	return len(d.Match) == 1 && d.Match[0] == d.BaseHost()
}

func allowMethodsAreDefault(methods []string) bool {
	return len(methods) == 0 || (len(methods) == 1 && methods[0] == "GET")
}

func renderStringList(values []string) string {
	quoted := make([]string, len(values))
	for i, v := range values {
		quoted[i] = fmt.Sprintf("%q", v)
	}
	return "[" + strings.Join(quoted, ", ") + "]"
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// AddDomain appends a domain to the config at path, creating the file if it
// does not exist.
//
// The result is parsed and validated before anything is written, so a change
// that would produce an unusable config — a duplicate name, a match pattern
// that collides with another domain — leaves the existing file untouched.
// Appending text rather than re-encoding the whole file keeps the user's own
// comments and formatting intact.
func AddDomain(path string, d *Domain) error {
	existing, err := os.ReadFile(path) // #nosec G304 -- path is the resolved config
	switch {
	case err == nil:
	case os.IsNotExist(err):
		existing = nil
	default:
		return fmt.Errorf("read config %s: %w", path, err)
	}

	updated := strings.TrimRight(string(existing), "\n")
	if updated != "" {
		updated += "\n"
	}
	// RenderDomain opens with a blank line to separate it from what came
	// before. A new file has nothing to separate it from.
	updated += strings.TrimLeft(RenderDomain(d), "\n")

	if _, err := Parse([]byte(updated), path); err != nil {
		return err
	}

	if err := os.MkdirAll(filepath.Dir(path), configDirMode); err != nil {
		return fmt.Errorf("create config directory: %w", err)
	}
	if err := writeFileAtomic(path, []byte(updated), configFileMode); err != nil {
		return fmt.Errorf("write config %s: %w", path, err)
	}
	return nil
}

// writeFileAtomic is indirected so the tests can drive the write failure.
var writeFileAtomic = func(path string, data []byte, mode os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}
