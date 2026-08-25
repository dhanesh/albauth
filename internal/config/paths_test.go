package config

import (
	"errors"
	"path/filepath"
	"testing"
)

// env builds a getenv function over a fixed map, so path resolution can be
// tested for every platform from one machine.
func env(pairs map[string]string) func(string) string {
	return func(k string) string { return pairs[k] }
}

func withGOOS(t *testing.T, value string) {
	t.Helper()
	orig := goos
	t.Cleanup(func() { goos = orig })
	goos = value
}

func withHome(t *testing.T, home string, err error) {
	t.Helper()
	orig := osUserHomeDir
	t.Cleanup(func() { osUserHomeDir = orig })
	osUserHomeDir = func() (string, error) { return home, err }
}

func TestResolvePathPrecedence(t *testing.T) {
	withGOOS(t, "linux")

	t.Run("the flag wins over everything", func(t *testing.T) {
		got, err := ResolvePath("/explicit/config.toml", env(map[string]string{
			"ALBAUTH_CONFIG": "/from/env.toml", "XDG_CONFIG_HOME": "/xdg",
		}))
		if err != nil || got != "/explicit/config.toml" {
			t.Fatalf("ResolvePath = %q, %v", got, err)
		}
	})

	t.Run("then the environment variable", func(t *testing.T) {
		got, err := ResolvePath("", env(map[string]string{
			"ALBAUTH_CONFIG": "/from/env.toml", "XDG_CONFIG_HOME": "/xdg",
		}))
		if err != nil || got != "/from/env.toml" {
			t.Fatalf("ResolvePath = %q, %v", got, err)
		}
	})

	t.Run("then XDG_CONFIG_HOME", func(t *testing.T) {
		got, err := ResolvePath("", env(map[string]string{"XDG_CONFIG_HOME": "/xdg"}))
		want := filepath.Join("/xdg", "albauth", "config.toml")
		if err != nil || got != want {
			t.Fatalf("ResolvePath = %q, %v; want %q", got, err, want)
		}
	})

	t.Run("then the per-user config directory", func(t *testing.T) {
		orig := osUserConfigDir
		t.Cleanup(func() { osUserConfigDir = orig })
		osUserConfigDir = func() (string, error) { return "/home/u/.config", nil }

		got, err := ResolvePath("", env(nil))
		want := filepath.Join("/home/u/.config", "albauth", "config.toml")
		if err != nil || got != want {
			t.Fatalf("ResolvePath = %q, %v; want %q", got, err, want)
		}
	})
}

func TestResolvePathIgnoresXDGOnWindows(t *testing.T) {
	withGOOS(t, "windows")
	orig := osUserConfigDir
	t.Cleanup(func() { osUserConfigDir = orig })
	osUserConfigDir = func() (string, error) { return `C:\Users\u\AppData\Roaming`, nil }

	got, err := ResolvePath("", env(map[string]string{"XDG_CONFIG_HOME": "/xdg"}))
	want := filepath.Join(`C:\Users\u\AppData\Roaming`, "albauth", "config.toml")
	if err != nil || got != want {
		t.Fatalf("ResolvePath = %q, %v; want %q", got, err, want)
	}
}

func TestResolvePathReportsAMissingConfigDirectory(t *testing.T) {
	withGOOS(t, "linux")
	orig := osUserConfigDir
	t.Cleanup(func() { osUserConfigDir = orig })
	osUserConfigDir = func() (string, error) { return "", errors.New("no HOME") }

	if _, err := ResolvePath("", env(nil)); err == nil {
		t.Fatal("ResolvePath should report a missing config directory")
	}
}

func TestStateDirPerPlatform(t *testing.T) {
	tests := []struct {
		name string
		goos string
		vars map[string]string
		home string
		want string
	}{
		{"linux with XDG_STATE_HOME", "linux", map[string]string{"XDG_STATE_HOME": "/xdg-state"}, "/home/u",
			filepath.Join("/xdg-state", "albauth")},
		{"linux without XDG_STATE_HOME", "linux", nil, "/home/u",
			filepath.Join("/home/u", ".local", "state", "albauth")},
		{"macOS", "darwin", map[string]string{"XDG_STATE_HOME": "/ignored"}, "/Users/u",
			filepath.Join("/Users/u", "Library", "Application Support", "albauth")},
		{"windows with LOCALAPPDATA", "windows", map[string]string{"LOCALAPPDATA": `C:\Users\u\AppData\Local`}, `C:\Users\u`,
			filepath.Join(`C:\Users\u\AppData\Local`, "albauth")},
		{"windows without LOCALAPPDATA", "windows", nil, `C:\Users\u`,
			filepath.Join(`C:\Users\u`, "AppData", "Local", "albauth")},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			withGOOS(t, tc.goos)
			withHome(t, tc.home, nil)
			got, err := StateDir(env(tc.vars))
			if err != nil || got != tc.want {
				t.Fatalf("StateDir = %q, %v; want %q", got, err, tc.want)
			}
		})
	}
}

func TestStateDirReportsAMissingHomeDirectory(t *testing.T) {
	for _, osName := range []string{"linux", "darwin"} {
		t.Run(osName, func(t *testing.T) {
			withGOOS(t, osName)
			withHome(t, "", errors.New("no HOME"))
			if _, err := StateDir(env(nil)); err == nil {
				t.Fatal("StateDir should report a missing home directory")
			}
		})
	}
}

func TestSessionFilePath(t *testing.T) {
	withGOOS(t, "linux")
	withHome(t, "/home/u", nil)

	got, err := SessionFilePath(env(map[string]string{"XDG_STATE_HOME": "/xdg-state"}))
	want := filepath.Join("/xdg-state", "albauth", "sessions.json")
	if err != nil || got != want {
		t.Fatalf("SessionFilePath = %q, %v; want %q", got, err, want)
	}

	withHome(t, "", errors.New("no HOME"))
	if _, err := SessionFilePath(env(nil)); err == nil {
		t.Fatal("SessionFilePath should propagate a state directory failure")
	}
}

func TestBrowserProfileDir(t *testing.T) {
	withGOOS(t, "linux")
	withHome(t, "/home/u", nil)

	got, err := BrowserProfileDir(env(map[string]string{"XDG_STATE_HOME": "/xdg-state"}), "internal-api")
	want := filepath.Join("/xdg-state", "albauth", "browser", "internal-api")
	if err != nil || got != want {
		t.Fatalf("BrowserProfileDir = %q, %v; want %q", got, err, want)
	}

	withHome(t, "", errors.New("no HOME"))
	if _, err := BrowserProfileDir(env(nil), "internal-api"); err == nil {
		t.Fatal("BrowserProfileDir should propagate a state directory failure")
	}
}
