package config

import (
	"errors"
	"os"
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

func withStat(t *testing.T, existing map[string]bool) {
	t.Helper()
	orig := statFile
	t.Cleanup(func() { statFile = orig })
	statFile = func(path string) (os.FileInfo, error) {
		if existing[path] {
			return nil, nil
		}
		return nil, os.ErrNotExist
	}
}

func TestResolvePathPrecedence(t *testing.T) {
	withGOOS(t, "linux")
	withHome(t, "/home/u", nil)

	t.Run("the flag wins over everything", func(t *testing.T) {
		withStat(t, nil)
		got, err := ResolvePath("/explicit/config.toml", env(map[string]string{
			"ALBAUTH_CONFIG": "/from/env.toml", "XDG_CONFIG_HOME": "/xdg",
		}))
		if err != nil || got != "/explicit/config.toml" {
			t.Fatalf("ResolvePath = %q, %v", got, err)
		}
	})

	t.Run("then the environment variable", func(t *testing.T) {
		withStat(t, nil)
		got, err := ResolvePath("", env(map[string]string{
			"ALBAUTH_CONFIG": "/from/env.toml", "XDG_CONFIG_HOME": "/xdg",
		}))
		if err != nil || got != "/from/env.toml" {
			t.Fatalf("ResolvePath = %q, %v", got, err)
		}
	})

	t.Run("with nothing on disk, the home dotfile is the default", func(t *testing.T) {
		withStat(t, nil)
		got, err := ResolvePath("", env(nil))
		want := filepath.Join("/home/u", DefaultConfigName)
		if err != nil || got != want {
			t.Fatalf("ResolvePath = %q, %v; want %q", got, err, want)
		}
	})

	t.Run("an existing dotfile wins over the conventional directory", func(t *testing.T) {
		dotfile := filepath.Join("/home/u", DefaultConfigName)
		withStat(t, map[string]bool{
			dotfile: true,
			filepath.Join("/home/u", ".config", "albauth", "config.toml"): true,
		})
		got, _ := ResolvePath("", env(nil))
		if got != dotfile {
			t.Fatalf("ResolvePath = %q, want the dotfile", got)
		}
	})

	// Someone who deliberately keeps configuration under XDG_CONFIG_HOME must
	// not have it ignored.
	t.Run("an existing XDG config is used when there is no dotfile", func(t *testing.T) {
		xdg := filepath.Join("/xdg", "albauth", "config.toml")
		withStat(t, map[string]bool{xdg: true})
		got, _ := ResolvePath("", env(map[string]string{"XDG_CONFIG_HOME": "/xdg"}))
		if got != xdg {
			t.Fatalf("ResolvePath = %q, want %q", got, xdg)
		}
	})

	t.Run("the conventional directory is used when it holds the config", func(t *testing.T) {
		conventional := filepath.Join("/home/u", ".config", "albauth", "config.toml")
		withStat(t, map[string]bool{conventional: true})
		got, _ := ResolvePath("", env(nil))
		if got != conventional {
			t.Fatalf("ResolvePath = %q, want %q", got, conventional)
		}
	})

	// An upgrade must not appear to lose a config an earlier version wrote.
	t.Run("a config left where an older version put it is still found", func(t *testing.T) {
		orig := osUserConfigDir
		t.Cleanup(func() { osUserConfigDir = orig })
		osUserConfigDir = func() (string, error) {
			return "/home/u/Library/Application Support", nil
		}
		legacy := filepath.Join("/home/u/Library/Application Support", "albauth", "config.toml")
		withStat(t, map[string]bool{legacy: true})
		got, _ := ResolvePath("", env(nil))
		if got != legacy {
			t.Fatalf("ResolvePath = %q, want %q", got, legacy)
		}
	})

	t.Run("a platform config directory that cannot be determined is not fatal", func(t *testing.T) {
		orig := osUserConfigDir
		t.Cleanup(func() { osUserConfigDir = orig })
		osUserConfigDir = func() (string, error) { return "", errors.New("no APPDATA") }
		withStat(t, nil)
		got, err := ResolvePath("", env(nil))
		if err != nil || got != filepath.Join("/home/u", DefaultConfigName) {
			t.Fatalf("ResolvePath = %q, %v", got, err)
		}
	})
}

func TestResolvePathReportsAMissingHomeDirectory(t *testing.T) {
	withGOOS(t, "linux")
	withHome(t, "", errors.New("no HOME"))
	withStat(t, nil)
	if _, err := ResolvePath("", env(nil)); err == nil {
		t.Fatal("ResolvePath should report a missing home directory")
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
