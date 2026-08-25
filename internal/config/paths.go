package config

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// osUserHomeDir is indirected so tests can exercise the failure branch.
var osUserHomeDir = os.UserHomeDir

// goos is indirected so the per-OS path rules can be tested on one machine.
var goos = runtime.GOOS

// StateDir returns the directory holding session state and browser profiles.
//
//	Linux   $XDG_STATE_HOME/albauth, else ~/.local/state/albauth
//	macOS   ~/Library/Application Support/albauth
//	Windows %LOCALAPPDATA%\albauth
func StateDir(getenv func(string) string) (string, error) {
	switch goos {
	case "windows":
		if base := getenv("LOCALAPPDATA"); base != "" {
			return filepath.Join(base, "albauth"), nil
		}
	case "darwin":
		home, err := osUserHomeDir()
		if err != nil {
			return "", fmt.Errorf("cannot determine home directory: %w", err)
		}
		return filepath.Join(home, "Library", "Application Support", "albauth"), nil
	default:
		if base := getenv("XDG_STATE_HOME"); base != "" {
			return filepath.Join(base, "albauth"), nil
		}
	}
	home, err := osUserHomeDir()
	if err != nil {
		return "", fmt.Errorf("cannot determine home directory: %w", err)
	}
	if goos == "windows" {
		return filepath.Join(home, "AppData", "Local", "albauth"), nil
	}
	return filepath.Join(home, ".local", "state", "albauth"), nil
}

// SessionFilePath is where the file storage backend keeps its JSON blob.
func SessionFilePath(getenv func(string) string) (string, error) {
	dir, err := StateDir(getenv)
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "sessions.json"), nil
}

// BrowserProfileDir is the persistent Chrome user-data directory for a domain.
//
// Reusing it between logins is what makes re-authentication feel silent: the
// identity provider's own SSO session usually survives, so the redirect chain
// completes without the user touching anything.
func BrowserProfileDir(getenv func(string) string, domainName string) (string, error) {
	dir, err := StateDir(getenv)
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "browser", domainName), nil
}
