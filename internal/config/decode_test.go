package config

import (
	"errors"

	"github.com/BurntSushi/toml"
)

// decode is a thin test helper mirroring what Parse does before defaulting, so
// the validation table can start from raw TOML.
func decode(text string, cfg *Config) (toml.MetaData, error) {
	return toml.Decode(text, cfg)
}

// configError extracts a *config.Error, so the validation tests need only one
// error-handling import.
func configError(err error) (*Error, bool) { return errors.AsType[*Error](err) }
