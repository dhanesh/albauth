# Changelog

## [0.4.0](https://github.com/dhanesh/albauth/compare/v0.3.0...v0.4.0) (2026-08-26)


### Features

* configure forward-auth proxies automatically from the probe ([d600e23](https://github.com/dhanesh/albauth/commit/d600e23780910fb5277c60d25a5aeb1e0af428db))


### Fixes

* start the MCP server when nothing is configured yet ([ff5a52f](https://github.com/dhanesh/albauth/commit/ff5a52f7939dedde4f8c815af0ca647f1f990211))
* stop a missing macOS keychain raising a modal dialog ([5a8445d](https://github.com/dhanesh/albauth/commit/5a8445d7cb5a81e8cdfff523d9c4289db8e9c248))
* stop treating a successful HTML page as an expired session ([d85f7a7](https://github.com/dhanesh/albauth/commit/d85f7a79e4c11fa24e547f6dc78ef885e64dda6e))

## [0.3.0](https://github.com/dhanesh/albauth/compare/v0.2.0...v0.3.0) (2026-08-26)


### Features

* remember application cookies, and add config remove-domain ([dcfbdfc](https://github.com/dhanesh/albauth/commit/dcfbdfcf310a1dbc8cd259e9e4dd81d9e5019f4f))


### Fixes

* keep the config at ~/.albauth.toml ([a443711](https://github.com/dhanesh/albauth/commit/a443711b8a489687c13ba625ee3129333b9840ce))
* return binary bodies intact, and stop treating every 401 as expiry ([7c919af](https://github.com/dhanesh/albauth/commit/7c919af8f91e21846ea4a41c08a065e4f73ce456))

## [0.2.0](https://github.com/dhanesh/albauth/compare/v0.1.0...v0.2.0) (2026-08-25)


### Features

* add domains from the command line ([c0e2fcf](https://github.com/dhanesh/albauth/commit/c0e2fcf87ff8237039a31edcc0f6f829b98f9ac4))

## [0.1.0](https://github.com/dhanesh/albauth/compare/v0.1.0...v0.1.0) (2026-08-25)


### Chores

* cut the first release ([1259990](https://github.com/dhanesh/albauth/commit/1259990ff08362ebf45336cdadb9db746d210620))
