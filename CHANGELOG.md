### 1.0.0 / 2026-02-11

Initial release -- a complete Rust rewrite of [bundler-audit] v0.9.x.

#### Core

* Implemented RubyGems `Gem::Version` parsing and comparison semantics,
  including inline alphanumeric segments and pre-release ordering.
* Implemented `Gem::Requirement` with all 7 operators
  (`=`, `!=`, `>`, `<`, `>=`, `<=`, `~>`).
* Implemented `Gemfile.lock` parser as a state-machine with indentation
  tracking. Handles GEM, GIT, PATH sections, platform variants, pinned
  dependencies, and compound version constraints.
* Implemented advisory YAML deserialization with vulnerability checking
  (`patched_versions`, `unaffected_versions`) and CVSS v3/v2 criticality.
* Implemented advisory database management using `git2` (libgit2) for
  clone and fast-forward update of [ruby-advisory-db].
* Implemented scanner that ties lockfile and database together:
  * Detects insecure gem sources (`git://` and `http://` protocols).
  * Checks each gem against the advisory database.
  * Ignores internal/private sources (RFC 1918, RFC 4193, RFC 6890 IP ranges).
  * Supports ignore lists by advisory ID (CVE, GHSA, OSVDB).
* Added `.bundler-audit.yml` configuration file support with strict
  YAML validation. CLI `--ignore` takes precedence over the config file.

#### CLI

* Added `bundler-audit check` command (also the default when no subcommand
  is given), with options:
  * `--quiet` / `-q` to suppress output.
  * `--verbose` / `-v` to show full advisory descriptions.
  * `--ignore` / `-i` to ignore specific advisory IDs.
  * `--update` / `-u` to update the database before checking.
  * `--database` / `-D` to specify a custom advisory database path.
  * `--format` / `-F` to select output format (`text` or `json`).
  * `--gemfile-lock` / `-G` to specify a custom lockfile path.
  * `--config` / `-c` to specify a custom configuration file path.
  * `--output` / `-o` to write output to a file.
* Added `bundler-audit update` command.
* Added `bundler-audit download` command.
* Added `bundler-audit stats` command.
* Added `bundler-audit version` command.
* Auto-downloads [ruby-advisory-db] on first run if not present.
* TTY detection for ANSI color output and JSON pretty-printing.

#### Output Formats

* Text format with ANSI color highlighting for criticality levels.
* JSON format with gem info, advisory details, and CVSS scores.

[bundler-audit]: https://github.com/rubysec/bundler-audit
[ruby-advisory-db]: https://github.com/rubysec/ruby-advisory-db
