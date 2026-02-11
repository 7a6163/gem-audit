# bundler-audit-rs

Patch-level verification for [Bundler] dependencies, rewritten in Rust.

A drop-in replacement for [bundler-audit] that compiles to a single static
binary with zero runtime dependencies -- no Ruby, no Bundler, no gem install
required.

## Features

* Checks for vulnerable versions of gems in `Gemfile.lock`.
* Checks for insecure gem sources (`http://` and `git://`).
* Allows ignoring specific advisories via CLI flags or a configuration file.
* Prints advisory information (CVE, GHSA, CVSS criticality, solution).
* Supports text and JSON output formats.
* Downloads and updates the [ruby-advisory-db] automatically.
* Does not require Ruby or Bundler to be installed.

## Install

### From source

```
$ cargo install --path .
```

### Build from source

```
$ git clone https://github.com/user/bundler-audit-rs.git
$ cd bundler-audit-rs
$ cargo build --release
$ ./target/release/bundler-audit --version
```

## Usage

Audit a project's `Gemfile.lock`:

```
$ bundler-audit
Name: activerecord
Version: 3.2.10
CVE: CVE-2015-7577
GHSA: GHSA-xrr6-3pc4-m447
Criticality: Medium
URL: https://groups.google.com/forum/#!topic/rubyonrails-security/cawsWcQ6c8g
Title: Nested attributes rejection proc bypass in Active Record
Solution: upgrade to '>= 5.0.0.beta1.1', '~> 4.2.5, >= 4.2.5.1', '~> 4.1.14, >= 4.1.14.1', '~> 3.2.22.1'

Vulnerabilities found!
```

Update the [ruby-advisory-db] before checking:

```
$ bundler-audit check --update
```

Ignore specific advisories:

```
$ bundler-audit check --ignore CVE-2020-1234 GHSA-xxxx-yyyy-zzzz
```

Audit a specific directory:

```
$ bundler-audit check /path/to/project
```

Check a custom `Gemfile.lock` file:

```
$ bundler-audit check --gemfile-lock Gemfile.custom.lock
```

Output in JSON format:

```
$ bundler-audit check --format json
```

Output to a file:

```
$ bundler-audit check --format json --output audit-results.json
```

## Commands

| Command    | Description                                              |
|------------|----------------------------------------------------------|
| `check`    | Check `Gemfile.lock` for insecure dependencies (default) |
| `update`   | Update the ruby-advisory-db                              |
| `download` | Download the ruby-advisory-db                            |
| `stats`    | Print ruby-advisory-db statistics                        |
| `version`  | Print the bundler-audit version                          |

Running `bundler-audit` with no subcommand is equivalent to `bundler-audit check`.

## Check Options

| Flag                        | Description                                |
|-----------------------------|--------------------------------------------|
| `-q`, `--quiet`             | Suppress output                            |
| `-v`, `--verbose`           | Show detailed advisory descriptions        |
| `-i`, `--ignore <IDS>...`   | Advisory IDs to ignore                     |
| `-u`, `--update`            | Update the advisory database before check  |
| `-D`, `--database <PATH>`   | Path to the advisory database              |
| `-F`, `--format <FORMAT>`   | Output format: `text` (default) or `json`  |
| `-G`, `--gemfile-lock <FILE>` | Path to the Gemfile.lock file            |
| `-c`, `--config <FILE>`     | Configuration file (default: `.bundler-audit.yml`) |
| `-o`, `--output <FILE>`     | Write output to a file instead of stdout   |

## Configuration File

bundler-audit supports a per-project configuration file (`.bundler-audit.yml`):

```yaml
---
ignore:
  - CVE-2020-1234
  - GHSA-xxxx-yyyy-zzzz
```

* `ignore:` \[Array\<String\>\] - Advisory IDs to ignore (CVE, GHSA, or OSVDB).

You can specify a custom config file path:

```
$ bundler-audit check --config custom-audit.yml
```

CLI `--ignore` flags take precedence over the configuration file.

## Compatibility

This is a compatible reimplementation of [bundler-audit] v0.9.x in Rust.
It uses the same [ruby-advisory-db] and produces equivalent output.

Key differences from the Ruby version:

* Single static binary -- no Ruby runtime required.
* Uses [libgit2] (via the `git2` crate) instead of shelling out to `git`.
* No Rake task integration (not applicable outside Ruby projects).
* No JUnit output format (text and JSON only).

## Architecture

```
src/
  version/          # RubyGems version parsing and comparison
    gem_version.rs  # Gem::Version semantics (segments, ordering, bump)
    requirement.rs  # Gem::Requirement with all 7 operators (=, !=, >, <, >=, <=, ~>)
  lockfile/         # Gemfile.lock parser
    parser.rs       # State-machine parser with indentation tracking
  advisory/         # Advisory database
    model.rs        # Advisory YAML deserialization, vulnerability checking, CVSS
    database.rs     # Database clone/update via git2, advisory enumeration
  scanner.rs        # Ties lockfile + database; source & spec scanning
  configuration.rs  # .bundler-audit.yml loading and validation
  format/           # Output formatters
    text.rs         # Human-readable text with ANSI colors
    json.rs         # JSON output with serde_json
  main.rs           # CLI (clap)
```

## License

Copyright (c) 2026 Zac

bundler-audit-rs is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

bundler-audit-rs is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with bundler-audit-rs. If not, see <https://www.gnu.org/licenses/>.

[Bundler]: https://bundler.io
[bundler-audit]: https://github.com/rubysec/bundler-audit
[ruby-advisory-db]: https://github.com/rubysec/ruby-advisory-db
[libgit2]: https://libgit2.org
