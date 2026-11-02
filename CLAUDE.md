# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

gem-audit is a Rust (edition 2024) reimplementation of Ruby's bundler-audit: it scans a `Gemfile.lock` against the [ruby-advisory-db] without needing Ruby, Bundler or a system git.

## Commands

CI (`.github/workflows/ci.yml`) runs all of these; a PR must pass each one:

```sh
cargo fmt --all -- --check
cargo clippy -- -D warnings
cargo test                         # also runs on macOS and Windows in CI
cargo audit                        # dependency CVEs
cargo llvm-cov                     # coverage (the project is at 100% line coverage)
cargo mutants --in-diff pr.diff    # PRs only; pr.diff = git diff origin/main...HEAD
```

- One test: `cargo test <name_substring>`; only the CLI integration tests: `cargo test --test cli <name>`.
- Benchmarks against bundler-audit: `./benchmarks/bench.sh` (needs hyperfine).

## Testing conventions

- **Mutation testing is enforced on changed lines**: every mutant cargo-mutants generates on a line a PR touches must be killed by a test. Settings and the documented exclusions/known survivors are in `.cargo/mutants.toml`.
- Unit tests live in `#[cfg(test)] mod tests` at the bottom of each source file. End-to-end tests are in `tests/cli.rs` and drive the binary with `assert_cmd`.
- Fixtures are in `tests/fixtures/`: one directory per scenario holding a `Gemfile.lock` (and sometimes a `.gem-audit.yml`), plus `mock_db/`, a fake advisory database. Tests point at it with `--database` or the `GEM_AUDIT_DB` env var, so they never touch the network.
- Tests that need a real git-backed DB build one locally (`init_git_db` in `tests/cli.rs`) and use `GEM_AUDIT_DB_URL` to "download" from that local origin.

## Architecture

The README's architecture section is out of date; this is the current layout.

`main.rs` is the clap CLI. Running with no subcommand means `check`. `cmd_check` is the pipeline:

1. Load the config (`configuration.rs`): `.gem-audit.yml`, falling back to the legacy `.bundler-audit.yml`.
2. Resolve the DB path (`--database` > `GEM_AUDIT_DB` > `~/.local/share/ruby-advisory-db`), then `ensure_database` downloads or updates it through `advisory::Database`, which uses gix with no system git.
3. Check DB staleness (`check.rs`).
4. Run `Scanner::new(lockfile, db).scan(&ScanOptions)` (`scanner/`), which produces a `Report` covering insecure sources, unpatched gems and a vulnerable Ruby version. Ignore lists and the `--severity` filter are applied in `ScanOptions::should_report`. CLI `--ignore` replaces the config's ignore list; the two are not merged.
5. If `--fix` is set, `fixer::resolve_fixes(report.remediations())` picks a version per gem, and `patch_lockfile` rewrites spec lines in the lockfile text.
6. Format the output (`format/text.rs` or `format/json.rs`). Color is used only when stdout is a TTY and `--output` is not set.
7. Exit with a semantic code (constants in `main.rs`). Precedence: vulnerable → 1, strict-mode parse/load errors → 2, stale DB with `--fail-on-stale` → 3, otherwise 0.

Supporting modules:

- `version/`: exact RubyGems semantics. `gem_version.rs` covers `Gem::Version` segment ordering and prerelease rules. `requirement.rs` covers `Gem::Requirement` with all 7 operators, including `~>`. Advisory matching correctness depends on this module.
- `lockfile/`: an indentation-tracking state-machine parser for `Gemfile.lock` (GEM/GIT/PATH sources, specs with platform suffixes, and the `RUBY VERSION` section).
- `advisory/`: `model.rs` deserializes advisory YAML and computes `patched`/`unaffected`/`vulnerable` and CVSS criticality. `database.rs` handles clone, fetch, checkout, and enumerating the `gems/` and `rubies/` advisory directories.
- `scanner/network.rs`: decides whether a source is insecure (`http://`, `git://`). Internal or private hosts are exempt.

Behavior to be aware of: `--fix` **writes** the patched `Gemfile.lock` (atomically, via `write_atomically`) unless `--dry-run` is also passed.

## Environment variables

- `GEM_AUDIT_DB`: advisory DB path.
- `GEM_AUDIT_DB_URL`: clone URL. It is used only when the DB doesn't exist yet; an existing DB always fetches from its own `origin`.

[ruby-advisory-db]: https://github.com/rubysec/ruby-advisory-db
