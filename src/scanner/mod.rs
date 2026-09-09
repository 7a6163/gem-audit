mod network;
mod report;

pub use network::{is_insecure_uri, is_internal_source};
pub use report::{InsecureSource, Remediation, Report, ScanResult, UnpatchedGem, VulnerableRuby};

use std::collections::HashSet;
use std::path::Path;
use thiserror::Error;

use crate::advisory::{Advisory, Criticality, Database, DatabaseError};
use crate::lockfile::{self, Lockfile, Source};
use crate::version::Version;

/// Scanner configuration options.
#[derive(Debug, Default)]
pub struct ScanOptions {
    /// Advisory IDs to ignore (e.g., "CVE-2020-1234", "GHSA-aaaa-bbbb-cccc").
    pub ignore: HashSet<String>,
    /// Minimum severity threshold: only report advisories at or above this level.
    pub severity: Option<Criticality>,
    /// Treat parse/load warnings as significant (tracked in report error counters).
    pub strict: bool,
}

impl ScanOptions {
    /// Check whether an advisory should be reported based on ignore list and severity threshold.
    fn should_report(&self, advisory: &Advisory) -> bool {
        if !self.ignore.is_empty() {
            let identifiers: HashSet<String> = advisory.identifiers().into_iter().collect();
            if !self.ignore.is_disjoint(&identifiers) {
                return false;
            }
        }
        if let Some(threshold) = &self.severity {
            match advisory.criticality() {
                Some(crit) if crit >= *threshold => {}
                _ => return false,
            }
        }
        true
    }
}

#[derive(Debug, Error)]
pub enum ScanError {
    #[error("Gemfile.lock not found: {0}")]
    LockfileNotFound(String),
    #[error("failed to parse Gemfile.lock: {0}")]
    LockfileParse(String),
    #[error("database error: {0}")]
    Database(#[from] DatabaseError),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

/// The main scanner that audits a Gemfile.lock for security issues.
pub struct Scanner {
    lockfile: Lockfile,
    database: Database,
    /// The raw lockfile text, so callers can patch it without re-reading.
    source: Option<String>,
}

impl Scanner {
    /// Create a new scanner from a lockfile path and database.
    pub fn new(lockfile_path: &Path, database: Database) -> Result<Self, ScanError> {
        let content = std::fs::read_to_string(lockfile_path)
            .map_err(|_| ScanError::LockfileNotFound(lockfile_path.display().to_string()))?;

        let lockfile =
            lockfile::parse(&content).map_err(|e| ScanError::LockfileParse(e.to_string()))?;

        Ok(Scanner {
            lockfile,
            database,
            source: Some(content),
        })
    }

    /// Create a scanner from an already-parsed lockfile and database.
    pub fn from_lockfile(lockfile: Lockfile, database: Database) -> Self {
        Scanner {
            lockfile,
            database,
            source: None,
        }
    }

    /// The raw lockfile text, when the scanner read it from disk.
    pub fn source(&self) -> Option<&str> {
        self.source.as_deref()
    }

    /// Run a full scan and produce a report.
    pub fn scan(&self, options: &ScanOptions) -> Report {
        let insecure_sources = self.scan_sources();
        let (unpatched_gems, version_parse_errors, advisory_load_errors) = self.scan_specs(options);
        let (vulnerable_rubies, ruby_advisory_errors) = self.scan_ruby(options);

        Report {
            insecure_sources,
            unpatched_gems,
            vulnerable_rubies,
            version_parse_errors,
            advisory_load_errors: advisory_load_errors + ruby_advisory_errors,
        }
    }

    /// Scan gem sources for insecure protocols (`git://`, `http://`).
    pub fn scan_sources(&self) -> Vec<InsecureSource> {
        let mut results = Vec::new();

        for source in &self.lockfile.sources {
            match source {
                Source::Git(git) => {
                    if is_insecure_uri(&git.remote) && !is_internal_source(&git.remote) {
                        results.push(InsecureSource {
                            source: git.remote.clone(),
                        });
                    }
                }
                Source::Rubygems(gem) => {
                    if gem.remote.starts_with("http://") && !is_internal_source(&gem.remote) {
                        results.push(InsecureSource {
                            source: gem.remote.clone(),
                        });
                    }
                }
                Source::Path(_) => {
                    // Local paths are always considered safe
                }
            }
        }

        results
    }

    /// Scan gem specs against the advisory database.
    ///
    /// Returns `(unpatched_gems, version_parse_errors, advisory_load_errors)`.
    pub fn scan_specs(&self, options: &ScanOptions) -> (Vec<UnpatchedGem>, usize, usize) {
        let mut results = Vec::new();
        let mut version_parse_errors: usize = 0;
        let mut advisory_load_errors: usize = 0;

        // Deduplicate: only check each gem name+version once (skip platform variants)
        let mut seen = HashSet::new();

        for spec in &self.lockfile.specs {
            let key = (&spec.name, &spec.version);
            if !seen.insert(key) {
                continue;
            }

            let version = match Version::parse(&spec.version) {
                Ok(v) => v,
                Err(_) => {
                    version_parse_errors += 1;
                    if options.strict {
                        eprintln!(
                            "warning: failed to parse version '{}' for gem '{}'",
                            spec.version, spec.name
                        );
                    }
                    continue;
                }
            };

            let (advisories, load_errors) = self.database.check_gem(&spec.name, &version);
            advisory_load_errors += load_errors;

            for advisory in advisories {
                if !options.should_report(&advisory) {
                    continue;
                }

                results.push(UnpatchedGem {
                    name: spec.name.clone(),
                    version: spec.version.clone(),
                    advisory,
                });
            }
        }

        // Sort by criticality descending (Critical first, None/Unknown last)
        results.sort_by_key(|r| std::cmp::Reverse(r.advisory.criticality()));

        (results, version_parse_errors, advisory_load_errors)
    }

    /// Scan the Ruby interpreter version against the advisory database.
    ///
    /// Returns `(vulnerable_rubies, advisory_load_errors)`.
    pub fn scan_ruby(&self, options: &ScanOptions) -> (Vec<VulnerableRuby>, usize) {
        let ruby_version = match self.lockfile.parsed_ruby_version() {
            Some(rv) => rv,
            None => return (Vec::new(), 0),
        };

        let version = match Version::parse(&ruby_version.version) {
            Ok(v) => v,
            Err(_) => return (Vec::new(), 0),
        };

        let (advisories, load_errors) = self.database.check_ruby(&ruby_version.engine, &version);

        let mut results = Vec::new();
        for advisory in advisories {
            if !options.should_report(&advisory) {
                continue;
            }

            results.push(VulnerableRuby {
                engine: ruby_version.engine.clone(),
                version: ruby_version.version.clone(),
                advisory,
            });
        }

        // Sort by criticality descending
        results.sort_by_key(|r| std::cmp::Reverse(r.advisory.criticality()));

        (results, load_errors)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn fixtures_dir() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
    }

    fn mock_database() -> Database {
        Database::open(&fixtures_dir().join("mock_db")).unwrap()
    }

    // ========== Source Scanning ==========

    #[test]
    fn scan_secure_sources() {
        let input = include_str!("../../tests/fixtures/secure/Gemfile.lock");
        let lockfile = lockfile::parse(input).unwrap();
        let db = mock_database();
        let scanner = Scanner::from_lockfile(lockfile, db);

        let insecure = scanner.scan_sources();
        assert!(
            insecure.is_empty(),
            "secure lockfile should have no insecure sources"
        );
    }

    #[test]
    fn scan_insecure_sources() {
        let input = include_str!("../../tests/fixtures/insecure_sources/Gemfile.lock");
        let lockfile = lockfile::parse(input).unwrap();
        let db = mock_database();
        let scanner = Scanner::from_lockfile(lockfile, db);

        let insecure = scanner.scan_sources();
        assert_eq!(insecure.len(), 2);

        let sources: Vec<&str> = insecure.iter().map(|s| s.source.as_str()).collect();
        assert!(sources.contains(&"git://github.com/rails/jquery-rails.git"));
        assert!(sources.contains(&"http://rubygems.org/"));
    }

    // ========== Spec Scanning (with mock DB) ==========

    #[test]
    fn scan_specs_with_mock_db() {
        let input = include_str!("../../tests/fixtures/secure/Gemfile.lock");
        let lockfile = lockfile::parse(input).unwrap();
        let db = mock_database();
        let scanner = Scanner::from_lockfile(lockfile, db);

        let opts = ScanOptions::default();
        let (vulns, _, _) = scanner.scan_specs(&opts);
        assert!(vulns.is_empty());
    }

    // ========== Full Scan ==========

    #[test]
    fn scan_reports_unpatched_gem() {
        let input = include_str!("../../tests/fixtures/vulnerable_gem/Gemfile.lock");
        let lockfile = lockfile::parse(input).unwrap();
        let scanner = Scanner::from_lockfile(lockfile, mock_database());

        let report = scanner.scan(&ScanOptions::default());

        assert_eq!(report.unpatched_gems.len(), 1);
        assert_eq!(report.unpatched_gems[0].name, "test");
        assert_eq!(report.unpatched_gems[0].version, "0.5.0");
    }

    #[test]
    fn scan_with_ignore_list() {
        let input = include_str!("../../tests/fixtures/vulnerable_gem/Gemfile.lock");
        let lockfile = lockfile::parse(input).unwrap();
        let scanner = Scanner::from_lockfile(lockfile, mock_database());

        let (all_vulns, _, _) = scanner.scan_specs(&ScanOptions::default());
        assert_eq!(all_vulns.len(), 1);

        let ignore: HashSet<String> = all_vulns[0].advisory.identifiers().into_iter().collect();
        let (filtered_vulns, _, _) = scanner.scan_specs(&ScanOptions {
            ignore,
            ..Default::default()
        });
        assert!(filtered_vulns.is_empty());
    }

    // ========== ScanError Display ==========

    #[test]
    fn scan_error_lockfile_not_found_display() {
        let err = ScanError::LockfileNotFound("/tmp/missing".to_string());
        assert!(err.to_string().contains("Gemfile.lock not found"));
        assert!(err.to_string().contains("/tmp/missing"));
    }

    #[test]
    fn scan_error_lockfile_parse_display() {
        let err = ScanError::LockfileParse("bad content".to_string());
        assert!(err.to_string().contains("failed to parse Gemfile.lock"));
    }

    #[test]
    fn scan_error_io_display() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
        let err = ScanError::Io(io_err);
        assert!(err.to_string().contains("IO error"));
    }

    // ========== Version parse error tracking ==========

    #[test]
    fn scan_specs_tracks_version_parse_errors() {
        let input = "\
GEM
  remote: https://rubygems.org/
  specs:
    badgem (!!!invalid!!!)

PLATFORMS
  ruby

DEPENDENCIES
  badgem
";
        let lockfile = lockfile::parse(input).unwrap();
        let db = mock_database();
        let scanner = Scanner::from_lockfile(lockfile, db);

        let opts = ScanOptions::default();
        let (_, version_parse_errors, _) = scanner.scan_specs(&opts);
        assert!(
            version_parse_errors > 0,
            "expected version parse errors for invalid version"
        );
    }

    #[test]
    fn scan_specs_strict_mode_prints_warning() {
        let input = "\
GEM
  remote: https://rubygems.org/
  specs:
    badgem (!!!invalid!!!)

PLATFORMS
  ruby

DEPENDENCIES
  badgem
";
        let lockfile = lockfile::parse(input).unwrap();
        let db = mock_database();
        let scanner = Scanner::from_lockfile(lockfile, db);

        let opts = ScanOptions {
            strict: true,
            ..Default::default()
        };
        let (results, version_parse_errors, advisory_load_errors) = scanner.scan_specs(&opts);
        assert_eq!(version_parse_errors, 1);
        assert_eq!(advisory_load_errors, 0);
        assert!(results.is_empty());
    }

    #[test]
    fn scan_sources_accepts_a_secure_git_remote() {
        let input = "\
GIT
  remote: https://github.com/rails/jquery-rails.git
  revision: abc123
  specs:
    jquery-rails (4.4.0)

PLATFORMS
  ruby

DEPENDENCIES
  jquery-rails!
";
        let lockfile = lockfile::parse(input).unwrap();
        let scanner = Scanner::from_lockfile(lockfile, mock_database());
        assert!(scanner.scan_sources().is_empty());
    }

    // ========== Path source scanning ==========

    #[test]
    fn scan_path_source_is_safe() {
        let input = "\
PATH
  remote: .
  specs:
    my_gem (0.1.0)

GEM
  remote: https://rubygems.org/
  specs:
    rack (2.0.0)

PLATFORMS
  ruby

DEPENDENCIES
  my_gem!
  rack
";
        let lockfile = lockfile::parse(input).unwrap();
        let db = mock_database();
        let scanner = Scanner::from_lockfile(lockfile, db);

        let insecure = scanner.scan_sources();
        assert!(insecure.is_empty(), "PATH sources should be safe");
    }

    // ========== Ruby Version Scanning ==========

    #[test]
    fn scan_ruby_detects_vulnerable_version() {
        let input = include_str!("../../tests/fixtures/vulnerable_ruby/Gemfile.lock");
        let lockfile = lockfile::parse(input).unwrap();
        let db = mock_database();
        let scanner = Scanner::from_lockfile(lockfile, db);

        let opts = ScanOptions::default();
        let (vulns, _) = scanner.scan_ruby(&opts);
        assert_eq!(vulns.len(), 1);
        assert_eq!(vulns[0].engine, "ruby");
        assert_eq!(vulns[0].version, "2.6.0");
        assert_eq!(vulns[0].advisory.id, "CVE-2021-31810");
    }

    #[test]
    fn scan_ruby_no_ruby_version_section() {
        let input = include_str!("../../tests/fixtures/secure/Gemfile.lock");
        let lockfile = lockfile::parse(input).unwrap();
        let db = mock_database();
        let scanner = Scanner::from_lockfile(lockfile, db);

        let opts = ScanOptions::default();
        let (vulns, _) = scanner.scan_ruby(&opts);
        assert!(vulns.is_empty());
    }

    #[test]
    fn scan_ruby_respects_ignore_list() {
        let input = include_str!("../../tests/fixtures/vulnerable_ruby/Gemfile.lock");
        let lockfile = lockfile::parse(input).unwrap();
        let db = mock_database();
        let scanner = Scanner::from_lockfile(lockfile, db);

        let mut ignore = HashSet::new();
        ignore.insert("CVE-2021-31810".to_string());
        let opts = ScanOptions {
            ignore,
            ..Default::default()
        };
        let (vulns, _) = scanner.scan_ruby(&opts);
        assert!(vulns.is_empty());
    }

    #[test]
    fn scan_ruby_respects_severity_filter() {
        let input = include_str!("../../tests/fixtures/vulnerable_ruby/Gemfile.lock");
        let lockfile = lockfile::parse(input).unwrap();
        let db = mock_database();
        let scanner = Scanner::from_lockfile(lockfile, db);

        let opts = ScanOptions {
            severity: Some(Criticality::High),
            ..Default::default()
        };
        let (vulns, _) = scanner.scan_ruby(&opts);
        assert!(vulns.is_empty());
    }

    #[test]
    fn scan_full_includes_ruby_vulnerabilities() {
        let input = include_str!("../../tests/fixtures/vulnerable_ruby/Gemfile.lock");
        let lockfile = lockfile::parse(input).unwrap();
        let db = mock_database();
        let scanner = Scanner::from_lockfile(lockfile, db);

        let opts = ScanOptions::default();
        let report = scanner.scan(&opts);
        assert!(report.vulnerable());
        assert_eq!(report.vulnerable_rubies.len(), 1);
    }

    #[test]
    fn scan_ruby_severity_threshold_met() {
        let input = include_str!("../../tests/fixtures/vulnerable_ruby/Gemfile.lock");
        let lockfile = lockfile::parse(input).unwrap();
        let db = mock_database();
        let scanner = Scanner::from_lockfile(lockfile, db);

        let opts = ScanOptions {
            severity: Some(Criticality::Medium),
            ..Default::default()
        };
        let (vulns, _) = scanner.scan_ruby(&opts);
        assert_eq!(vulns.len(), 1);
    }

    #[test]
    fn scan_ruby_unparseable_version() {
        let input = "\
GEM
  remote: https://rubygems.org/
  specs:
    rack (2.0.0)

PLATFORMS
  ruby

DEPENDENCIES
  rack

RUBY VERSION
   ruby !!!invalid!!!
";
        let lockfile = lockfile::parse(input).unwrap();
        let db = mock_database();
        let scanner = Scanner::from_lockfile(lockfile, db);

        let opts = ScanOptions::default();
        let (vulns, _) = scanner.scan_ruby(&opts);
        assert!(vulns.is_empty());
    }

    #[test]
    fn should_report_ignore_nonmatching() {
        let mut ignore = HashSet::new();
        ignore.insert("CVE-9999-0000".to_string());
        let opts = ScanOptions {
            ignore,
            ..Default::default()
        };
        let yaml =
            "---\ngem: test\ncve: 2020-1234\ncvss_v3: 9.0\npatched_versions:\n  - \">= 1.0\"\n";
        let advisory =
            crate::advisory::Advisory::from_yaml(yaml, Path::new("CVE-2020-1234.yml")).unwrap();
        assert!(opts.should_report(&advisory));
    }

    #[test]
    fn report_count_includes_ruby_vulns() {
        let input = include_str!("../../tests/fixtures/vulnerable_ruby/Gemfile.lock");
        let lockfile = lockfile::parse(input).unwrap();
        let db = mock_database();
        let scanner = Scanner::from_lockfile(lockfile, db);

        let opts = ScanOptions::default();
        let report = scanner.scan(&opts);
        assert!(report.count() >= 1);
    }

    #[test]
    fn scan_sums_gem_and_ruby_advisory_load_errors() {
        // A database where both the gem and the Ruby advisory fail to parse.
        let tmp = tempfile::tempdir().unwrap();
        for (kind, name) in [("gems", "test"), ("rubies", "ruby")] {
            let dir = tmp.path().join(kind).join(name);
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join("broken.yml"), "gem: [unclosed\n").unwrap();
        }

        let input = "\
GEM
  remote: https://rubygems.org/
  specs:
    test (0.5.0)

RUBY VERSION
   ruby 2.6.0
";
        let lockfile = lockfile::parse(input).unwrap();
        let scanner = Scanner::from_lockfile(lockfile, Database::open(tmp.path()).unwrap());

        let report = scanner.scan(&ScanOptions::default());
        assert_eq!(report.advisory_load_errors, 2);
        assert_eq!(report.version_parse_errors, 0);
        assert!(!report.vulnerable());
    }
}
