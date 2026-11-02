use std::collections::{HashMap, HashSet};
use std::time::SystemTime;

use crate::advisory::Database;
use crate::scanner::Report;

/// Age after which a stale database is warned about when no limit is configured.
pub const DEFAULT_MAX_DB_AGE_DAYS: u64 = 7;

/// Check whether the advisory database is stale, warning on stderr if so.
///
/// Without a configured maximum age, a database older than
/// [`DEFAULT_MAX_DB_AGE_DAYS`] is only warned about: this returns `true`
/// (which `--fail-on-stale` acts on) only for an explicitly configured limit.
pub fn check_staleness(
    db: &Database,
    max_db_age: Option<u64>,
    config_max_age: Option<u64>,
) -> bool {
    let configured = max_db_age.or(config_max_age);
    let max_days = configured.unwrap_or(DEFAULT_MAX_DB_AGE_DAYS);
    if let Some(last_updated) = db.last_updated_at() {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let age_days = (now - last_updated) / 86400;
        if age_days > max_days as i64 {
            eprintln!(
                "warning: advisory database is {} days old (max: {} days); run `gem-audit update` or pass --update",
                age_days, max_days
            );
            return configured.is_some();
        }
    }
    false
}

/// Build the set of advisory IDs and their human-readable comments from a scan report.
///
/// Returns a tuple of (advisory IDs, comments map) suitable for writing to a config file.
pub fn build_ignore_comments(report: &Report) -> (HashSet<String>, HashMap<String, String>) {
    let gem_entries = report.unpatched_gems.iter().map(|gem| {
        let criticality = gem
            .advisory
            .criticality()
            .map(|c| c.to_string())
            .unwrap_or_else(|| "Unknown".to_string());
        let title = gem.advisory.title.as_deref().unwrap_or("N/A");
        let comment = format!("{} {} ({}) - {}", gem.name, gem.version, criticality, title);
        (gem.advisory.identifiers(), comment)
    });

    let ruby_entries = report.vulnerable_rubies.iter().map(|ruby| {
        let criticality = ruby
            .advisory
            .criticality()
            .map(|c| c.to_string())
            .unwrap_or_else(|| "Unknown".to_string());
        let title = ruby.advisory.title.as_deref().unwrap_or("N/A");
        let comment = format!(
            "{} {} ({}) - {}",
            ruby.engine, ruby.version, criticality, title
        );
        (ruby.advisory.identifiers(), comment)
    });

    gem_entries.chain(ruby_entries).fold(
        (HashSet::new(), HashMap::new()),
        |(mut ids, mut comments), (identifiers, comment)| {
            for id in identifiers {
                comments
                    .entry(id.clone())
                    .or_insert_with(|| comment.clone());
                ids.insert(id);
            }
            (ids, comments)
        },
    )
}

/// Whether the report has findings an ignore list cannot silence: insecure
/// sources, and advisories with no CVE/GHSA/OSVDB identifier to list.
pub fn has_unignorable_findings(report: &Report) -> bool {
    !report.insecure_sources.is_empty()
        || report
            .unpatched_gems
            .iter()
            .any(|gem| gem.advisory.identifiers().is_empty())
        || report
            .vulnerable_rubies
            .iter()
            .any(|ruby| ruby.advisory.identifiers().is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::advisory::Advisory;
    use crate::scanner::{InsecureSource, Report, UnpatchedGem, VulnerableRuby};
    use std::path::Path;

    fn empty_report() -> Report {
        Report {
            insecure_sources: vec![],
            unpatched_gems: vec![],
            vulnerable_rubies: vec![],
            version_parse_errors: 0,
            advisory_load_errors: 0,
        }
    }

    // ========== has_unignorable_findings ==========

    fn advisory(yaml: &str) -> Advisory {
        Advisory::from_yaml(yaml, Path::new("GHSA-xxxx-yyyy-zzzz.yml")).unwrap()
    }

    fn gem_report(advisory: Advisory) -> Report {
        Report {
            unpatched_gems: vec![UnpatchedGem {
                name: "test".to_string(),
                version: "0.5.0".to_string(),
                advisory,
            }],
            ..empty_report()
        }
    }

    fn ruby_report(advisory: Advisory) -> Report {
        Report {
            vulnerable_rubies: vec![VulnerableRuby {
                engine: "ruby".to_string(),
                version: "2.6.0".to_string(),
                advisory,
            }],
            ..empty_report()
        }
    }

    const NO_ID: &str = "---\ngem: test\npatched_versions:\n  - \">= 1.0\"\n";
    const WITH_ID: &str = "---\ngem: test\ncve: 2020-1234\npatched_versions:\n  - \">= 1.0\"\n";

    #[test]
    fn unignorable_false_for_empty_report() {
        assert!(!has_unignorable_findings(&empty_report()));
    }

    #[test]
    fn unignorable_true_for_insecure_source() {
        let report = Report {
            insecure_sources: vec![InsecureSource {
                source: "http://rubygems.org/".to_string(),
            }],
            ..empty_report()
        };
        assert!(has_unignorable_findings(&report));
    }

    #[test]
    fn unignorable_depends_on_gem_advisory_identifiers() {
        assert!(has_unignorable_findings(&gem_report(advisory(NO_ID))));
        assert!(!has_unignorable_findings(&gem_report(advisory(WITH_ID))));
    }

    #[test]
    fn unignorable_depends_on_ruby_advisory_identifiers() {
        assert!(has_unignorable_findings(&ruby_report(advisory(NO_ID))));
        assert!(!has_unignorable_findings(&ruby_report(advisory(WITH_ID))));
    }

    // ========== build_ignore_comments ==========

    #[test]
    fn build_ignore_comments_empty_report() {
        let report = empty_report();
        let (ids, comments) = build_ignore_comments(&report);
        assert!(ids.is_empty());
        assert!(comments.is_empty());
    }

    #[test]
    fn build_ignore_comments_with_gem_vuln() {
        let yaml = "---\ngem: test\ncve: 2020-1234\ntitle: Test vuln\ncvss_v3: 9.8\npatched_versions:\n  - \">= 1.0.0\"\n";
        let advisory = Advisory::from_yaml(yaml, Path::new("CVE-2020-1234.yml")).unwrap();
        let report = Report {
            unpatched_gems: vec![UnpatchedGem {
                name: "test".to_string(),
                version: "0.5.0".to_string(),
                advisory,
            }],
            ..empty_report()
        };

        let (ids, comments) = build_ignore_comments(&report);
        assert!(ids.contains("CVE-2020-1234"));
        let comment = comments.get("CVE-2020-1234").unwrap();
        assert!(comment.contains("test"));
        assert!(comment.contains("0.5.0"));
        assert!(comment.contains("critical"));
        assert!(comment.contains("Test vuln"));
    }

    #[test]
    fn build_ignore_comments_with_ruby_vuln() {
        let yaml = "---\nengine: ruby\ncve: 2021-31810\ntitle: Ruby vuln\ncvss_v3: 5.9\npatched_versions:\n  - \">= 3.0.2\"\n";
        let advisory = Advisory::from_yaml(yaml, Path::new("CVE-2021-31810.yml")).unwrap();
        let report = Report {
            vulnerable_rubies: vec![VulnerableRuby {
                engine: "ruby".to_string(),
                version: "2.6.0".to_string(),
                advisory,
            }],
            ..empty_report()
        };

        let (ids, comments) = build_ignore_comments(&report);
        assert!(ids.contains("CVE-2021-31810"));
        let comment = comments.get("CVE-2021-31810").unwrap();
        assert!(comment.contains("ruby"));
        assert!(comment.contains("2.6.0"));
    }

    #[test]
    fn build_ignore_comments_includes_insecure_sources_only_in_report() {
        let report = Report {
            insecure_sources: vec![InsecureSource {
                source: "http://rubygems.org/".to_string(),
            }],
            ..empty_report()
        };

        // Insecure sources don't produce advisory IDs
        let (ids, comments) = build_ignore_comments(&report);
        assert!(ids.is_empty());
        assert!(comments.is_empty());
    }

    #[test]
    fn build_ignore_comments_deduplicates_ids() {
        let yaml1 = "---\ngem: test\ncve: 2020-1234\ntitle: First\ncvss_v3: 9.8\npatched_versions:\n  - \">= 1.0.0\"\n";
        let yaml2 = "---\ngem: test\ncve: 2020-1234\ntitle: Duplicate\ncvss_v3: 9.8\npatched_versions:\n  - \">= 1.0.0\"\n";
        let adv1 = Advisory::from_yaml(yaml1, Path::new("CVE-2020-1234.yml")).unwrap();
        let adv2 = Advisory::from_yaml(yaml2, Path::new("CVE-2020-1234.yml")).unwrap();
        let report = Report {
            unpatched_gems: vec![
                UnpatchedGem {
                    name: "test".to_string(),
                    version: "0.5.0".to_string(),
                    advisory: adv1,
                },
                UnpatchedGem {
                    name: "test".to_string(),
                    version: "0.5.0".to_string(),
                    advisory: adv2,
                },
            ],
            ..empty_report()
        };

        let (ids, _) = build_ignore_comments(&report);
        // Should have exactly 1 entry despite 2 vulns with same CVE
        assert_eq!(ids.len(), 1);
        assert!(ids.contains("CVE-2020-1234"));
    }
}
