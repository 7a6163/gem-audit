#![allow(deprecated)] // Command::cargo_bin — replacement macro is unstable

use std::path::{Path, PathBuf};

use assert_cmd::Command;
use predicates::prelude::*;

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

fn mock_db() -> PathBuf {
    fixtures_dir().join("mock_db")
}

fn vulnerable_lock() -> PathBuf {
    fixtures_dir().join("vulnerable_gem/Gemfile.lock")
}

fn secure_lock() -> PathBuf {
    fixtures_dir().join("secure/Gemfile.lock")
}

/// A path nested *inside* a regular file, so creating or opening anything at
/// it fails on every platform.
fn unwritable_path(tmp: &tempfile::TempDir) -> PathBuf {
    let file = tmp.path().join("not-a-directory");
    std::fs::write(&file, b"x").unwrap();
    file.join("child")
}

/// Build a git-backed advisory database at `path` with a single `test` advisory.
///
/// The commit is dated 2020-09-13 so staleness checks always fire.
fn init_git_db(path: &Path) {
    init_git_db_at(path, 1_600_000_000)
}

/// As [`init_git_db`], but with an explicit commit timestamp.
fn init_git_db_at(path: &Path, seconds: i64) {
    const YAML: &str = "---\ngem: test\ncve: 2020-1234\npatched_versions:\n  - \">= 1.0.0\"\n";

    std::fs::create_dir_all(path.join("gems").join("test")).unwrap();
    std::fs::write(
        path.join("gems").join("test").join("CVE-2020-1234.yml"),
        YAML,
    )
    .unwrap();

    let repo = gix::init(path).unwrap();
    let blob = repo.write_blob(YAML.as_bytes()).unwrap().detach();

    let tree = |entries: Vec<(&str, gix::ObjectId, gix::objs::tree::EntryKind)>| {
        let mut t = gix::objs::Tree::empty();
        for (name, oid, kind) in entries {
            t.entries.push(gix::objs::tree::Entry {
                mode: kind.into(),
                filename: name.into(),
                oid,
            });
        }
        t.entries.sort();
        repo.write_object(&t).unwrap().detach()
    };

    let gem = tree(vec![(
        "CVE-2020-1234.yml",
        blob,
        gix::objs::tree::EntryKind::Blob,
    )]);
    let gems = tree(vec![("test", gem, gix::objs::tree::EntryKind::Tree)]);
    let root = tree(vec![("gems", gems, gix::objs::tree::EntryKind::Tree)]);

    let time = format!("{} +0000", seconds);
    let sig = gix::actor::SignatureRef {
        name: "gem-audit tests".into(),
        email: "tests@example.com".into(),
        time: time.as_str(),
    };
    repo.commit_as(
        sig,
        sig,
        "HEAD",
        "advisories",
        root,
        gix::commit::NO_PARENT_IDS,
    )
    .unwrap();
}

/// Clone a local advisory-db repository so the copy has an `origin` to fetch from.
fn copy_git_clone(origin: &Path, dest: &Path) {
    let (mut checkout, _) = gix::prepare_clone(origin.to_str().unwrap(), dest)
        .unwrap()
        .fetch_then_checkout(gix::progress::Discard, &gix::interrupt::IS_INTERRUPTED)
        .unwrap();
    checkout
        .main_worktree(gix::progress::Discard, &gix::interrupt::IS_INTERRUPTED)
        .unwrap();
}

/// A fresh temporary directory that is removed when the test ends.
fn scratch(name: &str) -> tempfile::TempDir {
    tempfile::Builder::new().prefix(name).tempdir().unwrap()
}

// ==================== version ====================

#[test]
fn version_subcommand() {
    Command::cargo_bin("gem-audit")
        .unwrap()
        .arg("version")
        .assert()
        .success()
        .stdout(predicate::str::starts_with("gem-audit "));
}

// ==================== check — secure lockfile ====================

#[test]
fn check_secure_lockfile() {
    Command::cargo_bin("gem-audit")
        .unwrap()
        .args([
            "check",
            "--database",
            mock_db().to_str().unwrap(),
            "--gemfile-lock",
            fixtures_dir().join("secure/Gemfile.lock").to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("No vulnerabilities found"));
}

// ==================== check — insecure sources ====================

#[test]
fn check_insecure_sources() {
    Command::cargo_bin("gem-audit")
        .unwrap()
        .args([
            "check",
            "--database",
            mock_db().to_str().unwrap(),
            "--gemfile-lock",
            fixtures_dir()
                .join("insecure_sources/Gemfile.lock")
                .to_str()
                .unwrap(),
        ])
        .assert()
        .code(1)
        .stdout(predicate::str::contains("Insecure Source URI found"));
}

// ==================== check — unpatched gems ====================

#[test]
fn check_unpatched_gems() {
    Command::cargo_bin("gem-audit")
        .unwrap()
        .args([
            "check",
            "--database",
            mock_db().to_str().unwrap(),
            "--gemfile-lock",
            vulnerable_lock().to_str().unwrap(),
        ])
        .assert()
        .code(1)
        .stdout(
            predicate::str::contains("Vulnerabilities found!")
                .and(predicate::str::contains("CVE-2020-1234")),
        );
}

// ==================== check --quiet ====================

#[test]
fn check_quiet_secure() {
    Command::cargo_bin("gem-audit")
        .unwrap()
        .args([
            "check",
            "--quiet",
            "--database",
            mock_db().to_str().unwrap(),
            "--gemfile-lock",
            fixtures_dir().join("secure/Gemfile.lock").to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::is_empty());
}

// ==================== check --format json ====================

#[test]
fn check_json_secure() {
    let output = Command::cargo_bin("gem-audit")
        .unwrap()
        .args([
            "check",
            "--format",
            "json",
            "--database",
            mock_db().to_str().unwrap(),
            "--gemfile-lock",
            fixtures_dir().join("secure/Gemfile.lock").to_str().unwrap(),
        ])
        .output()
        .unwrap();

    assert!(output.status.success());
    let text = String::from_utf8(output.stdout).unwrap();
    // stdout is a pipe here, so the document must be compact.
    assert_eq!(text.trim_end().lines().count(), 1, "{}", text);
    let parsed: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(parsed["results"].as_array().unwrap().len(), 0);
}

#[test]
fn check_json_insecure_sources() {
    let output = Command::cargo_bin("gem-audit")
        .unwrap()
        .args([
            "check",
            "--format",
            "json",
            "--database",
            mock_db().to_str().unwrap(),
            "--gemfile-lock",
            fixtures_dir()
                .join("insecure_sources/Gemfile.lock")
                .to_str()
                .unwrap(),
        ])
        .output()
        .unwrap();

    assert!(!output.status.success());
    let parsed: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let results = parsed["results"].as_array().unwrap();
    assert!(results.iter().any(|r| r["type"] == "insecure_source"));
}

// ==================== check --output <file> ====================

#[test]
fn check_output_to_file() {
    let tmp = std::env::temp_dir().join("gem-audit-cli-test-output.txt");

    // Clean up from prior runs
    let _ = std::fs::remove_file(&tmp);

    Command::cargo_bin("gem-audit")
        .unwrap()
        .args([
            "check",
            "--database",
            mock_db().to_str().unwrap(),
            "--gemfile-lock",
            fixtures_dir().join("secure/Gemfile.lock").to_str().unwrap(),
            "--output",
            tmp.to_str().unwrap(),
        ])
        .assert()
        .success();

    let content = std::fs::read_to_string(&tmp).unwrap();
    assert!(content.contains("No vulnerabilities found"));

    let _ = std::fs::remove_file(&tmp);
}

// ==================== check --ignore ====================

#[test]
fn check_ignore_advisory() {
    Command::cargo_bin("gem-audit")
        .unwrap()
        .args([
            "check",
            "--database",
            mock_db().to_str().unwrap(),
            "--gemfile-lock",
            vulnerable_lock().to_str().unwrap(),
            "--ignore",
            "CVE-2020-1234",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("No vulnerabilities found"));
}

// ==================== check --config ====================

#[test]
fn check_with_config_ignore() {
    let db = mock_db();

    let lockfile = fixtures_dir().join("unpatched_gems_with_config/Gemfile.lock");
    let config = fixtures_dir().join("unpatched_gems_with_config/.gem-audit.yml");

    // Without config: should find vulnerabilities
    Command::cargo_bin("gem-audit")
        .unwrap()
        .args([
            "check",
            "--database",
            db.to_str().unwrap(),
            "--gemfile-lock",
            lockfile.to_str().unwrap(),
        ])
        .assert()
        .failure()
        .stdout(predicate::str::contains("Vulnerabilities found!"));

    // With config: the ignore list suppresses all known CVEs → clean result
    Command::cargo_bin("gem-audit")
        .unwrap()
        .args([
            "check",
            "--database",
            db.to_str().unwrap(),
            "--gemfile-lock",
            lockfile.to_str().unwrap(),
            "--config",
            config.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("No vulnerabilities found"));
}

// ==================== check — missing Gemfile.lock ====================

#[test]
fn check_missing_gemfile_lock() {
    Command::cargo_bin("gem-audit")
        .unwrap()
        .args([
            "check",
            "--database",
            mock_db().to_str().unwrap(),
            "--gemfile-lock",
            "/nonexistent/path/Gemfile.lock",
        ])
        .assert()
        .code(2)
        .stderr(predicate::str::is_empty().not());
}

// ==================== stats ====================

#[test]
fn stats_subcommand() {
    let tmp = scratch("gem-audit-stats");
    let db = tmp.path().to_path_buf();
    init_git_db(&db);

    Command::cargo_bin("gem-audit")
        .unwrap()
        .args(["stats", "--database", db.to_str().unwrap()])
        .assert()
        .success()
        .stdout(
            predicate::str::contains("ruby-advisory-db:")
                .and(predicate::str::contains("advisories:"))
                .and(predicate::str::contains("last updated:"))
                .and(predicate::str::contains("commit:"))
                // No rubies/ directory, so the per-kind breakdown is omitted.
                .and(predicate::str::contains("gems:").not())
                .and(predicate::str::contains("rubies:").not()),
        );
}

#[test]
fn stats_missing_database() {
    Command::cargo_bin("gem-audit")
        .unwrap()
        .args(["stats", "--database", "/nonexistent/advisory-db"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("Failed to open advisory database"));
}

// ==================== update ====================

#[test]
fn update_git_database() {
    let tmp = scratch("gem-audit-update");
    let origin = tmp.path().join("origin");
    init_git_db(&origin);

    // Clone it so the copy has an origin to fetch from.
    let clone = tmp.path().join("clone");
    Command::cargo_bin("gem-audit")
        .unwrap()
        .args(["stats", "--database", origin.to_str().unwrap()])
        .assert()
        .success();
    copy_git_clone(&origin, &clone);

    Command::cargo_bin("gem-audit")
        .unwrap()
        .args(["update", "--database", clone.to_str().unwrap()])
        .assert()
        .success()
        .stderr(
            predicate::str::contains("Updating ruby-advisory-db")
                .and(predicate::str::contains("Updated ruby-advisory-db")),
        );
}

#[test]
fn update_non_git_database_is_skipped() {
    Command::cargo_bin("gem-audit")
        .unwrap()
        .args(["update", "--database", mock_db().to_str().unwrap()])
        .assert()
        .success()
        .stderr(predicate::str::contains(
            "Skipping update, ruby-advisory-db is not a git repository",
        ));
}

#[test]
fn update_quiet_prints_nothing() {
    Command::cargo_bin("gem-audit")
        .unwrap()
        .args([
            "update",
            "--quiet",
            "--database",
            mock_db().to_str().unwrap(),
        ])
        .assert()
        .success()
        .stderr(predicate::str::is_empty())
        .stdout(predicate::str::is_empty());
}

#[test]
fn update_fails_when_origin_is_gone() {
    let tmp = scratch("gem-audit-update-broken");
    let origin = tmp.path().join("origin");
    init_git_db(&origin);
    let clone = tmp.path().join("clone");
    copy_git_clone(&origin, &clone);
    std::fs::remove_dir_all(&origin).unwrap();

    Command::cargo_bin("gem-audit")
        .unwrap()
        .args(["update", "--database", clone.to_str().unwrap()])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("Failed to update"));
}

#[test]
fn update_download_failure_is_reported() {
    let tmp = scratch("gem-audit-update-unwritable");
    let target = unwritable_path(&tmp);

    Command::cargo_bin("gem-audit")
        .unwrap()
        .args(["update", "--database", target.to_str().unwrap()])
        .assert()
        .code(2)
        .stderr(
            predicate::str::contains("Downloading ruby-advisory-db")
                .and(predicate::str::contains("Failed to download")),
        );
}

// ==================== check — nonexistent directory ====================

#[test]
fn check_nonexistent_directory() {
    Command::cargo_bin("gem-audit")
        .unwrap()
        .args([
            "check",
            "/nonexistent/directory/that/does/not/exist",
            "--database",
            mock_db().to_str().unwrap(),
        ])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("No such file or directory"));
}

// ==================== check --fix ====================

#[test]
fn check_fix_text_output() {
    let output = Command::cargo_bin("gem-audit")
        .unwrap()
        .args([
            "check",
            "--fix",
            "--dry-run",
            "--database",
            mock_db().to_str().unwrap(),
            "--gemfile-lock",
            vulnerable_lock().to_str().unwrap(),
        ])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Fixes:"), "{}", stdout);
}

#[test]
fn check_fix_json_output() {
    let output = Command::cargo_bin("gem-audit")
        .unwrap()
        .args([
            "check",
            "--fix",
            "--dry-run",
            "--format",
            "json",
            "--database",
            mock_db().to_str().unwrap(),
            "--gemfile-lock",
            vulnerable_lock().to_str().unwrap(),
        ])
        .output()
        .unwrap();

    let parsed: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let remediations = parsed["remediations"].as_array().unwrap();
    assert!(!remediations.is_empty());
    assert!(remediations[0]["status"].as_str().is_some());
}

#[test]
fn check_fix_rewrites_the_lockfile() {
    let tmp = scratch("gem-audit-fix");
    let lockfile = tmp.path().join("Gemfile.lock");
    std::fs::copy(vulnerable_lock(), &lockfile).unwrap();

    Command::cargo_bin("gem-audit")
        .unwrap()
        .args([
            "check",
            "--fix",
            "--database",
            mock_db().to_str().unwrap(),
            "--gemfile-lock",
            lockfile.to_str().unwrap(),
        ])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("Run `bundle install`"));

    let patched = std::fs::read_to_string(&lockfile).unwrap();
    assert!(!patched.contains("test (0.5.0)"), "{}", patched);
}

// ==================== check --fix on clean project ====================

#[test]
fn check_fix_no_remediation_when_clean() {
    Command::cargo_bin("gem-audit")
        .unwrap()
        .args([
            "check",
            "--fix",
            "--database",
            mock_db().to_str().unwrap(),
            "--gemfile-lock",
            fixtures_dir().join("secure/Gemfile.lock").to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(
            predicate::str::contains("No vulnerabilities found")
                .and(predicate::str::contains("Remediation:").not()),
        );
}

// ==================== check --severity ====================

#[test]
fn check_severity_filter() {
    // CVE-2020-1234 is Critical (9.8), so a `critical` threshold keeps it ...
    Command::cargo_bin("gem-audit")
        .unwrap()
        .args([
            "check",
            "--severity",
            "critical",
            "--database",
            mock_db().to_str().unwrap(),
            "--gemfile-lock",
            vulnerable_lock().to_str().unwrap(),
        ])
        .assert()
        .code(1)
        .stdout(predicate::str::contains("CVE-2020-1234"));
}

// ==================== check — vulnerable Ruby version ====================

#[test]
fn check_vulnerable_ruby_version() {
    Command::cargo_bin("gem-audit")
        .unwrap()
        .args([
            "check",
            "--database",
            mock_db().to_str().unwrap(),
            "--gemfile-lock",
            fixtures_dir()
                .join("vulnerable_ruby/Gemfile.lock")
                .to_str()
                .unwrap(),
        ])
        .assert()
        .code(1)
        .stdout(
            predicate::str::contains("Engine")
                .and(predicate::str::contains("ruby"))
                .and(predicate::str::contains("2.6.0"))
                .and(predicate::str::contains("CVE-2021-31810"))
                .and(predicate::str::contains("vulnerable Ruby version")),
        );
}

#[test]
fn check_vulnerable_ruby_json() {
    let output = Command::cargo_bin("gem-audit")
        .unwrap()
        .args([
            "check",
            "--format",
            "json",
            "--database",
            mock_db().to_str().unwrap(),
            "--gemfile-lock",
            fixtures_dir()
                .join("vulnerable_ruby/Gemfile.lock")
                .to_str()
                .unwrap(),
        ])
        .output()
        .unwrap();

    assert!(!output.status.success());
    let parsed: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let results = parsed["results"].as_array().unwrap();
    assert!(results.iter().any(|r| r["type"] == "vulnerable_ruby"));

    let ruby_result = results
        .iter()
        .find(|r| r["type"] == "vulnerable_ruby")
        .unwrap();
    assert_eq!(ruby_result["ruby"]["engine"], "ruby");
    assert_eq!(ruby_result["ruby"]["version"], "2.6.0");
    assert_eq!(ruby_result["advisory"]["cve"], "CVE-2021-31810");
}

#[test]
fn check_vulnerable_ruby_ignore() {
    Command::cargo_bin("gem-audit")
        .unwrap()
        .args([
            "check",
            "--database",
            mock_db().to_str().unwrap(),
            "--gemfile-lock",
            fixtures_dir()
                .join("vulnerable_ruby/Gemfile.lock")
                .to_str()
                .unwrap(),
            "--ignore",
            "CVE-2021-31810",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("No vulnerabilities found"));
}

#[test]
fn check_vulnerable_ruby_severity_filter() {
    // CVE-2021-31810 is Medium (5.9); filtering for High should exclude it
    Command::cargo_bin("gem-audit")
        .unwrap()
        .args([
            "check",
            "--database",
            mock_db().to_str().unwrap(),
            "--gemfile-lock",
            fixtures_dir()
                .join("vulnerable_ruby/Gemfile.lock")
                .to_str()
                .unwrap(),
            "--severity",
            "high",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("No vulnerabilities found"));
}

// ==================== check --write-ignore ====================

#[test]
fn check_write_ignore_creates_config() {
    let tmp = std::env::temp_dir().join("gem_audit_test_write_ignore");
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).unwrap();

    let config_path = tmp.join(".gem-audit.yml");

    Command::cargo_bin("gem-audit")
        .unwrap()
        .args([
            "check",
            "--write-ignore",
            "--database",
            mock_db().to_str().unwrap(),
            "--gemfile-lock",
            fixtures_dir()
                .join("vulnerable_ruby/Gemfile.lock")
                .to_str()
                .unwrap(),
            "--config",
            config_path.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains("Added 1 advisory ID(s)"));

    // Config file should exist and contain the advisory ID
    let content = std::fs::read_to_string(&config_path).unwrap();
    assert!(content.contains("CVE-2021-31810"));

    std::fs::remove_dir_all(&tmp).unwrap();
}

#[test]
fn check_write_ignore_merges_existing() {
    let tmp = std::env::temp_dir().join("gem_audit_test_write_ignore_merge");
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).unwrap();

    let config_path = tmp.join(".gem-audit.yml");
    // Pre-existing config with an existing ignore entry
    std::fs::write(&config_path, "---\nignore:\n  - CVE-EXISTING-001\n").unwrap();

    Command::cargo_bin("gem-audit")
        .unwrap()
        .args([
            "check",
            "--write-ignore",
            "--database",
            mock_db().to_str().unwrap(),
            "--gemfile-lock",
            fixtures_dir()
                .join("vulnerable_ruby/Gemfile.lock")
                .to_str()
                .unwrap(),
            "--config",
            config_path.to_str().unwrap(),
        ])
        .assert()
        .success()
        // Only the newly discovered ID is counted, not the pre-existing one.
        .stderr(predicate::str::contains("Added 1 advisory ID(s)"));

    let content = std::fs::read_to_string(&config_path).unwrap();
    // Should contain both old and new entries
    assert!(content.contains("CVE-EXISTING-001"));
    assert!(content.contains("CVE-2021-31810"));

    std::fs::remove_dir_all(&tmp).unwrap();
}

#[test]
fn check_write_ignore_no_vulns_no_write() {
    let tmp = std::env::temp_dir().join("gem_audit_test_write_ignore_clean");
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).unwrap();

    let config_path = tmp.join(".gem-audit.yml");

    Command::cargo_bin("gem-audit")
        .unwrap()
        .args([
            "check",
            "--write-ignore",
            "--database",
            mock_db().to_str().unwrap(),
            "--gemfile-lock",
            fixtures_dir().join("secure/Gemfile.lock").to_str().unwrap(),
            "--config",
            config_path.to_str().unwrap(),
        ])
        .assert()
        .success();

    // No vulns → no config file created
    assert!(!config_path.exists());

    std::fs::remove_dir_all(&tmp).unwrap();
}

// ==================== stats with mock DB ====================

#[test]
fn stats_with_mock_db() {
    // The mock_db now has both gems/ and rubies/
    Command::cargo_bin("gem-audit")
        .unwrap()
        .args(["stats", "--database", mock_db().to_str().unwrap()])
        .assert()
        .success()
        .stdout(
            predicate::str::contains("ruby-advisory-db:")
                .and(predicate::str::contains("gems:"))
                .and(predicate::str::contains("rubies:")),
        );
}

// ==================== default subcommand ====================

#[test]
fn no_subcommand_checks_the_current_directory() {
    let tmp = scratch("gem-audit-default");
    std::fs::copy(secure_lock(), tmp.path().join("Gemfile.lock")).unwrap();

    Command::cargo_bin("gem-audit")
        .unwrap()
        .current_dir(tmp.path())
        .env("GEM_AUDIT_DB", mock_db())
        .assert()
        .success()
        .stdout(predicate::str::contains("No vulnerabilities found"));
}

// ==================== check — database handling ====================

#[test]
fn check_download_failure_is_reported() {
    let tmp = scratch("gem-audit-check-unwritable");
    let target = unwritable_path(&tmp);

    Command::cargo_bin("gem-audit")
        .unwrap()
        .args([
            "check",
            "--database",
            target.to_str().unwrap(),
            "--gemfile-lock",
            secure_lock().to_str().unwrap(),
        ])
        .assert()
        .code(2)
        .stderr(predicate::str::contains(
            "Failed to download advisory database",
        ));
}

#[test]
fn check_update_skips_non_git_database() {
    Command::cargo_bin("gem-audit")
        .unwrap()
        .args([
            "check",
            "--update",
            "--database",
            mock_db().to_str().unwrap(),
            "--gemfile-lock",
            secure_lock().to_str().unwrap(),
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains(
            "Skipping update, ruby-advisory-db is not a git repository",
        ));
}

#[test]
fn check_update_refreshes_git_database() {
    let tmp = scratch("gem-audit-check-update");
    let origin = tmp.path().join("origin");
    init_git_db(&origin);
    let clone = tmp.path().join("clone");
    copy_git_clone(&origin, &clone);

    Command::cargo_bin("gem-audit")
        .unwrap()
        .args([
            "check",
            "--update",
            "--database",
            clone.to_str().unwrap(),
            "--gemfile-lock",
            vulnerable_lock().to_str().unwrap(),
        ])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("Updated ruby-advisory-db"));
}

#[test]
fn check_update_failure_is_only_a_warning() {
    let tmp = scratch("gem-audit-check-update-warn");
    let origin = tmp.path().join("origin");
    init_git_db(&origin);
    let clone = tmp.path().join("clone");
    copy_git_clone(&origin, &clone);
    std::fs::remove_dir_all(&origin).unwrap();

    Command::cargo_bin("gem-audit")
        .unwrap()
        .args([
            "check",
            "--update",
            "--database",
            clone.to_str().unwrap(),
            "--gemfile-lock",
            secure_lock().to_str().unwrap(),
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains(
            "warning: Failed to update advisory database",
        ));
}

// ==================== check — stale database ====================

#[test]
fn check_fail_on_stale_database() {
    let tmp = scratch("gem-audit-stale");
    let db = tmp.path().to_path_buf();
    init_git_db(&db);

    Command::cargo_bin("gem-audit")
        .unwrap()
        .args([
            "check",
            "--database",
            db.to_str().unwrap(),
            "--gemfile-lock",
            secure_lock().to_str().unwrap(),
            "--max-db-age",
            "0",
            "--fail-on-stale",
        ])
        .assert()
        .code(3)
        .stderr(predicate::str::contains("advisory database is"));
}

#[test]
fn check_fresh_database_is_not_stale() {
    let tmp = scratch("gem-audit-fresh");
    let db = tmp.path().to_path_buf();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    init_git_db_at(&db, now);

    Command::cargo_bin("gem-audit")
        .unwrap()
        .args([
            "check",
            "--database",
            db.to_str().unwrap(),
            "--gemfile-lock",
            secure_lock().to_str().unwrap(),
            "--max-db-age",
            "30",
            "--fail-on-stale",
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains("days old").not());
}

#[test]
fn check_database_just_inside_the_age_limit() {
    let tmp = scratch("gem-audit-age-boundary");
    let db = tmp.path().to_path_buf();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    // Two days and one hour old: exactly at the limit, so not yet stale.
    init_git_db_at(&db, now - 2 * 86_400 - 3_600);

    Command::cargo_bin("gem-audit")
        .unwrap()
        .args([
            "check",
            "--database",
            db.to_str().unwrap(),
            "--gemfile-lock",
            secure_lock().to_str().unwrap(),
            "--max-db-age",
            "2",
            "--fail-on-stale",
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains("days old").not());
}

#[test]
fn check_without_max_db_age_never_reports_staleness() {
    let tmp = scratch("gem-audit-no-age-limit");
    let db = tmp.path().to_path_buf();
    init_git_db(&db);

    Command::cargo_bin("gem-audit")
        .unwrap()
        .args([
            "check",
            "--database",
            db.to_str().unwrap(),
            "--gemfile-lock",
            secure_lock().to_str().unwrap(),
            "--fail-on-stale",
        ])
        .assert()
        .success();
}

// ==================== check — strict mode ====================

#[test]
fn check_strict_fails_on_version_parse_errors() {
    Command::cargo_bin("gem-audit")
        .unwrap()
        .args([
            "check",
            "--strict",
            "--database",
            mock_db().to_str().unwrap(),
            "--gemfile-lock",
            fixtures_dir()
                .join("bad_version/Gemfile.lock")
                .to_str()
                .unwrap(),
        ])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("failed to parse version"));
}

#[test]
fn check_strict_fails_on_advisory_load_errors() {
    Command::cargo_bin("gem-audit")
        .unwrap()
        .args([
            "check",
            "--strict",
            "--database",
            mock_db().to_str().unwrap(),
            "--gemfile-lock",
            fixtures_dir()
                .join("broken_advisory/Gemfile.lock")
                .to_str()
                .unwrap(),
        ])
        .assert()
        .code(2)
        .stdout(predicate::str::contains("1 advisory load error"));
}

#[test]
fn check_strict_succeeds_without_errors() {
    Command::cargo_bin("gem-audit")
        .unwrap()
        .args([
            "check",
            "--strict",
            "--database",
            mock_db().to_str().unwrap(),
            "--gemfile-lock",
            secure_lock().to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Warnings:").not());
}

// ==================== check — invalid config ====================

#[test]
fn check_invalid_config_is_an_error() {
    Command::cargo_bin("gem-audit")
        .unwrap()
        .args([
            "check",
            "--database",
            mock_db().to_str().unwrap(),
            "--gemfile-lock",
            secure_lock().to_str().unwrap(),
            "--config",
            fixtures_dir()
                .join("config/bad/ignore_is_not_an_array.yml")
                .to_str()
                .unwrap(),
        ])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("invalid configuration"));
}

// ==================== check — unwritable outputs ====================

#[test]
fn check_output_file_failure_is_an_error() {
    let tmp = scratch("gem-audit-output-unwritable");
    let target = unwritable_path(&tmp);

    Command::cargo_bin("gem-audit")
        .unwrap()
        .args([
            "check",
            "--database",
            mock_db().to_str().unwrap(),
            "--gemfile-lock",
            secure_lock().to_str().unwrap(),
            "--output",
            target.to_str().unwrap(),
        ])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("Failed to open output file"));
}

#[test]
fn check_write_ignore_failure_is_an_error() {
    let tmp = scratch("gem-audit-config-unwritable");
    let target = unwritable_path(&tmp);

    Command::cargo_bin("gem-audit")
        .unwrap()
        .args([
            "check",
            "--write-ignore",
            "--database",
            mock_db().to_str().unwrap(),
            "--gemfile-lock",
            vulnerable_lock().to_str().unwrap(),
            "--config",
            target.to_str().unwrap(),
        ])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("Failed to write config"));
}

// ==================== check --fix — partial and impossible fixes ====================

#[test]
fn check_fix_reports_unresolvable_alongside_fixed() {
    let tmp = scratch("gem-audit-mixed-fix");
    let lockfile = tmp.path().join("Gemfile.lock");
    std::fs::copy(fixtures_dir().join("mixed_fix/Gemfile.lock"), &lockfile).unwrap();

    Command::cargo_bin("gem-audit")
        .unwrap()
        .args([
            "check",
            "--fix",
            "--database",
            mock_db().to_str().unwrap(),
            "--gemfile-lock",
            lockfile.to_str().unwrap(),
        ])
        .assert()
        .code(1)
        .stdout(
            predicate::str::contains("no safe version found")
                .and(predicate::str::contains("test (0.5.0 ->")),
        )
        .stderr(predicate::str::contains("Fixed 1 gem(s)"));

    let patched = std::fs::read_to_string(&lockfile).unwrap();
    assert!(patched.contains("unfixable (0.5.0)"), "{}", patched);
}

#[test]
fn check_fix_writes_nothing_when_no_gem_is_fixable() {
    let tmp = scratch("gem-audit-unfixable");
    let lockfile = tmp.path().join("Gemfile.lock");
    std::fs::copy(fixtures_dir().join("unfixable_gem/Gemfile.lock"), &lockfile).unwrap();
    let before = std::fs::read_to_string(&lockfile).unwrap();

    Command::cargo_bin("gem-audit")
        .unwrap()
        .args([
            "check",
            "--fix",
            "--database",
            mock_db().to_str().unwrap(),
            "--gemfile-lock",
            lockfile.to_str().unwrap(),
        ])
        .assert()
        .code(1)
        .stdout(predicate::str::contains("no safe version found"))
        .stderr(predicate::str::contains("Fixed").not());

    assert_eq!(std::fs::read_to_string(&lockfile).unwrap(), before);
}

#[cfg(unix)]
#[test]
fn check_fix_reports_a_write_failure() {
    use std::os::unix::fs::PermissionsExt;

    let tmp = scratch("gem-audit-fix-readonly");
    let lockfile = tmp.path().join("Gemfile.lock");
    std::fs::copy(vulnerable_lock(), &lockfile).unwrap();

    // The lockfile stays readable, but the temporary file cannot be created.
    std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o500)).unwrap();

    let assertion = Command::cargo_bin("gem-audit")
        .unwrap()
        .args([
            "check",
            "--fix",
            "--database",
            mock_db().to_str().unwrap(),
            "--gemfile-lock",
            lockfile.to_str().unwrap(),
        ])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("error: failed to write"));

    std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    drop(assertion);
}

// ==================== default database path ====================

#[test]
fn missing_home_falls_back_to_a_relative_database_path() {
    let tmp = scratch("gem-audit-no-home");

    Command::cargo_bin("gem-audit")
        .unwrap()
        .arg("stats")
        .current_dir(tmp.path())
        .env_remove("HOME")
        .env_remove("GEM_AUDIT_DB")
        .assert()
        .code(2)
        .stderr(predicate::str::contains(".ruby-advisory-db"));
}

// ==================== check — report write failure ====================

/// `/dev/full` accepts `open` but fails every write; it only exists on Linux.
#[cfg(target_os = "linux")]
#[test]
fn check_report_write_failure_is_an_error() {
    Command::cargo_bin("gem-audit")
        .unwrap()
        .args([
            "check",
            "--database",
            mock_db().to_str().unwrap(),
            "--gemfile-lock",
            secure_lock().to_str().unwrap(),
            "--output",
            "/dev/full",
        ])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("error: write failed"));
}

// ==================== update — download from a mirror ====================

#[test]
fn update_downloads_from_the_configured_mirror() {
    let tmp = scratch("gem-audit-mirror");
    let origin = tmp.path().join("origin");
    init_git_db(&origin);
    let dest = tmp.path().join("fresh").join("advisory-db");

    Command::cargo_bin("gem-audit")
        .unwrap()
        .args(["update", "--database", dest.to_str().unwrap()])
        .env("GEM_AUDIT_DB_URL", &origin)
        .assert()
        .success()
        .stderr(
            predicate::str::contains("Downloading ruby-advisory-db")
                .and(predicate::str::contains("Downloaded ruby-advisory-db")),
        )
        .stdout(predicate::str::contains("1 advisories"));

    assert!(dest.join("gems").join("test").is_dir());
}

#[test]
fn check_downloads_the_database_when_missing() {
    let tmp = scratch("gem-audit-mirror-check");
    let origin = tmp.path().join("origin");
    init_git_db(&origin);
    let dest = tmp.path().join("advisory-db");

    Command::cargo_bin("gem-audit")
        .unwrap()
        .args([
            "check",
            "--quiet",
            "--database",
            dest.to_str().unwrap(),
            "--gemfile-lock",
            vulnerable_lock().to_str().unwrap(),
        ])
        .env("GEM_AUDIT_DB_URL", &origin)
        .assert()
        .code(1)
        // `--quiet` silences the download chatter but not the findings.
        .stderr(predicate::str::is_empty());

    assert!(dest.join("gems").join("test").is_dir());
}
