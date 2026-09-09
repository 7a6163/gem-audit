use std::collections::{HashMap, HashSet};
use std::io::{self, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process;

use clap::{Parser, Subcommand};

use gem_audit::advisory::{Criticality, Database};
use gem_audit::check;
use gem_audit::configuration::Configuration;
use gem_audit::fixer::{self, FixResult};
use gem_audit::format::{self, OutputFormat};
use gem_audit::scanner::{ScanOptions, Scanner};
use gem_audit::util::format_timestamp;

const VERSION: &str = env!("CARGO_PKG_VERSION");

const EXIT_SUCCESS: i32 = 0;
const EXIT_VULNERABLE: i32 = 1;
const EXIT_ERROR: i32 = 2;
const EXIT_STALE: i32 = 3;

#[derive(Parser)]
#[command(
    name = "gem-audit",
    about = "Patch-level verification for Ruby Bundler dependencies",
    version = VERSION,
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(clap::Args)]
struct CheckOptions {
    /// Project directory to audit
    #[arg(default_value = ".")]
    dir: String,

    /// Suppress output
    #[arg(short, long)]
    quiet: bool,

    /// Show detailed descriptions
    #[arg(short, long)]
    verbose: bool,

    /// Advisory IDs to ignore
    #[arg(short, long, num_args = 1..)]
    ignore: Vec<String>,

    /// Update the advisory database before checking
    #[arg(short, long)]
    update: bool,

    /// Path to the advisory database
    #[arg(short = 'D', long)]
    database: Option<String>,

    /// Output format
    #[arg(short = 'F', long, value_enum, default_value = "text")]
    format: OutputFormat,

    /// Path to the Gemfile.lock file
    #[arg(short = 'G', long, default_value = "Gemfile.lock")]
    gemfile_lock: String,

    /// Path to the configuration file
    #[arg(short, long, default_value = ".gem-audit.yml")]
    config: String,

    /// Output file (default: stdout)
    #[arg(short, long)]
    output: Option<String>,

    /// Minimum severity level to report (none, low, medium, high, critical)
    #[arg(short = 'S', long, value_enum)]
    severity: Option<Criticality>,

    /// Maximum advisory database age in days before warning
    #[arg(long)]
    max_db_age: Option<u64>,

    /// Exit with code 3 if the advisory database is stale
    #[arg(long)]
    fail_on_stale: bool,

    /// Treat parse/load warnings as errors (exit code 2)
    #[arg(long)]
    strict: bool,

    /// Fix vulnerable gem versions in Gemfile.lock
    #[arg(long)]
    fix: bool,

    /// Preview fix changes without writing (use with --fix)
    #[arg(long)]
    dry_run: bool,

    /// Write all detected advisory IDs to the config file's ignore list
    #[arg(long)]
    write_ignore: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Check the Gemfile.lock for insecure dependencies (default)
    Check(CheckOptions),

    /// Download or update the ruby-advisory-db
    Update {
        /// Suppress output
        #[arg(short, long)]
        quiet: bool,

        /// Path to the advisory database
        #[arg(short = 'D', long)]
        database: Option<String>,
    },

    /// Print ruby-advisory-db statistics
    Stats {
        /// Path to the advisory database
        #[arg(short = 'D', long)]
        database: Option<String>,
    },

    /// Print the gem-audit version
    Version,
}

fn main() {
    let cli = Cli::parse();

    let code = match cli.command {
        Some(Commands::Check(opts)) => to_code(cmd_check(opts)),
        Some(Commands::Update { quiet, database }) => {
            to_code(cmd_update(quiet, database.as_deref()))
        }
        Some(Commands::Stats { database }) => to_code(cmd_stats(database.as_deref())),
        Some(Commands::Version) => {
            println!("gem-audit {}", VERSION);
            EXIT_SUCCESS
        }
        None => to_code(cmd_check(CheckOptions::default())),
    };

    if code != EXIT_SUCCESS {
        process::exit(code);
    }
}

impl Default for CheckOptions {
    fn default() -> Self {
        Self {
            dir: ".".to_string(),
            quiet: false,
            verbose: false,
            ignore: Vec::new(),
            update: false,
            database: None,
            format: OutputFormat::Text,
            gemfile_lock: "Gemfile.lock".to_string(),
            config: Configuration::DEFAULT_FILE.to_string(),
            output: None,
            severity: None,
            max_db_age: None,
            fail_on_stale: false,
            strict: false,
            fix: false,
            dry_run: false,
            write_ignore: false,
        }
    }
}

/// Collapse a command result into a process exit code.
fn to_code(result: Result<(), i32>) -> i32 {
    result.map_or_else(|code| code, |()| EXIT_SUCCESS)
}

fn resolve_db_path(database: Option<&str>) -> PathBuf {
    database
        .map(PathBuf::from)
        .unwrap_or_else(Database::default_path)
}

/// Whether the advisory database has already been downloaded to `db_path`.
fn database_present(db_path: &Path) -> bool {
    db_path.join("gems").is_dir()
}

fn open_database(db_path: &Path) -> Result<Database, i32> {
    Database::open(db_path).map_err(|e| {
        eprintln!("Failed to open advisory database: {}", e);
        EXIT_ERROR
    })
}

fn download_database(db_path: &Path, quiet: bool) -> Result<Database, i32> {
    if !quiet {
        eprintln!("Downloading ruby-advisory-db ...");
    }
    match Database::download(db_path, quiet) {
        Ok(db) => {
            if !quiet {
                eprintln!("Downloaded ruby-advisory-db");
            }
            Ok(db)
        }
        Err(e) => {
            eprintln!("Failed to download advisory database: {}", e);
            Err(EXIT_ERROR)
        }
    }
}

/// Fetch the latest advisories, reporting progress on stderr.
///
/// Returns the failure message when the update did not succeed.
fn run_update(db: &Database, quiet: bool) -> Result<(), String> {
    if !quiet {
        eprintln!("Updating ruby-advisory-db ...");
    }
    match db.update() {
        Ok(true) => {
            if !quiet {
                eprintln!("Updated ruby-advisory-db");
            }
            Ok(())
        }
        Ok(false) => {
            if !quiet {
                eprintln!("Skipping update, ruby-advisory-db is not a git repository");
            }
            Ok(())
        }
        Err(e) => Err(e.to_string()),
    }
}

fn ensure_database(db_path: &Path, update: bool, quiet: bool) -> Result<Database, i32> {
    if !database_present(db_path) {
        return download_database(db_path, quiet);
    }

    let db = open_database(db_path)?;
    if update && let Err(e) = run_update(&db, quiet) {
        eprintln!("warning: Failed to update advisory database: {}", e);
    }
    Ok(db)
}

/// Replace `path` with `content`, via a temporary file so a failed write
/// cannot leave a half-written lockfile behind.
fn write_atomically(path: &Path, content: &str) -> io::Result<()> {
    let tmp_path = path.with_extension("lock.tmp");
    std::fs::write(&tmp_path, content)?;
    std::fs::rename(&tmp_path, path).inspect_err(|_| {
        let _ = std::fs::remove_file(&tmp_path);
    })
}

/// Map a failed report write to an exit code.
///
/// A closed pipe (`gem-audit check | head`) is not an error.
fn report_write_result(result: io::Result<()>) -> Result<(), i32> {
    match result {
        Err(e) if e.kind() != io::ErrorKind::BrokenPipe => {
            eprintln!("error: write failed: {}", e);
            Err(EXIT_ERROR)
        }
        _ => Ok(()),
    }
}

fn apply_fixes(lockfile_path: &Path, content: &str, fix_results: &[FixResult]) {
    let fixes: Vec<fixer::FixSuggestion> = fix_results
        .iter()
        .filter_map(|r| match r {
            FixResult::Fixed(f) => Some(f.clone()),
            _ => None,
        })
        .collect();

    // `patch_lockfile` is a no-op for an empty fix list, so one guard covers
    // both "nothing to fix" and "nothing matched".
    let (patched, patched_names) = fixer::patch_lockfile(content, &fixes);
    if patched_names.is_empty() {
        return;
    }

    match write_atomically(lockfile_path, &patched) {
        Ok(()) => eprintln!(
            "\nFixed {} gem(s) in {}. Run `bundle install` to install the updated versions.",
            patched_names.len(),
            lockfile_path.display()
        ),
        Err(e) => eprintln!("error: failed to write {}: {}", lockfile_path.display(), e),
    }
}

fn write_ignore_list(
    report: &gem_audit::scanner::Report,
    config: &Configuration,
    config_path: &Path,
) -> Result<(), i32> {
    let (new_ids, new_comments) = check::build_ignore_comments(report);
    let merged_ignore: HashSet<String> = config.ignore.union(&new_ids).cloned().collect();

    let mut merged_comments = config.ignore_comments.clone();
    for (id, comment) in new_comments {
        merged_comments.insert(id, comment);
    }

    let updated_config = Configuration {
        ignore: merged_ignore,
        max_db_age_days: config.max_db_age_days,
        ignore_comments: HashMap::new(),
    };

    match updated_config.save(config_path, Some(&merged_comments)) {
        Ok(()) => {
            let count = updated_config.ignore.len() - config.ignore.len();
            eprintln!(
                "Added {} advisory ID(s) to {}",
                count,
                config_path.display()
            );
            Ok(())
        }
        Err(e) => {
            eprintln!("Failed to write config: {}", e);
            Err(EXIT_ERROR)
        }
    }
}

fn cmd_check(opts: CheckOptions) -> Result<(), i32> {
    let dir = Path::new(&opts.dir);
    if !dir.is_dir() {
        eprintln!("No such file or directory: {}", dir.display());
        return Err(EXIT_ERROR);
    }

    let config_path = if Path::new(&opts.config).is_absolute() {
        PathBuf::from(&opts.config)
    } else {
        dir.join(&opts.config)
    };
    let config = Configuration::load_or_default(&config_path).map_err(|e| {
        eprintln!("{}", e);
        EXIT_ERROR
    })?;

    let db_path = resolve_db_path(opts.database.as_deref());

    let db = ensure_database(&db_path, opts.update, opts.quiet)?;

    let stale = check::check_staleness(&db, opts.max_db_age, config.max_db_age_days);

    let lockfile_path = dir.join(&opts.gemfile_lock);
    let scanner = Scanner::new(&lockfile_path, db).map_err(|e| {
        eprintln!("{}", e);
        EXIT_ERROR
    })?;

    let ignore_set = if !opts.ignore.is_empty() {
        opts.ignore.iter().cloned().collect::<HashSet<String>>()
    } else {
        config.ignore.clone()
    };

    let scan_options = ScanOptions {
        ignore: ignore_set,
        severity: opts.severity,
        strict: opts.strict,
    };

    let report = scanner.scan(&scan_options);

    // Output
    let stdout = io::stdout();
    let is_tty = stdout.is_terminal();
    let mut output_handle: Box<dyn Write> = match opts.output {
        Some(ref path) => Box::new(std::fs::File::create(path).map_err(|e| {
            eprintln!("Failed to open output file {}: {}", path, e);
            EXIT_ERROR
        })?),
        None => Box::new(stdout.lock()),
    };

    let fix_results = opts
        .fix
        .then(|| fixer::resolve_fixes(&report.remediations()));

    let print_result = match opts.format {
        OutputFormat::Text => {
            let use_color = opts.output.is_none() && is_tty;
            format::print_text(
                &report,
                &mut output_handle,
                opts.verbose,
                opts.quiet,
                use_color,
                opts.fix,
                fix_results.as_deref(),
            )
        }
        OutputFormat::Json => format::print_json(
            &report,
            &mut output_handle,
            is_tty && opts.output.is_none(),
            opts.fix,
            fix_results.as_deref(),
        ),
    };

    report_write_result(print_result)?;

    if opts.fix
        && !opts.dry_run
        && let Some(ref results) = fix_results
    {
        apply_fixes(
            &lockfile_path,
            scanner.source().unwrap_or_default(),
            results,
        );
    }

    if opts.write_ignore && report.vulnerable() {
        return write_ignore_list(&report, &config, &config_path);
    }

    if report.vulnerable() {
        return Err(EXIT_VULNERABLE);
    }

    if opts.strict && (report.version_parse_errors > 0 || report.advisory_load_errors > 0) {
        return Err(EXIT_ERROR);
    }

    if stale && opts.fail_on_stale {
        return Err(EXIT_STALE);
    }

    Ok(())
}

fn cmd_update(quiet: bool, database: Option<&str>) -> Result<(), i32> {
    let db_path = resolve_db_path(database);

    let db = if database_present(&db_path) {
        let db = open_database(&db_path)?;
        if let Err(e) = run_update(&db, quiet) {
            eprintln!("Failed to update: {}", e);
            return Err(EXIT_ERROR);
        }
        db
    } else {
        download_database(&db_path, quiet)?
    };

    if !quiet {
        print_stats(&db);
    }

    Ok(())
}

fn cmd_stats(database: Option<&str>) -> Result<(), i32> {
    print_stats(&open_database(&resolve_db_path(database))?);
    Ok(())
}

fn print_stats(db: &Database) {
    let gems = db.size();
    let rubies = db.rubies_size();

    println!("ruby-advisory-db:");
    println!("  advisories:\t{} advisories", gems + rubies);

    if rubies > 0 {
        println!("  gems:\t\t{}", gems);
        println!("  rubies:\t{}", rubies);
    }

    if let Some(ts) = db.last_updated_at() {
        println!("  last updated:\t{}", format_timestamp(ts));
    }

    if let Some(commit) = db.commit_id() {
        println!("  commit:\t{}", commit);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_write_result_ignores_a_closed_pipe() {
        assert_eq!(report_write_result(Ok(())), Ok(()));
        assert_eq!(
            report_write_result(Err(io::Error::from(io::ErrorKind::BrokenPipe))),
            Ok(())
        );
        assert_eq!(
            report_write_result(Err(io::Error::other("disk full"))),
            Err(EXIT_ERROR)
        );
    }

    #[test]
    fn to_code_maps_results_to_exit_codes() {
        assert_eq!(to_code(Ok(())), EXIT_SUCCESS);
        assert_eq!(to_code(Err(EXIT_VULNERABLE)), EXIT_VULNERABLE);
        assert_eq!(to_code(Err(EXIT_STALE)), EXIT_STALE);
    }

    #[test]
    fn write_atomically_replaces_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("Gemfile.lock");
        std::fs::write(&dest, "old").unwrap();

        write_atomically(&dest, "new").unwrap();

        assert_eq!(std::fs::read_to_string(&dest).unwrap(), "new");
        assert!(!dest.with_extension("lock.tmp").exists());
    }

    #[test]
    fn write_atomically_cleans_up_after_a_failed_rename() {
        let dir = tempfile::tempdir().unwrap();
        // A non-empty directory cannot be replaced by a rename.
        let dest = dir.path().join("Gemfile.lock");
        std::fs::create_dir(&dest).unwrap();
        std::fs::write(dest.join("occupied"), b"x").unwrap();

        let err = write_atomically(&dest, "new").unwrap_err();
        assert!(err.kind() != io::ErrorKind::NotFound, "got {:?}", err);

        // The temporary file must not be left behind next to the lockfile.
        assert!(!dest.with_extension("lock.tmp").exists());
        assert!(dest.join("occupied").exists());
    }
}
