/// A parsed Ruby interpreter version from a Gemfile.lock `RUBY VERSION` section.
///
/// Example inputs:
/// - `"ruby 3.0.0p0"` -> engine="ruby", version="3.0.0"
/// - `"jruby 9.3.6.0"` -> engine="jruby", version="9.3.6.0"
/// - `"ruby 3.2.1"` -> engine="ruby", version="3.2.1"
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RubyVersion {
    /// The Ruby engine (e.g., "ruby", "jruby", "mruby").
    pub engine: String,
    /// The version string with patchlevel stripped (e.g., "3.0.0").
    pub version: String,
}

impl RubyVersion {
    /// Parse a Ruby version string from a Gemfile.lock `RUBY VERSION` section.
    ///
    /// Expects format: `"<engine> <version>[p<patchlevel>]"`
    ///
    /// Returns `None` if the input doesn't match the expected format.
    pub fn parse(input: &str) -> Option<Self> {
        let trimmed = input.trim();
        let (engine, version_raw) = trimmed.split_once(' ')?;

        if engine.is_empty() || version_raw.is_empty() {
            return None;
        }

        let version = strip_patchlevel(version_raw);

        Some(RubyVersion {
            engine: engine.to_string(),
            version,
        })
    }
}

/// Strip the patchlevel suffix (e.g., "p0", "p219") from a Ruby version string.
///
/// - `"3.0.0p0"` -> `"3.0.0"`
/// - `"2.7.6p219"` -> `"2.7.6"`
/// - `"9.3.6.0"` -> `"9.3.6.0"` (no patchlevel)
fn strip_patchlevel(version: &str) -> String {
    // Ruby patchlevel format: digits followed by 'p' followed by digits at end
    if let Some(pos) = version.rfind('p') {
        let before = &version[..pos];
        let after = &version[pos + 1..];
        // Only strip if the part after 'p' is all digits (patchlevel)
        // and the part before ends with a digit (not e.g. "pre")
        if !after.is_empty()
            && after.chars().all(|c| c.is_ascii_digit())
            && before.ends_with(|c: char| c.is_ascii_digit())
        {
            return before.to_string();
        }
    }
    version.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ruby_with_patchlevel() {
        let rv = RubyVersion::parse("ruby 3.0.0p0").unwrap();
        assert_eq!(rv.engine, "ruby");
        assert_eq!(rv.version, "3.0.0");
    }

    #[test]
    fn parse_ruby_with_high_patchlevel() {
        let rv = RubyVersion::parse("ruby 2.7.6p219").unwrap();
        assert_eq!(rv.engine, "ruby");
        assert_eq!(rv.version, "2.7.6");
    }

    #[test]
    fn parse_ruby_without_patchlevel() {
        let rv = RubyVersion::parse("ruby 3.2.1").unwrap();
        assert_eq!(rv.engine, "ruby");
        assert_eq!(rv.version, "3.2.1");
    }

    #[test]
    fn parse_jruby() {
        let rv = RubyVersion::parse("jruby 9.3.6.0").unwrap();
        assert_eq!(rv.engine, "jruby");
        assert_eq!(rv.version, "9.3.6.0");
    }

    #[test]
    fn parse_mruby() {
        let rv = RubyVersion::parse("mruby 3.1.0").unwrap();
        assert_eq!(rv.engine, "mruby");
        assert_eq!(rv.version, "3.1.0");
    }

    #[test]
    fn parse_with_leading_whitespace() {
        let rv = RubyVersion::parse("  ruby 3.0.0p0  ").unwrap();
        assert_eq!(rv.engine, "ruby");
        assert_eq!(rv.version, "3.0.0");
    }

    #[test]
    fn parse_empty_string() {
        assert!(RubyVersion::parse("").is_none());
    }

    #[test]
    fn parse_no_space() {
        assert!(RubyVersion::parse("ruby").is_none());
    }

    #[test]
    fn parse_empty_version() {
        assert!(RubyVersion::parse("ruby ").is_none());
    }

    #[test]
    fn strip_patchlevel_with_p0() {
        assert_eq!(strip_patchlevel("3.0.0p0"), "3.0.0");
    }

    #[test]
    fn strip_patchlevel_with_p219() {
        assert_eq!(strip_patchlevel("2.7.6p219"), "2.7.6");
    }

    #[test]
    fn strip_patchlevel_no_patchlevel() {
        assert_eq!(strip_patchlevel("3.2.1"), "3.2.1");
    }

    #[test]
    fn strip_patchlevel_preserves_pre_release() {
        // "pre" contains 'p' but it's not a patchlevel
        assert_eq!(strip_patchlevel("1.0.0.pre1"), "1.0.0.pre1");
    }
}
