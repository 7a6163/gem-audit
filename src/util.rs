/// Format a Unix timestamp as a human-readable UTC date string.
pub fn format_timestamp(seconds: i64) -> String {
    let days_since_epoch = seconds / 86400;
    let time_of_day = seconds % 86400;
    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let secs = time_of_day % 60;

    let (year, month, day) = days_to_date(days_since_epoch);

    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02} UTC",
        year, month, day, hours, minutes, secs
    )
}

/// Convert days since Unix epoch (1970-01-01) to a (year, month, day) tuple.
///
/// Algorithm from <https://howardhinnant.github.io/date_algorithms.html>.
pub fn days_to_date(days: i64) -> (i64, u32, u32) {
    let z = days + 719468;
    let era = (if z >= 0 { z } else { z - 146096 }) / 146097;
    let doe = (z - era * 146097) as u32;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_timestamp_epoch() {
        assert_eq!(format_timestamp(0), "1970-01-01 00:00:00 UTC");
    }

    #[test]
    fn format_timestamp_known_date() {
        // 2023-11-14 22:13:20 UTC
        assert_eq!(format_timestamp(1700000000), "2023-11-14 22:13:20 UTC");
    }

    #[test]
    fn format_timestamp_with_time_components() {
        // 1970-01-01 01:01:01 UTC = 3661 seconds
        assert_eq!(format_timestamp(3661), "1970-01-01 01:01:01 UTC");
    }

    #[test]
    fn format_timestamp_end_of_day() {
        // 1970-01-01 23:59:59 UTC = 86399 seconds
        assert_eq!(format_timestamp(86399), "1970-01-01 23:59:59 UTC");
    }

    #[test]
    fn days_to_date_epoch() {
        assert_eq!(days_to_date(0), (1970, 1, 1));
    }

    #[test]
    fn days_to_date_leap_year() {
        // 2000-02-29 is day 11016 from epoch
        assert_eq!(days_to_date(11016), (2000, 2, 29));
    }

    #[test]
    fn days_to_date_end_of_month() {
        // 1970-01-31 is day 30
        assert_eq!(days_to_date(30), (1970, 1, 31));
    }

    #[test]
    fn days_to_date_pre_epoch() {
        // 1969-12-31 is day -1
        assert_eq!(days_to_date(-1), (1969, 12, 31));
    }

    #[test]
    fn days_to_date_year_2024() {
        // 2024-01-01 is day 19723
        assert_eq!(days_to_date(19723), (2024, 1, 1));
    }
}
