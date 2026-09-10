/// Format a Unix timestamp as a human-readable UTC date string.
pub fn format_timestamp(seconds: i64) -> String {
    // Euclidean division so timestamps before 1970 borrow into the previous day
    // instead of producing a negative time of day.
    let days_since_epoch = seconds.div_euclid(86400);
    let time_of_day = seconds.rem_euclid(86400);
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

    #[test]
    fn format_timestamp_before_the_epoch() {
        assert_eq!(format_timestamp(-1), "1969-12-31 23:59:59 UTC");
        assert_eq!(format_timestamp(-86400), "1969-12-31 00:00:00 UTC");
    }

    // The civil-from-days algorithm branches on 400-year eras; these cases
    // reach the parts of it that dates near 1970 never touch.

    #[test]
    fn days_to_date_across_leap_cycles() {
        // Day-of-era 1460 and 120257: the leap-day corrections in `yoe` have to
        // be summed, not folded together.
        assert_eq!(days_to_date(12477), (2004, 2, 29));
        assert_eq!(days_to_date(131274), (2329, 6, 2));
    }

    #[test]
    fn days_to_date_more_than_a_century_into_an_era() {
        // day-of-era 54892, so the `doe / 36524` century correction applies
        assert_eq!(days_to_date(65909), (2150, 6, 15));
        // The first day of era-day 36524 and 109572, where that correction
        // first changes the year-of-era.
        assert_eq!(days_to_date(47541), (2100, 3, 1));
        assert_eq!(days_to_date(120589), (2300, 3, 1));
    }

    #[test]
    fn days_to_date_at_the_era_boundary() {
        // z == 0: the first day of era 0
        assert_eq!(days_to_date(-719468), (0, 3, 1));
        // z == -1: the negative-era branch, and day-of-era 146096, the only
        // value for which the `doe / 146096` correction is non-zero
        assert_eq!(days_to_date(-719469), (0, 2, 29));
    }

    #[test]
    fn days_to_date_far_before_the_epoch() {
        assert_eq!(days_to_date(-800000), (-221, 9, 4));
        assert_eq!(days_to_date(-719162), (1, 1, 1));
    }
}
