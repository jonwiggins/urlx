//! Build script for urlx-cli: sets the `URLX_RELEASE_DATE` env var.

fn main() {
    // Expose the build date as URLX_RELEASE_DATE so --version shows it.
    // Override with the URLX_RELEASE_DATE env var for reproducible release builds.
    let date = std::env::var("URLX_RELEASE_DATE").unwrap_or_else(|_| {
        // Fall back to today's date at build time.
        let Ok(now) = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) else {
            // System clock before epoch — use a placeholder date.
            return "1970-01-01".to_string();
        };
        let secs = now.as_secs();
        // Simple UTC date calculation (no external crate needed)
        let days = secs / 86400;
        let (year, month, day) = days_to_ymd(days);
        format!("{year}-{month:02}-{day:02}")
    });
    println!("cargo:rustc-env=URLX_RELEASE_DATE={date}");
}

/// Convert days since Unix epoch to (year, month, day).
const fn days_to_ymd(days: u64) -> (u64, u64, u64) {
    // Algorithm from http://howardhinnant.github.io/date_algorithms.html
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}
