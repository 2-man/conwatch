//! Optional country database download (DB-IP "IP to Country Lite", CC BY 4.0, https://db-ip.com).
//! Only runs when the user asks for it. Uses the system `curl` (present on Windows 10+ and macOS).

use std::io::Read;
use std::path::Path;

/// (year, month) for a unix timestamp, plus the previous month.
fn year_month(ts: i64) -> (i64, i64) {
    // Howard Hinnant's civil_from_days.
    let z = ts.div_euclid(86400) + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + if m <= 2 { 1 } else { 0 };
    (y, m)
}

fn urls(ts: i64) -> Vec<String> {
    let (y, m) = year_month(ts);
    let (py, pm) = if m == 1 { (y - 1, 12) } else { (y, m - 1) };
    [(y, m), (py, pm)].iter().map(|(y, m)| format!("https://download.db-ip.com/free/dbip-country-lite-{y}-{m:02}.mmdb.gz")).collect()
}

/// Download, decompress and validate the database into `dest`.
pub fn download(dest: &Path) -> Result<(), String> {
    let now = crate::storage::now_secs();
    let tmp = dest.with_extension("gz.part");
    let mut last_err = String::from("no download URL worked");
    for url in urls(now) {
        let mut c = std::process::Command::new("curl");
        c.args(["-fsSL", "--max-time", "120", "-o"]).arg(&tmp).arg(&url);
        match crate::no_window(&mut c).status() {
            Ok(s) if s.success() => {
                let gz = std::fs::File::open(&tmp).map_err(|e| e.to_string())?;
                let mut out = Vec::new();
                flate2::read::GzDecoder::new(gz).read_to_end(&mut out).map_err(|e| format!("bad archive: {e}"))?;
                let _ = std::fs::remove_file(&tmp);
                maxminddb::Reader::from_source(out.clone()).map_err(|e| format!("invalid database: {e}"))?;
                std::fs::write(dest, out).map_err(|e| e.to_string())?;
                return Ok(());
            }
            Ok(_) => last_err = format!("download failed: {url}"),
            Err(e) => last_err = format!("curl not available: {e}"),
        }
    }
    let _ = std::fs::remove_file(&tmp);
    Err(last_err)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn month_math() {
        assert_eq!(year_month(1_795_742_260), (2026, 11));
        assert_eq!(year_month(0), (1970, 1));
        assert!(urls(1_767_225_600)[1].ends_with("2025-12.mmdb.gz")); // 2026-01-01 -> previous is 2025-12
    }
}
