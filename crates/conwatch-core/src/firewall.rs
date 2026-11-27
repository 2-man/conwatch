//! Per-application blocking via the OS firewall.
//! Windows: Windows Defender Firewall rules through `netsh advfirewall` (needs admin).
//! macOS: not implemented yet (needs a Network Extension / pf anchors).

const PREFIX: &str = "ConWatch block: ";

fn rule_name(exe: &str) -> String {
    format!("{PREFIX}{exe}")
}

fn validate(exe: &str) -> Result<(), String> {
    let p = std::path::Path::new(exe);
    if !p.is_absolute() || !p.is_file() {
        return Err("exe must be an absolute path to an existing file".into());
    }
    if exe.contains('"') || exe.contains('\n') {
        return Err("invalid characters in path".into());
    }
    Ok(())
}

#[cfg(windows)]
fn netsh(args: &[&str]) -> Result<String, String> {
    let o = crate::no_window(std::process::Command::new("netsh").args(args)).output().map_err(|e| e.to_string())?;
    let out = String::from_utf8_lossy(&o.stdout).to_string();
    if o.status.success() {
        Ok(out)
    } else {
        Err(format!("{} (run as Administrator?)", out.trim()))
    }
}

#[cfg(windows)]
pub fn block(exe: &str) -> Result<(), String> {
    validate(exe)?;
    let name = format!("name={}", rule_name(exe));
    let prog = format!("program={exe}");
    for dir in ["out", "in"] {
        netsh(&["advfirewall", "firewall", "add", "rule", &name, &format!("dir={dir}"), "action=block", &prog, "enable=yes"])?;
    }
    Ok(())
}

#[cfg(windows)]
pub fn unblock(exe: &str) -> Result<(), String> {
    validate_name(exe)?;
    netsh(&["advfirewall", "firewall", "delete", "rule", &format!("name={}", rule_name(exe))]).map(|_| ())
}

#[cfg(windows)]
pub fn blocked() -> Vec<String> {
    let out = netsh(&["advfirewall", "firewall", "show", "rule", "name=all", "dir=out"]).unwrap_or_default();
    let mut v: Vec<String> = out
        .lines()
        .filter_map(|l| l.find(PREFIX).map(|i| l[i + PREFIX.len()..].trim().to_string()))
        .collect();
    v.sort();
    v.dedup();
    v
}

#[cfg(windows)]
fn validate_name(exe: &str) -> Result<(), String> {
    if exe.contains('"') || exe.contains('\n') || exe.is_empty() {
        return Err("invalid characters in path".into());
    }
    Ok(())
}

#[cfg(not(windows))]
pub fn block(exe: &str) -> Result<(), String> {
    validate(exe)?;
    Err("firewall control is not implemented on this platform yet".into())
}
#[cfg(not(windows))]
pub fn unblock(_exe: &str) -> Result<(), String> {
    Err("firewall control is not implemented on this platform yet".into())
}
#[cfg(not(windows))]
pub fn blocked() -> Vec<String> {
    Vec::new()
}
