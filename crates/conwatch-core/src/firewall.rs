//! Per-application blocking via the OS firewall, separately for inbound and outbound.
//! Windows: Windows Defender Firewall rules through `netsh advfirewall` (needs admin).
//! macOS: not implemented yet (needs a Network Extension / pf anchors).

const PREFIX: &str = "ConWatch block";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dir {
    In,
    Out,
}

impl Dir {
    fn tag(self) -> &'static str {
        match self {
            Dir::In => "in",
            Dir::Out => "out",
        }
    }
}

/// An application with at least one ConWatch block rule.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Blocked {
    pub exe: String,
    pub inbound: bool,
    pub outbound: bool,
}

fn rule_name(exe: &str, dir: Dir) -> String {
    format!("{PREFIX} [{}]: {exe}", dir.tag())
}

/// Parse one `netsh show rule` line that mentions our rule name:
/// `... ConWatch block [out]: C:\\app.exe` (or the legacy `ConWatch block: C:\\app.exe`, both directions).
pub fn parse_rule_line(line: &str) -> Option<(String, bool, bool)> {
    let rest = &line[line.find(PREFIX)? + PREFIX.len()..];
    let (inb, outb, path) = if let Some(p) = rest.strip_prefix(" [out]:") {
        (false, true, p)
    } else if let Some(p) = rest.strip_prefix(" [in]:") {
        (true, false, p)
    } else {
        let p = rest.strip_prefix(':')?;
        (true, true, p)
    };
    let path = path.trim();
    (!path.is_empty()).then(|| (path.to_string(), inb, outb))
}

/// Merge parsed rule lines into one entry per executable.
pub fn merge_rules(lines: impl Iterator<Item = (String, bool, bool)>) -> Vec<Blocked> {
    let mut v: Vec<Blocked> = Vec::new();
    for (exe, i, o) in lines {
        match v.iter_mut().find(|b| b.exe.eq_ignore_ascii_case(&exe)) {
            Some(b) => {
                b.inbound |= i;
                b.outbound |= o;
            }
            None => v.push(Blocked { exe, inbound: i, outbound: o }),
        }
    }
    v.sort_by_key(|a| a.exe.to_lowercase());
    v
}

fn validate(exe: &str) -> Result<(), String> {
    let p = std::path::Path::new(exe);
    if !p.is_absolute() || !p.is_file() {
        return Err("exe must be an absolute path to an existing file".into());
    }
    validate_name(exe)
}

fn validate_name(exe: &str) -> Result<(), String> {
    if exe.is_empty() || exe.contains('"') || exe.contains('\n') {
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
pub fn blocked() -> Vec<Blocked> {
    let out = netsh(&["advfirewall", "firewall", "show", "rule", "name=all"]).unwrap_or_default();
    merge_rules(out.lines().filter_map(parse_rule_line))
}

#[cfg(windows)]
pub fn block_dir(exe: &str, dir: Dir) -> Result<(), String> {
    validate(exe)?;
    let name = format!("name={}", rule_name(exe, dir));
    netsh(&["advfirewall", "firewall", "add", "rule", &name, &format!("dir={}", dir.tag()), "action=block", &format!("program={exe}"), "enable=yes"]).map(|_| ())
}

#[cfg(windows)]
pub fn unblock_dir(exe: &str, dir: Dir) -> Result<(), String> {
    validate_name(exe)?;
    let r = netsh(&["advfirewall", "firewall", "delete", "rule", &format!("name={}", rule_name(exe, dir))]);
    if r.is_err() {
        // Missing rule is fine; a real failure leaves the rule in place.
        let still = blocked().iter().any(|b| b.exe.eq_ignore_ascii_case(exe) && if dir == Dir::In { b.inbound } else { b.outbound });
        if still {
            return r.map(|_| ());
        }
    }
    Ok(())
}

/// Remove rules created by older versions (one rule name covering both directions).
#[cfg(windows)]
fn delete_legacy(exe: &str) {
    let _ = netsh(&["advfirewall", "firewall", "delete", "rule", &format!("name={PREFIX}: {exe}")]);
}

#[cfg(not(windows))]
pub fn blocked() -> Vec<Blocked> {
    Vec::new()
}
#[cfg(not(windows))]
pub fn block_dir(exe: &str, _dir: Dir) -> Result<(), String> {
    validate(exe)?;
    Err("firewall control is not implemented on this platform yet".into())
}
#[cfg(not(windows))]
pub fn unblock_dir(_exe: &str, _dir: Dir) -> Result<(), String> {
    Err("firewall control is not implemented on this platform yet".into())
}
#[cfg(not(windows))]
fn delete_legacy(_exe: &str) {}

/// Block both directions.
pub fn block(exe: &str) -> Result<(), String> {
    block_dir(exe, Dir::Out)?;
    block_dir(exe, Dir::In)
}

/// Remove every ConWatch rule for this executable (both directions, including legacy rules).
pub fn unblock(exe: &str) -> Result<(), String> {
    delete_legacy(exe);
    let a = unblock_dir(exe, Dir::Out);
    let b = unblock_dir(exe, Dir::In);
    a.and(b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_rule_names() {
        assert_eq!(parse_rule_line("Rule Name:  ConWatch block [out]: C:\\a.exe"), Some(("C:\\a.exe".into(), false, true)));
        assert_eq!(parse_rule_line("Nazwa reguły: ConWatch block [in]: C:\\a.exe"), Some(("C:\\a.exe".into(), true, false)));
        assert_eq!(parse_rule_line("Rule Name: ConWatch block: C:\\a.exe"), Some(("C:\\a.exe".into(), true, true)));
        assert_eq!(parse_rule_line("Rule Name: Something else"), None);
    }

    #[test]
    fn merges_directions() {
        let v = merge_rules(vec![("C:\\a.exe".into(), false, true), ("c:\\A.exe".into(), true, false)].into_iter());
        assert_eq!(v, vec![Blocked { exe: "C:\\a.exe".into(), inbound: true, outbound: true }]);
    }
}
