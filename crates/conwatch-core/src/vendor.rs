//! MAC vendor lookup (IEEE OUI public registry, embedded) and a rough device-kind guess.

use std::sync::OnceLock;

const OUI: &str = include_str!("../data/oui.tsv");

fn table() -> &'static Vec<(&'static str, &'static str)> {
    static T: OnceLock<Vec<(&'static str, &'static str)>> = OnceLock::new();
    T.get_or_init(|| OUI.lines().filter_map(|l| l.split_once('\t')).collect())
}

/// Vendor for a `aa:bb:cc:dd:ee:ff` style MAC (locally administered / random MACs return None).
pub fn vendor(mac: &str) -> Option<&'static str> {
    let hex: String = mac.chars().filter(|c| c.is_ascii_hexdigit()).take(6).collect::<String>().to_lowercase();
    if hex.len() < 6 {
        return None;
    }
    // Bit 1 of the first octet set = locally administered (privacy/random address): no vendor.
    if u8::from_str_radix(&hex[..2], 16).ok()? & 0x02 != 0 {
        return None;
    }
    let t = table();
    t.binary_search_by(|(p, _)| (*p).cmp(hex.as_str())).ok().map(|i| t[i].1)
}

/// "router" | "printer" | "smart" | "computer" | "phone" | "tv" | "generic"
pub fn kind(vendor: Option<&str>, is_gateway: bool) -> &'static str {
    if is_gateway {
        return "router";
    }
    let v = vendor.unwrap_or("").to_lowercase();
    let has = |words: &[&str]| words.iter().any(|w| v.contains(w));
    if has(&["brother", "canon", "epson", "xerox", "lexmark", "kyocera", "ricoh", "konica"]) {
        "printer"
    } else if has(&["tuya", "espressif", "shelly", "sonoff", "ewelink", "yeelight", "tp-link smart", "philips lighting", "signify", "ring", "nest", "ecobee", "hikvision", "dahua", "reolink", "amazon", "sonos"]) {
        "smart"
    } else if has(&["huawei", "tp-link", "netgear", "d-link", "zyxel", "mikrotik", "ubiquiti", "linksys", "zte", "technicolor", "sagemcom", "asustek", "arris", "fritz", "avm"]) {
        "router"
    } else if has(&["micro-star", "msi", "gigabyte", "dell", "lenovo", "hewlett", "hp ", "intel", "realtek", "asrock", "acer", "azurewave", "liteon", "microsoft"]) {
        "computer"
    } else if has(&["apple", "samsung", "xiaomi", "oppo", "oneplus", "vivo", "motorola", "google"]) {
        "phone"
    } else if has(&["lg elec", "sony", "tcl", "hisense", "roku", "vizio"]) {
        "tv"
    } else {
        "generic"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn lookup() {
        assert_eq!(vendor("d8:d6:68:47:7a:6a"), Some("Tuya Smart"));
        assert_eq!(vendor("fa:68:e9:9b:e1:7b"), None); // locally administered
        assert_eq!(kind(Some("Tuya Smart"), false), "smart");
        assert_eq!(kind(None, true), "router");
        // table must be sorted for binary search
        let t = table();
        assert!(t.windows(2).all(|w| w[0].0 <= w[1].0));
    }
}
