//! EXPERIMENTAL / UNVERIFIED: application blocking through the Windows Filtering Platform.
//!
//! Adds persistent filters at the ALE connect layers (IPv4 + IPv6) matching the application id,
//! so connection attempts are dropped before any packet leaves. Needs Administrator.
//! Note: this is equivalent in effect to a firewall rule; it cannot *hold* a first connection
//! to ask the user (that needs a signed kernel callout driver, which is out of scope).
//! Enabled with the `wfp` cargo feature.

use std::ffi::c_void;
use windows::core::{GUID, PCWSTR, PWSTR};
use windows::Win32::Foundation::HANDLE;
use windows::Win32::NetworkManagement::WindowsFilteringPlatform::*;

const RPC_C_AUTHN_WINNT: u32 = 10;

fn fnv(data: &[u8], seed: u64) -> u64 {
    let mut h = 0xcbf29ce484222325u64 ^ seed;
    for b in data {
        h ^= *b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

/// Stable filter key per (exe, layer index) so the filter can be removed later.
fn key(exe: &str, idx: u8) -> GUID {
    let lower = exe.to_lowercase();
    let (a, b) = (fnv(lower.as_bytes(), idx as u64), fnv(lower.as_bytes(), 0x9e3779b97f4a7c15 ^ idx as u64));
    GUID::from_values(a as u32, (a >> 32) as u16, (a >> 48) as u16, b.to_le_bytes())
}

fn check(code: u32, what: &str) -> Result<(), String> {
    if code == 0 {
        Ok(())
    } else {
        Err(format!("{what} failed (error 0x{code:08x}); run as Administrator"))
    }
}

struct Engine(HANDLE);
impl Engine {
    fn open() -> Result<Self, String> {
        let mut h = HANDLE::default();
        check(unsafe { FwpmEngineOpen0(PCWSTR::null(), RPC_C_AUTHN_WINNT, None, None, &mut h) }, "FwpmEngineOpen0")?;
        Ok(Engine(h))
    }
}
impl Drop for Engine {
    fn drop(&mut self) {
        unsafe {
            let _ = FwpmEngineClose0(self.0);
        }
    }
}

pub fn block_app(exe: &str) -> Result<(), String> {
    let eng = Engine::open()?;
    let wide: Vec<u16> = exe.encode_utf16().chain(std::iter::once(0)).collect();
    let mut blob: *mut FWP_BYTE_BLOB = std::ptr::null_mut();
    check(unsafe { FwpmGetAppIdFromFileName0(PCWSTR(wide.as_ptr()), &mut blob) }, "FwpmGetAppIdFromFileName0")?;

    let mut result = Ok(());
    let mut name: Vec<u16> = "ConWatch block".encode_utf16().chain(std::iter::once(0)).collect();
    for (idx, layer) in [(0u8, FWPM_LAYER_ALE_AUTH_CONNECT_V4), (1u8, FWPM_LAYER_ALE_AUTH_CONNECT_V6)] {
        let mut cond = FWPM_FILTER_CONDITION0::default();
        cond.fieldKey = FWPM_CONDITION_ALE_APP_ID;
        cond.matchType = FWP_MATCH_EQUAL;
        cond.conditionValue.r#type = FWP_BYTE_BLOB_TYPE;
        cond.conditionValue.Anonymous.byteBlob = blob;

        let mut f = FWPM_FILTER0::default();
        f.filterKey = key(exe, idx);
        f.displayData.name = PWSTR(name.as_mut_ptr());
        f.flags = FWPM_FILTER_FLAGS(FWPM_FILTER_FLAG_PERSISTENT.0);
        f.layerKey = layer;
        f.subLayerKey = FWPM_SUBLAYER_UNIVERSAL;
        f.action.r#type = FWP_ACTION_BLOCK;
        f.numFilterConditions = 1;
        f.filterCondition = &mut cond;
        let mut id = 0u64;
        result = check(unsafe { FwpmFilterAdd0(eng.0, &f, None, Some(&mut id)) }, "FwpmFilterAdd0");
        if result.is_err() {
            break;
        }
    }
    unsafe { FwpmFreeMemory0(&mut blob as *mut _ as *mut *mut c_void) };
    result
}

pub fn unblock_app(exe: &str) -> Result<(), String> {
    let eng = Engine::open()?;
    for idx in 0..2u8 {
        let k = key(exe, idx);
        // 0x80320009 = FWP_E_FILTER_NOT_FOUND: nothing to remove for this layer.
        let code = unsafe { FwpmFilterDeleteByKey0(eng.0, &k) };
        if code != 0 && code != 0x8032_0003 && code != 0x8032_0009 {
            return check(code, "FwpmFilterDeleteByKey0");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn keys_are_stable_and_distinct() {
        assert_eq!(key("C:\\A.exe", 0), key("c:\\a.exe", 0));
        assert_ne!(key("C:\\A.exe", 0), key("C:\\A.exe", 1));
        assert_ne!(key("C:\\A.exe", 0), key("C:\\B.exe", 0));
    }
}
