//! Application icons: extracts the icon of an executable and encodes it as PNG.
//! Windows only; other platforms return `None` (the UI falls back to a letter avatar).

use std::io::Write;

/// Minimal PNG encoder for 8-bit RGBA images.
pub fn png_encode(rgba: &[u8], w: u32, h: u32) -> Vec<u8> {
    fn crc(data: &[u8]) -> u32 {
        let mut c = 0xffff_ffffu32;
        for &b in data {
            c ^= b as u32;
            for _ in 0..8 {
                c = if c & 1 != 0 { 0xedb8_8320 ^ (c >> 1) } else { c >> 1 };
            }
        }
        !c
    }
    fn chunk(out: &mut Vec<u8>, kind: &[u8; 4], data: &[u8]) {
        out.extend_from_slice(&(data.len() as u32).to_be_bytes());
        let mut body = kind.to_vec();
        body.extend_from_slice(data);
        out.extend_from_slice(&body);
        out.extend_from_slice(&crc(&body).to_be_bytes());
    }
    let mut raw = Vec::with_capacity((w as usize * 4 + 1) * h as usize);
    for row in rgba.chunks(w as usize * 4) {
        raw.push(0); // filter: none
        raw.extend_from_slice(row);
    }
    let mut z = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::fast());
    let _ = z.write_all(&raw);
    let idat = z.finish().unwrap_or_default();
    let mut out = vec![0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a];
    let mut ihdr = Vec::new();
    ihdr.extend_from_slice(&w.to_be_bytes());
    ihdr.extend_from_slice(&h.to_be_bytes());
    ihdr.extend_from_slice(&[8, 6, 0, 0, 0]); // 8-bit, RGBA
    chunk(&mut out, b"IHDR", &ihdr);
    chunk(&mut out, b"IDAT", &idat);
    chunk(&mut out, b"IEND", &[]);
    out
}

/// PNG bytes of the executable's (large) icon.
#[cfg(windows)]
pub fn exe_icon_png(path: &str) -> Option<Vec<u8>> {
    let (w, h, rgba) = exe_icon_rgba(path)?;
    Some(png_encode(&rgba, w, h))
}

#[cfg(not(windows))]
pub fn exe_icon_png(_path: &str) -> Option<Vec<u8>> {
    None
}

#[cfg(windows)]
fn exe_icon_rgba(path: &str) -> Option<(u32, u32, Vec<u8>)> {
    use std::ffi::c_void;
    use windows::core::PCWSTR;
    use windows::Win32::Graphics::Gdi::*;
    use windows::Win32::Storage::FileSystem::FILE_FLAGS_AND_ATTRIBUTES;
    use windows::Win32::UI::Shell::{SHGetFileInfoW, SHFILEINFOW, SHGFI_ICON, SHGFI_LARGEICON};
    use windows::Win32::UI::WindowsAndMessaging::{DestroyIcon, GetIconInfo, ICONINFO};

    unsafe {
        let wide: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();
        let mut sfi = SHFILEINFOW::default();
        let r = SHGetFileInfoW(
            PCWSTR(wide.as_ptr()),
            FILE_FLAGS_AND_ATTRIBUTES(0),
            Some(&mut sfi),
            std::mem::size_of::<SHFILEINFOW>() as u32,
            SHGFI_ICON | SHGFI_LARGEICON,
        );
        if r == 0 || sfi.hIcon.is_invalid() {
            return None;
        }
        let mut ii = ICONINFO::default();
        let ok = GetIconInfo(sfi.hIcon, &mut ii).is_ok();
        let result = if ok && !ii.hbmColor.is_invalid() {
            let mut bm = BITMAP::default();
            GetObjectW(HGDIOBJ(ii.hbmColor.0), std::mem::size_of::<BITMAP>() as i32, Some(&mut bm as *mut _ as *mut c_void));
            let (w, h) = (bm.bmWidth, bm.bmHeight);
            if w <= 0 || h <= 0 || w > 256 || h > 256 {
                None
            } else {
                let hdc = GetDC(None);
                let mut bi = BITMAPINFO {
                    bmiHeader: BITMAPINFOHEADER {
                        biSize: std::mem::size_of::<BITMAPINFOHEADER>() as u32,
                        biWidth: w,
                        biHeight: -h, // top-down
                        biPlanes: 1,
                        biBitCount: 32,
                        biCompression: BI_RGB.0,
                        ..Default::default()
                    },
                    ..Default::default()
                };
                let n = (w * h * 4) as usize;
                let mut px = vec![0u8; n];
                let mut mask = vec![0u8; n];
                let got = GetDIBits(hdc, ii.hbmColor, 0, h as u32, Some(px.as_mut_ptr() as *mut c_void), &mut bi, DIB_RGB_COLORS);
                let got_m = if !ii.hbmMask.is_invalid() {
                    GetDIBits(hdc, ii.hbmMask, 0, h as u32, Some(mask.as_mut_ptr() as *mut c_void), &mut bi, DIB_RGB_COLORS)
                } else {
                    0
                };
                ReleaseDC(None, hdc);
                if got == 0 {
                    None
                } else {
                    let has_alpha = px.chunks(4).any(|p| p[3] != 0);
                    for (i, p) in px.chunks_mut(4).enumerate() {
                        p.swap(0, 2); // BGRA -> RGBA
                        if !has_alpha {
                            // Legacy icon: transparency comes from the AND mask (white = transparent).
                            let transparent = got_m != 0 && mask[i * 4] != 0;
                            p[3] = if transparent { 0 } else { 255 };
                        }
                    }
                    Some((w as u32, h as u32, px))
                }
            }
        } else {
            None
        };
        if !ii.hbmColor.is_invalid() {
            let _ = DeleteObject(HGDIOBJ(ii.hbmColor.0));
        }
        if !ii.hbmMask.is_invalid() {
            let _ = DeleteObject(HGDIOBJ(ii.hbmMask.0));
        }
        let _ = DestroyIcon(sfi.hIcon);
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn png_has_valid_structure() {
        let px = vec![255u8, 0, 0, 255, 0, 255, 0, 128, 0, 0, 255, 0, 1, 2, 3, 4];
        let png = png_encode(&px, 2, 2);
        assert_eq!(&png[..8], &[0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a]);
        assert_eq!(&png[12..16], b"IHDR");
        assert_eq!(&png[png.len() - 8..png.len() - 4], b"IEND");
    }

    #[cfg(windows)]
    #[test]
    fn extracts_notepad_icon() {
        let p = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".into()) + "\\System32\\notepad.exe";
        let png = exe_icon_png(&p).expect("icon");
        assert!(png.len() > 100 && &png[1..4] == b"PNG");
    }
}
