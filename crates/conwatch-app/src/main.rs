#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]
//! ConWatch desktop shell: native window (system webview) + tray icon showing live speed.

use conwatch_core::event::Event as NetEvent;
use conwatch_core::traffic::TrafficSampler;
use std::time::{Duration, Instant};
use tao::dpi::LogicalSize;
use tao::event::{Event, StartCause, WindowEvent};
use tao::event_loop::{ControlFlow, EventLoopBuilder};
use tao::window::WindowBuilder;
use tray_icon::menu::{Menu, MenuEvent, MenuItem};
use tray_icon::{Icon, TrayIconBuilder, TrayIconEvent};
use wry::WebViewBuilder;

const PORT: u16 = 8650;

fn human(bps: u64) -> String {
    let (mut v, mut i) = (bps as f64, 0);
    while v >= 1024.0 && i < 3 {
        v /= 1024.0;
        i += 1;
    }
    format!("{v:.1} {}/s", ["B", "KB", "MB", "GB"][i])
}

/// 32x32 blue disc with a white down-arrow, generated at runtime (no asset files).
fn icon() -> Icon {
    let n = 32usize;
    let mut px = vec![0u8; n * n * 4];
    for y in 0..n {
        for x in 0..n {
            let (dx, dy) = (x as f32 - 15.5, y as f32 - 15.5);
            let inside = dx * dx + dy * dy <= 15.0 * 15.0;
            let arrow = (x >= 14 && x <= 17 && (7..18).contains(&y)) || ((y as i32 - 17).abs() as f32 <= 8.0 - (x as f32 - 15.5).abs() && y >= 17 && y < 25);
            let c = if !inside { [0, 0, 0, 0] } else if arrow { [255, 255, 255, 255] } else { [47, 124, 246, 255] };
            let o = (y * n + x) * 4;
            px[o..o + 4].copy_from_slice(&c);
        }
    }
    Icon::from_rgba(px, n as u32, n as u32).expect("icon")
}

fn main() {
    let url = match conwatch_cli::serve::start(PORT) {
        Ok(u) => u,
        // Another instance (or the CLI) already serves the dashboard: just attach to it.
        Err(_) => format!("http://127.0.0.1:{PORT}"),
    };

    let event_loop = EventLoopBuilder::new().build();
    let window = WindowBuilder::new()
        .with_title("ConWatch")
        .with_inner_size(LogicalSize::new(1100.0, 760.0))
        .build(&event_loop)
        .expect("window");
    let _webview = WebViewBuilder::new().with_url(&url).build(&window).expect("webview");

    let menu = Menu::new();
    let show = MenuItem::new("Open ConWatch", true, None);
    let quit = MenuItem::new("Quit", true, None);
    let _ = menu.append_items(&[&show, &quit]);
    let (show_id, quit_id) = (show.id().clone(), quit.id().clone());
    let tray = TrayIconBuilder::new().with_menu(Box::new(menu)).with_tooltip("ConWatch").with_icon(icon()).build().expect("tray");

    let mut sampler = TrafficSampler::new();
    event_loop.run(move |event, _, flow| {
        *flow = ControlFlow::WaitUntil(Instant::now() + Duration::from_secs(1));
        match event {
            Event::NewEvents(StartCause::ResumeTimeReached { .. }) | Event::NewEvents(StartCause::Init) => {
                if let NetEvent::TrafficSample { rx_bytes, tx_bytes, interval_ms } = sampler.sample() {
                    let (rx, tx) = (rx_bytes * 1000 / interval_ms, tx_bytes * 1000 / interval_ms);
                    let _ = tray.set_tooltip(Some(format!("ConWatch\n▼ {}  ▲ {}", human(rx), human(tx))));
                }
            }
            // Closing the window hides it to the tray; use the tray menu to quit.
            Event::WindowEvent { event: WindowEvent::CloseRequested, .. } => window.set_visible(false),
            _ => {}
        }
        while let Ok(ev) = MenuEvent::receiver().try_recv() {
            if ev.id == show_id {
                window.set_visible(true);
                window.set_focus();
            } else if ev.id == quit_id {
                *flow = ControlFlow::Exit;
            }
        }
        while let Ok(ev) = TrayIconEvent::receiver().try_recv() {
            if matches!(ev, TrayIconEvent::DoubleClick { .. }) {
                window.set_visible(true);
                window.set_focus();
            }
        }
    });
}
