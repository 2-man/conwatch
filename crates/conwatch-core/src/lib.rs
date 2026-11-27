//! ConWatch core: event model, module API and platform network monitors.

pub mod builtin;
pub mod engine;
pub mod event;
pub mod external;
pub mod firewall;
pub mod lan;
pub mod module;
pub mod monitor;
pub mod procnet;
pub mod resolve;
pub mod settings;
pub mod storage;
pub mod traffic;
#[cfg(all(windows, feature = "wfp"))]
pub mod wfp;

/// Run helper processes without flashing a console window (the GUI app has no console of its own).
pub fn no_window(cmd: &mut std::process::Command) -> &mut std::process::Command {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    cmd
}

pub use engine::Engine;
pub use event::{Alert, AlertLevel, Connection, Event, Proto};
pub use module::{Context, Module};
