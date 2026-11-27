use serde::{Deserialize, Serialize};
use std::net::IpAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Proto {
    Tcp,
    Udp,
}

/// A single network connection attributed to a process.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Connection {
    pub proto: Proto,
    pub local_addr: IpAddr,
    pub local_port: u16,
    pub remote_addr: IpAddr,
    pub remote_port: u16,
    pub pid: u32,
    pub process: String,
    pub exe: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AlertLevel {
    Info,
    Warning,
    Critical,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Alert {
    pub level: AlertLevel,
    pub source: String,
    pub message: String,
}

/// Events flowing through the engine. This is also the wire format sent
/// to external modules (one JSON object per line).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Event {
    ConnectionOpened(Connection),
    ConnectionClosed(Connection),
    /// First time this executable name was seen talking to the network.
    AppFirstSeen { process: String, exe: Option<String> },
    /// Bytes transferred over all interfaces during the last sampling interval.
    TrafficSample { rx_bytes: u64, tx_bytes: u64, interval_ms: u64 },
    /// A device seen on the local network.
    DeviceSeen { ip: String, mac: String },
    Alert(Alert),
}
