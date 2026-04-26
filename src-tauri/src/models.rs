use serde::{Deserialize, Serialize};

pub const PROTOCOL_VERSION: &str = "0.1";
pub const SERVICE_TYPE: &str = "_sharingm._tcp.local.";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AppMode {
    Sender,
    Receiver,
}

impl Default for AppMode {
    fn default() -> Self {
        Self::Sender
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceIdentity {
    pub device_id: String,
    pub device_name: String,
    pub public_key: String,
    pub fingerprint: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LanDevice {
    pub device_id: String,
    pub device_name: String,
    pub address: String,
    pub port: u16,
    pub public_key: String,
    pub fingerprint: String,
    pub protocol_version: String,
    pub capabilities: Vec<String>,
    pub last_seen_ms: i64,
    #[serde(default)]
    pub extra_addresses: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustedDevice {
    pub device_id: String,
    pub device_name: String,
    pub public_key: String,
    pub fingerprint: String,
    pub trusted_at_ms: i64,
    pub last_connected_ms: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingPairing {
    pub device_id: String,
    pub device_name: String,
    pub code: String,
    pub expires_at_ms: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferRecord {
    pub id: String,
    pub file_name: String,
    pub destination: String,
    pub size_bytes: u64,
    pub hash: String,
    pub completed_at_ms: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScreenSession {
    pub id: String,
    pub device_id: String,
    pub display_name: String,
    pub width: u32,
    pub height: u32,
    pub fps: u32,
    pub bitrate_kbps: u32,
    pub source_kind: DisplaySourceKind,
    pub started_at_ms: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DisplaySourceKind {
    CaptureSource,
    VirtualDisplaySource,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppSnapshot {
    pub identity: DeviceIdentity,
    pub mode: AppMode,
    pub autostart_required: bool,
    pub discovery_active: bool,
    pub trusted_devices: Vec<TrustedDevice>,
    pub discovered_devices: Vec<LanDevice>,
    pub pending_pairing: Option<PendingPairing>,
    pub transfers: Vec<TransferRecord>,
    pub screen_session: Option<ScreenSession>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairingResult {
    pub trusted: bool,
    pub challenge_required: bool,
    pub code_hint: Option<String>,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileTransferRequest {
    pub source_path: String,
    pub target_device_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StartScreenRequest {
    pub target_device_id: String,
    pub display_name: String,
    pub width: u32,
    pub height: u32,
    pub fps: u32,
    pub bitrate_kbps: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosticStatus {
    Ok,
    Warn,
    Fail,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiagnosticItem {
    pub id: String,
    pub label: String,
    pub status: DiagnosticStatus,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiagnosticInterface {
    pub name: String,
    pub address: String,
    pub broadcast: Option<String>,
    pub is_loopback: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkDiagnosticReport {
    pub mode: AppMode,
    pub generated_at_ms: i64,
    pub overall_status: DiagnosticStatus,
    pub items: Vec<DiagnosticItem>,
    pub interfaces: Vec<DiagnosticInterface>,
    pub broadcast_targets: Vec<String>,
    pub firewall_hint: Option<String>,
}
