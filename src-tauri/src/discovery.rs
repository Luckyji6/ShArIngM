use crate::{
    clipboard,
    identity::Identity,
    models::{
        AppMode, ClipboardTextRecord, DeviceIdentity, DiagnosticInterface, DiagnosticItem,
        DiagnosticStatus, LanDevice, NetworkDiagnosticReport, PairingResult, PendingPairing,
        ScreenFrame, ScreenSession, TransferRecord, TrustedDevice, PROTOCOL_VERSION, SERVICE_TYPE,
    },
    storage, transfer,
};
use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose, Engine};
use chrono::Utc;
use mdns_sd::{ServiceDaemon, ServiceEvent, ServiceInfo};
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    io::{ErrorKind, Read, Write},
    net::{IpAddr, Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream, UdpSocket},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};
use uuid::Uuid;

const SERVICE_PORT: u16 = 41874;
const UDP_DISCOVERY_PORT: u16 = 41875;
const UDP_DISCOVERY_REQUEST: &[u8] = b"SHARINGM_DISCOVER_V1";
const DISCOVERY_TIMEOUT: Duration = Duration::from_millis(4500);
const CONTROL_PROBE_TIMEOUT: Duration = Duration::from_millis(1500);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DiscoverySource {
    Mdns,
    Udp,
}

#[derive(Clone)]
struct DiscoveryEntry {
    device: LanDevice,
    source: DiscoverySource,
}

#[derive(Clone)]
struct IncomingPairing {
    requester: DeviceIdentity,
    pending: PendingPairing,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum ControlRequest {
    Ping,
    PairRequest {
        requester: DeviceIdentity,
    },
    VerifyPairing {
        requester: DeviceIdentity,
        code: String,
    },
    FilePush {
        sender: DeviceIdentity,
        file_name: String,
        size_bytes: u64,
        hash: String,
    },
    ScreenFrame {
        sender: DeviceIdentity,
        session: ScreenSession,
        width: u32,
        height: u32,
        mime_type: String,
        frame_size: u64,
    },
    ClipboardText {
        sender: DeviceIdentity,
        text: String,
    },
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum ControlResponse {
    Pong,
    PairChallenge {
        expires_at_ms: i64,
        message: String,
    },
    PairAccepted {
        trusted_device: TrustedDevice,
        message: String,
    },
    FileAccepted {
        record: TransferRecord,
        message: String,
    },
    ScreenFrameAccepted,
    ClipboardTextAccepted {
        record: ClipboardTextRecord,
        message: String,
    },
    Error {
        message: String,
    },
}

#[derive(Default)]
pub struct DiscoveryRuntime {
    mdns: Option<ServiceDaemon>,
    registered_name: Option<String>,
    udp_shutdown: Option<Arc<AtomicBool>>,
    udp_thread: Option<JoinHandle<()>>,
    tcp_shutdown: Option<Arc<AtomicBool>>,
    tcp_thread: Option<JoinHandle<()>>,
    pending_pairing: Arc<Mutex<Option<IncomingPairing>>>,
    trusted_updates: Arc<Mutex<Vec<TrustedDevice>>>,
    transfer_updates: Arc<Mutex<Vec<TransferRecord>>>,
    clipboard_updates: Arc<Mutex<Vec<ClipboardTextRecord>>>,
    latest_screen_frame: Arc<Mutex<Option<ScreenFrame>>>,
}

impl DiscoveryRuntime {
    pub fn start_receiver(&mut self, identity: &Identity, config_path: PathBuf) -> Result<()> {
        if self.mdns.is_some() && self.udp_thread.is_some() && self.tcp_thread.is_some() {
            return Ok(());
        }

        let mut errors = Vec::new();
        if self.tcp_thread.is_none() {
            if let Err(error) = self.start_tcp_control_listener(identity, config_path) {
                errors.push(format!("TCP control listener: {error:#}"));
            }
        }
        if self.udp_thread.is_none() {
            if let Err(error) = self.start_udp_responder(identity) {
                errors.push(format!("UDP broadcast discovery: {error:#}"));
            }
        }
        if self.mdns.is_none() {
            if let Err(error) = self.start_mdns_advertiser(identity) {
                errors.push(format!("mDNS discovery: {error:#}"));
            }
        }

        if self.tcp_thread.is_some() && (self.mdns.is_some() || self.udp_thread.is_some()) {
            Ok(())
        } else {
            Err(anyhow!(
                "failed to start receiver discovery: {}",
                errors.join("; ")
            ))
        }
    }

    pub fn pending_pairing(&self) -> Option<PendingPairing> {
        self.pending_pairing
            .lock()
            .ok()
            .and_then(|pending| pending.as_ref().map(|item| item.pending.clone()))
    }

    pub fn drain_trusted_updates(&self) -> Vec<TrustedDevice> {
        self.trusted_updates
            .lock()
            .map(|mut updates| updates.drain(..).collect())
            .unwrap_or_default()
    }

    pub fn drain_transfer_updates(&self) -> Vec<TransferRecord> {
        self.transfer_updates
            .lock()
            .map(|mut updates| updates.drain(..).collect())
            .unwrap_or_default()
    }

    pub fn drain_clipboard_updates(&self) -> Vec<ClipboardTextRecord> {
        self.clipboard_updates
            .lock()
            .map(|mut updates| updates.drain(..).collect())
            .unwrap_or_default()
    }

    #[allow(dead_code)]
    pub fn latest_screen_frame(&self) -> Option<ScreenFrame> {
        self.latest_screen_frame
            .lock()
            .ok()
            .and_then(|frame| frame.clone())
    }

    fn start_mdns_advertiser(&mut self, identity: &Identity) -> Result<()> {
        let mdns = ServiceDaemon::new().context("failed to start mDNS daemon")?;
        let public = identity.public_identity();
        let instance = format!("sharingm-{}", public.device_id);
        let host_name = format!("{}.local.", hostname::get()?.to_string_lossy());
        let props = [
            ("device_id", public.device_id.as_str()),
            ("device_name", public.device_name.as_str()),
            ("public_key", public.public_key.as_str()),
            ("fingerprint", public.fingerprint.as_str()),
            ("protocol_version", PROTOCOL_VERSION),
            ("capabilities", "screen_stream,file_push,clipboard_text"),
        ];
        let info = ServiceInfo::new(
            SERVICE_TYPE,
            &instance,
            &host_name,
            "",
            SERVICE_PORT,
            &props[..],
        )?
        .enable_addr_auto();

        let fullname = info.get_fullname().to_string();
        mdns.register(info)?;
        self.registered_name = Some(fullname);
        self.mdns = Some(mdns);
        Ok(())
    }

    pub fn stop(&mut self) {
        if let (Some(mdns), Some(name)) = (&self.mdns, &self.registered_name) {
            let _ = mdns.unregister(name);
        }
        if let Some(shutdown) = self.udp_shutdown.take() {
            shutdown.store(true, Ordering::SeqCst);
        }
        if let Some(handle) = self.udp_thread.take() {
            let _ = handle.join();
        }
        if let Some(shutdown) = self.tcp_shutdown.take() {
            shutdown.store(true, Ordering::SeqCst);
        }
        if let Some(handle) = self.tcp_thread.take() {
            let _ = handle.join();
        }
        self.registered_name = None;
        self.mdns = None;
    }

    fn start_udp_responder(&mut self, identity: &Identity) -> Result<()> {
        if self.udp_thread.is_some() {
            return Ok(());
        }

        let socket = UdpSocket::bind(("0.0.0.0", UDP_DISCOVERY_PORT))
            .with_context(|| format!("failed to bind UDP discovery port {UDP_DISCOVERY_PORT}"))?;
        socket
            .set_read_timeout(Some(Duration::from_millis(250)))
            .context("failed to configure UDP discovery socket")?;

        let shutdown = Arc::new(AtomicBool::new(false));
        let thread_shutdown = shutdown.clone();
        let public = identity.public_identity();
        let handle = thread::spawn(move || {
            let mut buf = [0_u8; 256];
            while !thread_shutdown.load(Ordering::SeqCst) {
                match socket.recv_from(&mut buf) {
                    Ok((len, peer)) if &buf[..len] == UDP_DISCOVERY_REQUEST => {
                        let device = lan_device_from_identity(&public, String::new());
                        if let Ok(payload) = serde_json::to_vec(&device) {
                            let _ = socket.send_to(&payload, peer);
                        }
                    }
                    Ok(_) => {}
                    Err(error)
                        if matches!(
                            error.kind(),
                            ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::Interrupted
                        ) => {}
                    Err(_) => break,
                }
            }
        });

        self.udp_shutdown = Some(shutdown);
        self.udp_thread = Some(handle);
        Ok(())
    }

    fn start_tcp_control_listener(
        &mut self,
        identity: &Identity,
        config_path: PathBuf,
    ) -> Result<()> {
        if self.tcp_thread.is_some() {
            return Ok(());
        }

        let listener = TcpListener::bind(("0.0.0.0", SERVICE_PORT))
            .with_context(|| format!("failed to bind TCP control port {SERVICE_PORT}"))?;
        listener
            .set_nonblocking(true)
            .context("failed to configure TCP control listener")?;

        let shutdown = Arc::new(AtomicBool::new(false));
        let thread_shutdown = shutdown.clone();
        let receiver = identity.public_identity();
        let pending_pairing = self.pending_pairing.clone();
        let trusted_updates = self.trusted_updates.clone();
        let transfer_updates = self.transfer_updates.clone();
        let clipboard_updates = self.clipboard_updates.clone();
        let latest_screen_frame = self.latest_screen_frame.clone();
        let handle = thread::spawn(move || {
            while !thread_shutdown.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((mut stream, _peer)) => {
                        let _ = stream.set_read_timeout(Some(Duration::from_millis(1500)));
                        let _ = stream.set_write_timeout(Some(Duration::from_millis(1500)));
                        handle_control_stream(
                            &mut stream,
                            &receiver,
                            &config_path,
                            &pending_pairing,
                            &trusted_updates,
                            &transfer_updates,
                            &clipboard_updates,
                            &latest_screen_frame,
                        );
                    }
                    Err(error) if error.kind() == ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(50));
                    }
                    Err(_) => break,
                }
            }
        });

        self.tcp_shutdown = Some(shutdown);
        self.tcp_thread = Some(handle);
        Ok(())
    }
}

pub fn send_remote_file(
    addresses: &[String],
    port: u16,
    sender: &DeviceIdentity,
    source_path: &str,
) -> Result<(String, TransferRecord)> {
    let source = transfer::inspect_source(source_path)?;
    let mut errors = Vec::new();
    for address in addresses {
        if address.is_empty() {
            continue;
        }
        match send_file_to_address(address, port, sender, &source) {
            Ok(record) => return Ok((address.clone(), record)),
            Err(error) => errors.push(format!("{address}: {error:#}")),
        }
    }

    Err(anyhow!(
        "all candidate addresses failed file transfer: {}",
        errors.join("; ")
    ))
}

#[allow(dead_code)]
pub fn send_screen_frame(
    addresses: &[String],
    port: u16,
    sender: &DeviceIdentity,
    session: &ScreenSession,
    width: u32,
    height: u32,
    mime_type: String,
    bytes: Vec<u8>,
) -> Result<String> {
    let mut errors = Vec::new();
    let frame_size = bytes.len() as u64;
    for address in addresses {
        if address.is_empty() {
            continue;
        }
        match send_control_request_with_body(
            address,
            port,
            &ControlRequest::ScreenFrame {
                sender: sender.clone(),
                session: session.clone(),
                width,
                height,
                mime_type: mime_type.clone(),
                frame_size,
            },
            std::io::Cursor::new(bytes.clone()),
        ) {
            Ok(ControlResponse::ScreenFrameAccepted) => return Ok(address.clone()),
            Ok(ControlResponse::Error { message }) => errors.push(format!("{address}: {message}")),
            Ok(_) => errors.push(format!("{address}: unexpected screen frame response")),
            Err(error) => errors.push(format!("{address}: {error:#}")),
        }
    }

    Err(anyhow!(
        "all candidate addresses failed screen frame transfer: {}",
        errors.join("; ")
    ))
}

pub fn send_remote_clipboard_text(
    addresses: &[String],
    port: u16,
    sender: &DeviceIdentity,
    text: &str,
) -> Result<(String, ClipboardTextRecord)> {
    let mut errors = Vec::new();
    for address in addresses {
        if address.is_empty() {
            continue;
        }
        match send_control_request(
            address,
            port,
            &ControlRequest::ClipboardText {
                sender: sender.clone(),
                text: text.to_string(),
            },
        ) {
            Ok(ControlResponse::ClipboardTextAccepted { record, .. }) => {
                return Ok((address.clone(), record));
            }
            Ok(ControlResponse::Error { message }) => errors.push(format!("{address}: {message}")),
            Ok(_) => errors.push(format!("{address}: unexpected clipboard response")),
            Err(error) => errors.push(format!("{address}: {error:#}")),
        }
    }

    Err(anyhow!(
        "all candidate addresses failed clipboard transfer: {}",
        errors.join("; ")
    ))
}

pub fn request_remote_pairing(
    addresses: &[String],
    port: u16,
    requester: &DeviceIdentity,
) -> Result<(String, PairingResult)> {
    let response = send_control_request_any(
        addresses,
        port,
        &ControlRequest::PairRequest {
            requester: requester.clone(),
        },
    )?;

    match response {
        (address, ControlResponse::PairChallenge { message, .. }) => Ok((
            address,
            PairingResult {
                trusted: false,
                challenge_required: true,
                code_hint: None,
                message,
            },
        )),
        (_, ControlResponse::Error { message }) => Err(anyhow!(message)),
        (_, _) => Err(anyhow!("unexpected pairing response from receiver")),
    }
}

pub fn verify_remote_pairing(
    addresses: &[String],
    port: u16,
    requester: &DeviceIdentity,
    code: &str,
) -> Result<(String, TrustedDevice, PairingResult)> {
    let response = send_control_request_any(
        addresses,
        port,
        &ControlRequest::VerifyPairing {
            requester: requester.clone(),
            code: code.trim().to_string(),
        },
    )?;

    match response {
        (
            address,
            ControlResponse::PairAccepted {
                trusted_device,
                message,
            },
        ) => Ok((
            address,
            trusted_device,
            PairingResult {
                trusted: true,
                challenge_required: false,
                code_hint: None,
                message,
            },
        )),
        (_, ControlResponse::Error { message }) => Err(anyhow!(message)),
        (_, _) => Err(anyhow!("unexpected verification response from receiver")),
    }
}

fn send_control_request_any(
    addresses: &[String],
    port: u16,
    request: &ControlRequest,
) -> Result<(String, ControlResponse)> {
    if addresses.is_empty() {
        return Err(anyhow!("no candidate address provided for control request"));
    }

    let mut errors = Vec::new();
    for address in addresses {
        if address.is_empty() {
            continue;
        }
        match send_control_request(address, port, request) {
            Ok(response) => return Ok((address.clone(), response)),
            Err(error) => errors.push(format!("{address}: {error:#}")),
        }
    }

    Err(anyhow!(
        "all candidate addresses unreachable: {}",
        errors.join("; ")
    ))
}

fn send_control_request(
    address: &str,
    port: u16,
    request: &ControlRequest,
) -> Result<ControlResponse> {
    let ip = address
        .parse::<IpAddr>()
        .with_context(|| format!("invalid device address {address}"))?;
    let socket_addr = SocketAddr::new(ip, port);
    let mut stream = TcpStream::connect_timeout(&socket_addr, CONTROL_PROBE_TIMEOUT)
        .with_context(|| format!("failed to connect to {socket_addr}"))?;
    stream
        .set_read_timeout(Some(CONTROL_PROBE_TIMEOUT))
        .context("failed to configure control read timeout")?;
    stream
        .set_write_timeout(Some(CONTROL_PROBE_TIMEOUT))
        .context("failed to configure control write timeout")?;
    write_control_header(&mut stream, request).context("failed to send control request")?;
    let _ = stream.shutdown(Shutdown::Write);

    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .context("failed to read control response")?;
    serde_json::from_slice(&response).context("failed to decode control response")
}

fn send_file_to_address(
    address: &str,
    port: u16,
    sender: &DeviceIdentity,
    source: &transfer::SourceFile,
) -> Result<TransferRecord> {
    let response = send_control_request_with_body(
        address,
        port,
        &ControlRequest::FilePush {
            sender: sender.clone(),
            file_name: source.file_name.clone(),
            size_bytes: source.size_bytes,
            hash: source.hash.clone(),
        },
        std::fs::File::open(&source.path)?,
    )?;

    match response {
        ControlResponse::FileAccepted { record, .. } => Ok(record),
        ControlResponse::Error { message } => Err(anyhow!(message)),
        _ => Err(anyhow!("unexpected file transfer response from receiver")),
    }
}

fn send_control_request_with_body<R: Read>(
    address: &str,
    port: u16,
    request: &ControlRequest,
    mut body: R,
) -> Result<ControlResponse> {
    let ip = address
        .parse::<IpAddr>()
        .with_context(|| format!("invalid device address {address}"))?;
    let socket_addr = SocketAddr::new(ip, port);
    let mut stream = TcpStream::connect_timeout(&socket_addr, Duration::from_millis(5000))
        .with_context(|| format!("failed to connect to {socket_addr}"))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(30)))
        .context("failed to configure control read timeout")?;
    stream
        .set_write_timeout(Some(Duration::from_secs(30)))
        .context("failed to configure control write timeout")?;
    write_control_header(&mut stream, request)?;
    std::io::copy(&mut body, &mut stream).context("failed to send file body")?;
    let _ = stream.shutdown(Shutdown::Write);

    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .context("failed to read control response")?;
    serde_json::from_slice(&response).context("failed to decode control response")
}

fn write_control_header(stream: &mut TcpStream, request: &ControlRequest) -> Result<()> {
    let payload = serde_json::to_vec(request).context("failed to encode control request")?;
    let len = u32::try_from(payload.len()).context("control request is too large")?;
    stream.write_all(&len.to_be_bytes())?;
    stream.write_all(&payload)?;
    Ok(())
}

fn handle_control_stream(
    stream: &mut TcpStream,
    receiver: &DeviceIdentity,
    config_path: &Path,
    pending_pairing: &Arc<Mutex<Option<IncomingPairing>>>,
    trusted_updates: &Arc<Mutex<Vec<TrustedDevice>>>,
    transfer_updates: &Arc<Mutex<Vec<TransferRecord>>>,
    clipboard_updates: &Arc<Mutex<Vec<ClipboardTextRecord>>>,
    latest_screen_frame: &Arc<Mutex<Option<ScreenFrame>>>,
) {
    let response = match read_control_request(stream) {
        Ok(ControlRequest::Ping) => ControlResponse::Pong,
        Ok(ControlRequest::PairRequest { requester }) => {
            handle_pair_request(requester, pending_pairing)
        }
        Ok(ControlRequest::VerifyPairing { requester, code }) => handle_pair_verification(
            receiver,
            requester,
            code,
            config_path,
            pending_pairing,
            trusted_updates,
        ),
        Ok(ControlRequest::FilePush {
            sender,
            file_name,
            size_bytes,
            hash,
        }) => handle_file_push(
            sender,
            file_name,
            size_bytes,
            hash,
            stream,
            config_path,
            transfer_updates,
        ),
        Ok(ControlRequest::ScreenFrame {
            sender,
            session,
            width,
            height,
            mime_type,
            frame_size,
        }) => handle_screen_frame(
            sender,
            session,
            width,
            height,
            mime_type,
            frame_size,
            stream,
            config_path,
            latest_screen_frame,
        ),
        Ok(ControlRequest::ClipboardText { sender, text }) => {
            handle_clipboard_text(sender, text, config_path, clipboard_updates)
        }
        Err(error) => ControlResponse::Error {
            message: error.to_string(),
        },
    };

    if let Ok(payload) = serde_json::to_vec(&response) {
        let _ = stream.write_all(&payload);
    }
}

fn read_control_request(stream: &mut TcpStream) -> Result<ControlRequest> {
    let mut len_bytes = [0_u8; 4];
    stream
        .read_exact(&mut len_bytes)
        .context("failed to read control request length")?;
    let len = u32::from_be_bytes(len_bytes) as usize;
    if len > 1024 * 1024 {
        return Err(anyhow!("control request is too large"));
    }
    let mut payload = vec![0_u8; len];
    stream
        .read_exact(&mut payload)
        .context("failed to read control request")?;
    serde_json::from_slice(&payload).context("failed to decode control request")
}

fn handle_pair_request(
    requester: DeviceIdentity,
    pending_pairing: &Arc<Mutex<Option<IncomingPairing>>>,
) -> ControlResponse {
    let code = format!("{:06}", rand::thread_rng().gen_range(0..1_000_000));
    let expires_at_ms = Utc::now().timestamp_millis() + 120_000;
    let pending = PendingPairing {
        device_id: requester.device_id.clone(),
        device_name: requester.device_name.clone(),
        code,
        expires_at_ms,
    };

    if let Ok(mut guard) = pending_pairing.lock() {
        *guard = Some(IncomingPairing { requester, pending });
    }

    ControlResponse::PairChallenge {
        expires_at_ms,
        message: "验证码已在被控端显示，请在控制端输入。".to_string(),
    }
}

fn handle_pair_verification(
    receiver: &DeviceIdentity,
    requester: DeviceIdentity,
    code: String,
    config_path: &Path,
    pending_pairing: &Arc<Mutex<Option<IncomingPairing>>>,
    trusted_updates: &Arc<Mutex<Vec<TrustedDevice>>>,
) -> ControlResponse {
    let now = Utc::now().timestamp_millis();
    let trusted_requester = {
        let mut guard = match pending_pairing.lock() {
            Ok(guard) => guard,
            Err(_) => {
                return ControlResponse::Error {
                    message: "被控端配对状态不可用。".to_string(),
                }
            }
        };

        let Some(pending) = guard.as_ref() else {
            return ControlResponse::Error {
                message: "被控端没有待验证的验证码，请重新请求。".to_string(),
            };
        };
        if pending.requester.device_id != requester.device_id {
            return ControlResponse::Error {
                message: "验证码请求设备不匹配，请重新请求。".to_string(),
            };
        }
        if pending.pending.expires_at_ms < now {
            *guard = None;
            return ControlResponse::Error {
                message: "验证码已过期，请重新请求。".to_string(),
            };
        }
        if pending.pending.code != code.trim() {
            return ControlResponse::Error {
                message: "验证码不正确。".to_string(),
            };
        }

        *guard = None;
        trusted_from_identity(&requester, now)
    };

    if let Err(error) = persist_trusted_device(config_path, trusted_requester.clone()) {
        return ControlResponse::Error {
            message: format!("被控端保存可信设备失败：{error:#}"),
        };
    }
    if let Ok(mut updates) = trusted_updates.lock() {
        updates.push(trusted_requester);
    }

    ControlResponse::PairAccepted {
        trusted_device: trusted_from_identity(receiver, now),
        message: "被控端验证通过，双方已记录可信设备。".to_string(),
    }
}

fn persist_trusted_device(config_path: &Path, trusted: TrustedDevice) -> Result<()> {
    let raw = std::fs::read_to_string(config_path)
        .with_context(|| format!("failed to read config {}", config_path.display()))?;
    let mut config: storage::StoredConfig = serde_json::from_str(&raw)
        .with_context(|| format!("failed to parse config {}", config_path.display()))?;
    config
        .trusted_devices
        .retain(|device| device.device_id != trusted.device_id);
    config.trusted_devices.push(trusted);
    storage::save_to_path(config_path, &config)
}

fn trusted_from_identity(identity: &DeviceIdentity, now: i64) -> TrustedDevice {
    TrustedDevice {
        device_id: identity.device_id.clone(),
        device_name: identity.device_name.clone(),
        public_key: identity.public_key.clone(),
        fingerprint: identity.fingerprint.clone(),
        trusted_at_ms: now,
        last_connected_ms: Some(now),
    }
}

fn handle_file_push(
    sender: DeviceIdentity,
    file_name: String,
    size_bytes: u64,
    hash: String,
    stream: &mut TcpStream,
    config_path: &Path,
    transfer_updates: &Arc<Mutex<Vec<TransferRecord>>>,
) -> ControlResponse {
    if !is_trusted_sender(config_path, &sender) {
        return ControlResponse::Error {
            message: "发送端未受信任，请先完成验证码配对。".to_string(),
        };
    }

    match transfer::write_incoming_file(&file_name, stream, size_bytes, &hash) {
        Ok(record) => {
            if let Ok(mut updates) = transfer_updates.lock() {
                updates.push(record.clone());
            }
            ControlResponse::FileAccepted {
                record,
                message: "文件已保存到被控端下载目录。".to_string(),
            }
        }
        Err(error) => ControlResponse::Error {
            message: format!("文件接收失败：{error:#}"),
        },
    }
}

fn handle_screen_frame(
    sender: DeviceIdentity,
    session: ScreenSession,
    width: u32,
    height: u32,
    mime_type: String,
    frame_size: u64,
    stream: &mut TcpStream,
    config_path: &Path,
    latest_screen_frame: &Arc<Mutex<Option<ScreenFrame>>>,
) -> ControlResponse {
    if !is_trusted_sender(config_path, &sender) {
        return ControlResponse::Error {
            message: "发送端未受信任，请先完成验证码配对。".to_string(),
        };
    }
    if mime_type != "image/jpeg" && mime_type != "image/png" {
        return ControlResponse::Error {
            message: "屏幕帧格式不支持。".to_string(),
        };
    }
    if frame_size == 0 || frame_size > 16 * 1024 * 1024 {
        return ControlResponse::Error {
            message: "屏幕帧大小无效。".to_string(),
        };
    }

    let mut frame_bytes = vec![0_u8; frame_size as usize];
    if let Err(error) = stream.read_exact(&mut frame_bytes) {
        return ControlResponse::Error {
            message: format!("屏幕帧读取失败：{error}"),
        };
    }

    let data_url = format!(
        "data:{mime_type};base64,{}",
        general_purpose::STANDARD.encode(&frame_bytes)
    );
    let frame = ScreenFrame {
        session,
        width,
        height,
        mime_type,
        data_url,
        updated_at_ms: Utc::now().timestamp_millis(),
    };

    if let Ok(mut latest) = latest_screen_frame.lock() {
        *latest = Some(frame);
    }

    ControlResponse::ScreenFrameAccepted
}

fn handle_clipboard_text(
    sender: DeviceIdentity,
    text: String,
    config_path: &Path,
    clipboard_updates: &Arc<Mutex<Vec<ClipboardTextRecord>>>,
) -> ControlResponse {
    if !is_trusted_sender(config_path, &sender) {
        return ControlResponse::Error {
            message: "发送端未受信任，请先完成验证码配对。".to_string(),
        };
    }
    if text.is_empty() || text.len() > 64 * 1024 {
        return ControlResponse::Error {
            message: "剪贴板文本为空或超过 64KB。".to_string(),
        };
    }

    if let Err(error) = clipboard::write_text(&text) {
        return ControlResponse::Error {
            message: format!("写入被控端剪贴板失败：{error:#}"),
        };
    }

    let preview = text.chars().take(80).collect::<String>();
    let record = ClipboardTextRecord {
        id: Uuid::new_v4().to_string(),
        sender_device_id: sender.device_id,
        sender_device_name: sender.device_name,
        preview,
        char_count: text.chars().count(),
        received_at_ms: Utc::now().timestamp_millis(),
    };
    if let Ok(mut updates) = clipboard_updates.lock() {
        updates.push(record.clone());
    }

    ControlResponse::ClipboardTextAccepted {
        record,
        message: "文本已复制到被控端剪贴板。".to_string(),
    }
}

fn is_trusted_sender(config_path: &Path, sender: &DeviceIdentity) -> bool {
    if sender.device_id.trim().is_empty() || sender.public_key.trim().is_empty() {
        return false;
    }
    let Ok(raw) = std::fs::read_to_string(config_path) else {
        return false;
    };
    let Ok(config) = serde_json::from_str::<storage::StoredConfig>(&raw) else {
        return false;
    };
    config.trusted_devices.iter().any(|trusted| {
        trusted.device_id == sender.device_id
            && trusted.public_key == sender.public_key
            && trusted.fingerprint == sender.fingerprint
    })
}

pub fn browse_once() -> Result<Vec<LanDevice>> {
    let mdns = ServiceDaemon::new().ok();
    let receiver = mdns
        .as_ref()
        .and_then(|daemon| daemon.browse(SERVICE_TYPE).ok());
    let udp = UdpSocket::bind(("0.0.0.0", 0)).ok();
    if let Some(socket) = &udp {
        let _ = socket.set_broadcast(true);
        let _ = socket.set_nonblocking(true);
    }
    let broadcast_targets = collect_broadcast_targets();
    send_udp_discovery(&udp, &broadcast_targets);

    let devices: Arc<Mutex<HashMap<String, DiscoveryEntry>>> = Arc::new(Mutex::new(HashMap::new()));
    let devices_for_thread = devices.clone();

    let handle = thread::spawn(move || {
        let deadline = Instant::now() + DISCOVERY_TIMEOUT;
        let mut next_udp_broadcast = Instant::now() + Duration::from_millis(700);

        while Instant::now() < deadline {
            if Instant::now() >= next_udp_broadcast {
                send_udp_discovery(&udp, &broadcast_targets);
                next_udp_broadcast = Instant::now() + Duration::from_millis(700);
            }

            if let Some(receiver) = &receiver {
                match receiver.recv_timeout(Duration::from_millis(100)) {
                    Ok(ServiceEvent::ServiceResolved(info)) => {
                        if let Some(device) = device_from_info(&info) {
                            upsert_device(&devices_for_thread, device, DiscoverySource::Mdns);
                        }
                    }
                    Ok(_) => {}
                    Err(_) => {}
                }
            }

            drain_udp_responses(&udp, &devices_for_thread);
            thread::sleep(Duration::from_millis(25));
        }
    });

    let _ = handle.join();
    if let Some(mdns) = mdns {
        let _ = mdns.shutdown();
    }
    let mut values = devices
        .lock()
        .expect("discovery lock poisoned")
        .values()
        .cloned()
        .map(|entry| entry.device)
        .collect::<Vec<_>>();
    values.sort_by(|a, b| a.device_name.cmp(&b.device_name));
    Ok(values)
}

pub fn candidate_addresses_for(device: &LanDevice) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for address in std::iter::once(device.address.clone()).chain(device.extra_addresses.clone()) {
        if address.is_empty() {
            continue;
        }
        if seen.insert(address.clone()) {
            out.push(address);
        }
    }
    out
}

fn collect_broadcast_targets() -> Vec<SocketAddr> {
    let mut seen = HashSet::new();
    let mut targets = Vec::new();
    let limited = SocketAddr::new(IpAddr::V4(Ipv4Addr::BROADCAST), UDP_DISCOVERY_PORT);
    if seen.insert(limited) {
        targets.push(limited);
    }

    if let Ok(interfaces) = if_addrs::get_if_addrs() {
        for iface in interfaces {
            if iface.is_loopback() {
                continue;
            }
            if let if_addrs::IfAddr::V4(v4) = iface.addr {
                if let Some(broadcast) = v4.broadcast {
                    if broadcast.is_unspecified() {
                        continue;
                    }
                    let addr = SocketAddr::new(IpAddr::V4(broadcast), UDP_DISCOVERY_PORT);
                    if seen.insert(addr) {
                        targets.push(addr);
                    }
                }
            }
        }
    }

    targets
}

fn send_udp_discovery(socket: &Option<UdpSocket>, targets: &[SocketAddr]) {
    let Some(socket) = socket else {
        return;
    };
    for target in targets {
        let _ = socket.send_to(UDP_DISCOVERY_REQUEST, target);
    }
}

fn drain_udp_responses(
    socket: &Option<UdpSocket>,
    devices: &Arc<Mutex<HashMap<String, DiscoveryEntry>>>,
) {
    let Some(socket) = socket else {
        return;
    };

    let mut buf = [0_u8; 4096];
    loop {
        match socket.recv_from(&mut buf) {
            Ok((len, peer)) => {
                if let Some(device) = device_from_udp_response(&buf[..len], peer) {
                    upsert_device(devices, device, DiscoverySource::Udp);
                }
            }
            Err(error) if error.kind() == ErrorKind::WouldBlock => break,
            Err(_) => break,
        }
    }
}

fn upsert_device(
    devices: &Arc<Mutex<HashMap<String, DiscoveryEntry>>>,
    mut device: LanDevice,
    source: DiscoverySource,
) {
    let mut guard = devices.lock().expect("discovery lock poisoned");
    match guard.get_mut(&device.device_id) {
        Some(existing) => {
            // UDP responses always win because peer.ip() is guaranteed to be reachable.
            // mDNS data only refreshes a non-UDP entry, but we always merge address pools
            // so request_pairing can fall back to alternate IPs.
            for address in candidate_addresses_for(&existing.device) {
                merge_address_pool(&mut device.extra_addresses, &address);
            }
            merge_address_pool(&mut device.extra_addresses, &existing.device.address);

            let prefer_new =
                source == DiscoverySource::Udp || existing.source != DiscoverySource::Udp;
            if prefer_new {
                existing.device = device;
                existing.source = source;
            } else {
                merge_address_pool(&mut existing.device.extra_addresses, &device.address);
                for address in device.extra_addresses {
                    merge_address_pool(&mut existing.device.extra_addresses, &address);
                }
                existing.device.last_seen_ms = device.last_seen_ms;
            }
        }
        None => {
            let address_clone = device.address.clone();
            merge_address_pool(&mut device.extra_addresses, &address_clone);
            guard.insert(device.device_id.clone(), DiscoveryEntry { device, source });
        }
    }
}

fn merge_address_pool(pool: &mut Vec<String>, candidate: &str) {
    if candidate.is_empty() {
        return;
    }
    if !pool.iter().any(|item| item == candidate) {
        pool.push(candidate.to_string());
    }
}

fn device_from_udp_response(payload: &[u8], peer: SocketAddr) -> Option<LanDevice> {
    let mut device = serde_json::from_slice::<LanDevice>(payload).ok()?;
    if device.protocol_version != PROTOCOL_VERSION {
        return None;
    }
    if !device.address.is_empty() && device.address != "0.0.0.0" {
        merge_address_pool(&mut device.extra_addresses, &device.address.clone());
    }
    let peer_ip = peer.ip().to_string();
    merge_address_pool(&mut device.extra_addresses, &peer_ip);
    device.address = peer_ip;
    device.last_seen_ms = Utc::now().timestamp_millis();
    Some(device)
}

fn device_from_info(info: &ServiceInfo) -> Option<LanDevice> {
    let props = info.get_properties();
    let get = |key: &str| props.get_property_val_str(key).map(ToOwned::to_owned);
    let device_id = get("device_id")?;
    let protocol_version = get("protocol_version")?;
    if protocol_version != PROTOCOL_VERSION {
        return None;
    }

    let mut sorted_addresses: Vec<IpAddr> = info.get_addresses().iter().copied().collect();
    sorted_addresses.sort_by_key(|address| match address {
        IpAddr::V4(ip) if is_usable_lan_address(&IpAddr::V4(*ip)) => 0,
        IpAddr::V6(ip) if is_usable_lan_address(&IpAddr::V6(*ip)) => 1,
        _ => 2,
    });

    let mut address = "0.0.0.0".to_string();
    let mut extra_addresses: Vec<String> = Vec::new();
    for candidate in &sorted_addresses {
        let text = candidate.to_string();
        if address == "0.0.0.0" {
            address = text.clone();
        }
        merge_address_pool(&mut extra_addresses, &text);
    }
    if address == "0.0.0.0" {
        if let Some(first) = extra_addresses.first().cloned() {
            address = first;
        }
    }

    let capabilities = get("capabilities")
        .unwrap_or_default()
        .split(',')
        .filter(|item| !item.is_empty())
        .map(ToOwned::to_owned)
        .collect();

    Some(LanDevice {
        device_id,
        device_name: get("device_name").unwrap_or_else(|| info.get_fullname().to_string()),
        address,
        port: info.get_port(),
        public_key: get("public_key").unwrap_or_default(),
        fingerprint: get("fingerprint").unwrap_or_default(),
        protocol_version,
        capabilities,
        last_seen_ms: Utc::now().timestamp_millis(),
        extra_addresses,
    })
}

fn lan_device_from_identity(
    identity: &crate::models::DeviceIdentity,
    address: String,
) -> LanDevice {
    let mut extra_addresses = local_ipv4_addresses();
    if !address.is_empty() {
        merge_address_pool(&mut extra_addresses, &address);
    }
    LanDevice {
        device_id: identity.device_id.clone(),
        device_name: identity.device_name.clone(),
        address,
        port: SERVICE_PORT,
        public_key: identity.public_key.clone(),
        fingerprint: identity.fingerprint.clone(),
        protocol_version: PROTOCOL_VERSION.to_string(),
        capabilities: vec![
            "screen_stream".to_string(),
            "file_push".to_string(),
            "clipboard_text".to_string(),
        ],
        last_seen_ms: Utc::now().timestamp_millis(),
        extra_addresses,
    }
}

fn local_ipv4_addresses() -> Vec<String> {
    let mut out = Vec::new();
    if let Ok(interfaces) = if_addrs::get_if_addrs() {
        for iface in interfaces {
            if iface.is_loopback() {
                continue;
            }
            if let if_addrs::IfAddr::V4(v4) = iface.addr {
                let ip = IpAddr::V4(v4.ip);
                if is_usable_lan_address(&ip) {
                    merge_address_pool(&mut out, &ip.to_string());
                }
            }
        }
    }
    out
}

fn is_usable_lan_address(address: &IpAddr) -> bool {
    match address {
        IpAddr::V4(ip) => !ip.is_unspecified() && !ip.is_loopback() && !ip.is_link_local(),
        IpAddr::V6(ip) => !ip.is_unspecified() && !ip.is_loopback(),
    }
}

pub fn run_network_diagnostic(mode: AppMode) -> NetworkDiagnosticReport {
    let mut items: Vec<DiagnosticItem> = Vec::new();
    let interfaces = collect_diagnostic_interfaces();
    let broadcast_targets = collect_broadcast_targets()
        .into_iter()
        .map(|addr| addr.to_string())
        .collect::<Vec<_>>();

    items.push(diagnose_interfaces(&interfaces));
    items.push(diagnose_broadcast_targets(&broadcast_targets));
    items.push(diagnose_mdns_daemon());
    items.push(diagnose_outbound_udp_broadcast());

    if mode == AppMode::Receiver {
        items.push(diagnose_port_listenable(
            "udp_listener",
            "UDP 发现端口绑定",
            UDP_DISCOVERY_PORT,
            true,
        ));
        items.push(diagnose_port_listenable(
            "tcp_listener",
            "TCP 控制端口绑定",
            SERVICE_PORT,
            false,
        ));
    } else {
        items.push(DiagnosticItem {
            id: "receiver_only".to_string(),
            label: "被控端服务监听".to_string(),
            status: DiagnosticStatus::Ok,
            detail: "当前为控制端，无需占用 UDP/TCP 监听端口。".to_string(),
        });
    }

    let overall_status =
        items
            .iter()
            .map(|item| &item.status)
            .fold(DiagnosticStatus::Ok, |acc, status| match (acc, status) {
                (DiagnosticStatus::Fail, _) | (_, DiagnosticStatus::Fail) => DiagnosticStatus::Fail,
                (DiagnosticStatus::Warn, _) | (_, DiagnosticStatus::Warn) => DiagnosticStatus::Warn,
                _ => DiagnosticStatus::Ok,
            });

    NetworkDiagnosticReport {
        mode,
        generated_at_ms: Utc::now().timestamp_millis(),
        overall_status,
        items,
        interfaces,
        broadcast_targets,
        firewall_hint: firewall_hint(),
    }
}

fn collect_diagnostic_interfaces() -> Vec<DiagnosticInterface> {
    let mut out = Vec::new();
    if let Ok(interfaces) = if_addrs::get_if_addrs() {
        for iface in interfaces {
            let (address, broadcast) = match iface.addr {
                if_addrs::IfAddr::V4(ref v4) => (
                    IpAddr::V4(v4.ip).to_string(),
                    v4.broadcast.map(|b| b.to_string()),
                ),
                if_addrs::IfAddr::V6(ref v6) => (IpAddr::V6(v6.ip).to_string(), None),
            };
            out.push(DiagnosticInterface {
                name: iface.name.clone(),
                address,
                broadcast,
                is_loopback: iface.is_loopback(),
            });
        }
    }
    out
}

fn diagnose_interfaces(interfaces: &[DiagnosticInterface]) -> DiagnosticItem {
    let lan_count = interfaces
        .iter()
        .filter(|iface| {
            !iface.is_loopback
                && iface
                    .address
                    .parse::<IpAddr>()
                    .map(|ip| is_usable_lan_address(&ip) && matches!(ip, IpAddr::V4(_)))
                    .unwrap_or(false)
        })
        .count();
    if lan_count == 0 {
        DiagnosticItem {
            id: "interfaces".to_string(),
            label: "本机网络接口".to_string(),
            status: DiagnosticStatus::Fail,
            detail: "未检测到可用的局域网 IPv4 接口，请检查网线 / Wi-Fi 是否连接。".to_string(),
        }
    } else {
        DiagnosticItem {
            id: "interfaces".to_string(),
            label: "本机网络接口".to_string(),
            status: DiagnosticStatus::Ok,
            detail: format!("共发现 {lan_count} 个可用 IPv4 局域网接口。"),
        }
    }
}

fn diagnose_broadcast_targets(targets: &[String]) -> DiagnosticItem {
    let subnet_targets = targets
        .iter()
        .filter(|target| !target.starts_with("255.255.255.255"))
        .count();
    if subnet_targets == 0 {
        DiagnosticItem {
            id: "broadcast_targets".to_string(),
            label: "子网广播地址".to_string(),
            status: DiagnosticStatus::Warn,
            detail: "未推导出任何子网广播地址，多网卡环境下可能无法跨接口发现。".to_string(),
        }
    } else {
        DiagnosticItem {
            id: "broadcast_targets".to_string(),
            label: "子网广播地址".to_string(),
            status: DiagnosticStatus::Ok,
            detail: format!("将向 {subnet_targets} 个子网广播地址 + 受限广播发起扫描。"),
        }
    }
}

fn diagnose_mdns_daemon() -> DiagnosticItem {
    match ServiceDaemon::new() {
        Ok(daemon) => {
            let _ = daemon.shutdown();
            DiagnosticItem {
                id: "mdns_daemon".to_string(),
                label: "mDNS 服务".to_string(),
                status: DiagnosticStatus::Ok,
                detail: "mDNS 守护进程可正常创建。".to_string(),
            }
        }
        Err(error) => DiagnosticItem {
            id: "mdns_daemon".to_string(),
            label: "mDNS 服务".to_string(),
            status: DiagnosticStatus::Warn,
            detail: format!("mDNS 守护进程初始化失败：{error}。仍可依赖 UDP 广播继续发现设备。"),
        },
    }
}

fn diagnose_outbound_udp_broadcast() -> DiagnosticItem {
    let socket = match UdpSocket::bind(("0.0.0.0", 0)) {
        Ok(socket) => socket,
        Err(error) => {
            return DiagnosticItem {
                id: "udp_outbound".to_string(),
                label: "UDP 出站发现".to_string(),
                status: DiagnosticStatus::Fail,
                detail: format!("无法创建出站 UDP 套接字：{error}"),
            };
        }
    };
    if let Err(error) = socket.set_broadcast(true) {
        return DiagnosticItem {
            id: "udp_outbound".to_string(),
            label: "UDP 出站发现".to_string(),
            status: DiagnosticStatus::Warn,
            detail: format!("出站 UDP 套接字无法启用广播：{error}"),
        };
    }

    let targets = collect_broadcast_targets();
    let mut succeeded: usize = 0;
    let mut errors = Vec::new();
    for target in &targets {
        match socket.send_to(UDP_DISCOVERY_REQUEST, target) {
            Ok(_) => succeeded += 1,
            Err(error) => errors.push(format!("{target}: {error}")),
        }
    }

    if succeeded == 0 {
        DiagnosticItem {
            id: "udp_outbound".to_string(),
            label: "UDP 出站发现".to_string(),
            status: DiagnosticStatus::Fail,
            detail: format!("所有广播目标均发送失败：{}", errors.join("; ")),
        }
    } else if !errors.is_empty() {
        DiagnosticItem {
            id: "udp_outbound".to_string(),
            label: "UDP 出站发现".to_string(),
            status: DiagnosticStatus::Warn,
            detail: format!(
                "成功向 {succeeded} 个目标发送广播，{} 个目标受阻：{}",
                errors.len(),
                errors.join("; ")
            ),
        }
    } else {
        DiagnosticItem {
            id: "udp_outbound".to_string(),
            label: "UDP 出站发现".to_string(),
            status: DiagnosticStatus::Ok,
            detail: format!("成功向 {succeeded} 个广播目标投递发现包。"),
        }
    }
}

fn diagnose_port_listenable(id: &str, label: &str, port: u16, is_udp: bool) -> DiagnosticItem {
    let bind_result: Result<()> = if is_udp {
        UdpSocket::bind(("0.0.0.0", port))
            .map(|_| ())
            .map_err(Into::into)
    } else {
        TcpListener::bind(("0.0.0.0", port))
            .map(|_| ())
            .map_err(Into::into)
    };

    match bind_result {
        Ok(()) => DiagnosticItem {
            id: id.to_string(),
            label: label.to_string(),
            status: DiagnosticStatus::Warn,
            detail: format!("端口 {port} 当前未被监听。请通过设置启动被控端服务后再次自查。"),
        },
        Err(error) => {
            let kind = error
                .downcast_ref::<std::io::Error>()
                .map(|e| e.kind())
                .unwrap_or(ErrorKind::Other);
            if kind == ErrorKind::AddrInUse {
                DiagnosticItem {
                    id: id.to_string(),
                    label: label.to_string(),
                    status: DiagnosticStatus::Ok,
                    detail: format!("端口 {port} 已被本应用占用，监听正常。"),
                }
            } else {
                DiagnosticItem {
                    id: id.to_string(),
                    label: label.to_string(),
                    status: DiagnosticStatus::Fail,
                    detail: format!("端口 {port} 不可用：{error}"),
                }
            }
        }
    }
}

fn firewall_hint() -> Option<String> {
    if cfg!(target_os = "macos") {
        Some(
            "macOS：若首次使用，请在「系统设置 → 网络 → 防火墙」允许 ShArIngM 接受入站连接，并在「本地网络」权限弹窗中点击允许。"
                .to_string(),
        )
    } else if cfg!(target_os = "windows") {
        Some(
            "Windows：在 Windows Defender 防火墙弹窗中勾选「专用网络」与「公用网络」，允许 ShArIngM 通信。"
                .to_string(),
        )
    } else if cfg!(target_os = "linux") {
        Some("Linux：如启用了 ufw / firewalld，请放行 UDP 41875 与 TCP 41874 端口。".to_string())
    } else {
        None
    }
}
