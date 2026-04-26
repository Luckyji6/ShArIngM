use crate::{
    identity::Identity,
    models::{
        AppMode, DiagnosticInterface, DiagnosticItem, DiagnosticStatus, LanDevice,
        NetworkDiagnosticReport, PROTOCOL_VERSION, SERVICE_TYPE,
    },
};
use anyhow::{anyhow, Context, Result};
use chrono::Utc;
use mdns_sd::{ServiceDaemon, ServiceEvent, ServiceInfo};
use std::{
    collections::{HashMap, HashSet},
    io::{ErrorKind, Read, Write},
    net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream, UdpSocket},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

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

#[derive(Default)]
pub struct DiscoveryRuntime {
    mdns: Option<ServiceDaemon>,
    registered_name: Option<String>,
    udp_shutdown: Option<Arc<AtomicBool>>,
    udp_thread: Option<JoinHandle<()>>,
    tcp_shutdown: Option<Arc<AtomicBool>>,
    tcp_thread: Option<JoinHandle<()>>,
}

impl DiscoveryRuntime {
    pub fn start_receiver(&mut self, identity: &Identity) -> Result<()> {
        if self.mdns.is_some() && self.udp_thread.is_some() && self.tcp_thread.is_some() {
            return Ok(());
        }

        let mut errors = Vec::new();
        if self.tcp_thread.is_none() {
            if let Err(error) = self.start_tcp_control_listener() {
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
            (
                "capabilities",
                "screen_stream,file_push,clipboard_text_reserved",
            ),
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

    fn start_tcp_control_listener(&mut self) -> Result<()> {
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
        let handle = thread::spawn(move || {
            while !thread_shutdown.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((mut stream, _peer)) => {
                        let _ = stream.set_read_timeout(Some(Duration::from_millis(1500)));
                        let _ = stream.set_write_timeout(Some(Duration::from_millis(1500)));
                        handle_control_stream(&mut stream);
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

pub fn check_control_plane_any(addresses: &[String], port: u16) -> Result<String> {
    if addresses.is_empty() {
        return Err(anyhow!("no candidate address provided for control probe"));
    }

    let mut errors = Vec::new();
    for address in addresses {
        if address.is_empty() {
            continue;
        }
        match probe_single_address(address, port) {
            Ok(()) => return Ok(address.clone()),
            Err(error) => errors.push(format!("{address}: {error:#}")),
        }
    }

    Err(anyhow!(
        "all candidate addresses unreachable: {}",
        errors.join("; ")
    ))
}

fn probe_single_address(address: &str, port: u16) -> Result<()> {
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
    stream
        .write_all(b"SHARINGM_CONTROL_PING_V1\n")
        .context("failed to send control ping")?;

    let mut buf = [0_u8; 64];
    let len = stream
        .read(&mut buf)
        .context("failed to read control ping response")?;
    if &buf[..len] == b"SHARINGM_CONTROL_PONG_V1\n" {
        Ok(())
    } else {
        Err(anyhow!("invalid control ping response"))
    }
}

fn handle_control_stream(stream: &mut TcpStream) {
    let mut buf = [0_u8; 64];
    let Ok(len) = stream.read(&mut buf) else {
        return;
    };
    if &buf[..len] == b"SHARINGM_CONTROL_PING_V1\n" {
        let _ = stream.write_all(b"SHARINGM_CONTROL_PONG_V1\n");
    }
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

    let devices: Arc<Mutex<HashMap<String, DiscoveryEntry>>> =
        Arc::new(Mutex::new(HashMap::new()));
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

            let prefer_new = source == DiscoverySource::Udp || existing.source != DiscoverySource::Udp;
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
            guard.insert(
                device.device_id.clone(),
                DiscoveryEntry { device, source },
            );
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
            "clipboard_text_reserved".to_string(),
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

    let overall_status = items
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
            detail: format!(
                "mDNS 守护进程初始化失败：{error}。仍可依赖 UDP 广播继续发现设备。"
            ),
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

fn diagnose_port_listenable(
    id: &str,
    label: &str,
    port: u16,
    is_udp: bool,
) -> DiagnosticItem {
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
            detail: format!(
                "端口 {port} 当前未被监听。请通过设置启动被控端服务后再次自查。"
            ),
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
        Some(
            "Linux：如启用了 ufw / firewalld，请放行 UDP 41875 与 TCP 41874 端口。"
                .to_string(),
        )
    } else {
        None
    }
}
