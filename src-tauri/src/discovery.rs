use crate::{
    identity::Identity,
    models::{LanDevice, PROTOCOL_VERSION, SERVICE_TYPE},
};
use anyhow::{Context, Result};
use chrono::Utc;
use mdns_sd::{ServiceDaemon, ServiceEvent, ServiceInfo};
use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr},
    sync::{Arc, Mutex},
    thread,
    time::Duration,
};

const SERVICE_PORT: u16 = 41874;

#[derive(Default)]
pub struct DiscoveryRuntime {
    mdns: Option<ServiceDaemon>,
    registered_name: Option<String>,
}

impl DiscoveryRuntime {
    pub fn start_receiver(&mut self, identity: &Identity) -> Result<()> {
        if self.mdns.is_some() {
            return Ok(());
        }

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
            ("capabilities", "screen_stream,file_push,clipboard_text_reserved"),
        ];
        let info = ServiceInfo::new(
            SERVICE_TYPE,
            &instance,
            &host_name,
            IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            SERVICE_PORT,
            &props[..],
        )?;

        mdns.register(info)?;
        self.registered_name = Some(instance);
        self.mdns = Some(mdns);
        Ok(())
    }

    pub fn stop(&mut self) {
        if let (Some(mdns), Some(name)) = (&self.mdns, &self.registered_name) {
            let _ = mdns.unregister(name);
        }
        self.registered_name = None;
        self.mdns = None;
    }
}

pub fn browse_once() -> Result<Vec<LanDevice>> {
    let mdns = ServiceDaemon::new().context("failed to start mDNS browser")?;
    let receiver = mdns.browse(SERVICE_TYPE)?;
    let devices: Arc<Mutex<HashMap<String, LanDevice>>> = Arc::new(Mutex::new(HashMap::new()));
    let devices_for_thread = devices.clone();

    let handle = thread::spawn(move || {
        let deadline = std::time::Instant::now() + Duration::from_millis(1400);
        while std::time::Instant::now() < deadline {
            match receiver.recv_timeout(Duration::from_millis(150)) {
                Ok(ServiceEvent::ServiceResolved(info)) => {
                    if let Some(device) = device_from_info(&info) {
                        let mut guard = devices_for_thread.lock().expect("discovery lock poisoned");
                        guard.insert(device.device_id.clone(), device);
                    }
                }
                Ok(_) => {}
                Err(_) => {}
            }
        }
    });

    let _ = handle.join();
    let _ = mdns.shutdown();
    let mut values = devices
        .lock()
        .expect("discovery lock poisoned")
        .values()
        .cloned()
        .collect::<Vec<_>>();
    values.sort_by(|a, b| a.device_name.cmp(&b.device_name));
    Ok(values)
}

fn device_from_info(info: &ServiceInfo) -> Option<LanDevice> {
    let props = info.get_properties();
    let get = |key: &str| props.get_property_val_str(key).map(ToOwned::to_owned);
    let device_id = get("device_id")?;
    let protocol_version = get("protocol_version")?;
    if protocol_version != PROTOCOL_VERSION {
        return None;
    }

    let address = info
        .get_addresses()
        .iter()
        .next()
        .map(ToString::to_string)
        .unwrap_or_else(|| "0.0.0.0".to_string());
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
    })
}
