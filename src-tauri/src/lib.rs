mod discovery;
mod display;
mod identity;
mod models;
mod storage;
mod transfer;

use crate::{
    discovery::DiscoveryRuntime,
    display::{CaptureSource, DisplaySource, VirtualDisplaySource},
    identity::Identity,
    models::{
        AppMode, AppSnapshot, DisplaySourceKind, FileTransferRequest, LanDevice, PairingResult,
        PendingPairing, ScreenSession, StartScreenRequest, TransferRecord, TrustedDevice,
    },
    storage::StoredConfig,
};
use anyhow::{bail, Context, Result};
use chrono::Utc;
use rand::Rng;
use std::{
    collections::HashMap,
    path::PathBuf,
    process::Command,
    sync::Mutex,
};
use tauri::{AppHandle, Manager, State};

struct SharedApp {
    inner: Mutex<AppCore>,
}

struct AppCore {
    config: StoredConfig,
    config_path: PathBuf,
    identity: Identity,
    discovery: DiscoveryRuntime,
    discovered: HashMap<String, LanDevice>,
    pending_pairing: Option<PendingPairing>,
    transfers: Vec<TransferRecord>,
    screen_session: Option<ScreenSession>,
    discovery_active: bool,
}

impl AppCore {
    fn load() -> Result<Self> {
        let (config, config_path) = storage::load_or_create()?;
        let identity = Identity::from_config(&config)?;
        Ok(Self {
            config,
            config_path,
            identity,
            discovery: DiscoveryRuntime::default(),
            discovered: HashMap::new(),
            pending_pairing: None,
            transfers: Vec::new(),
            screen_session: None,
            discovery_active: false,
        })
    }

    fn save(&self) -> Result<()> {
        storage::save_to_path(&self.config_path, &self.config)
    }

    fn snapshot(&self) -> AppSnapshot {
        let mut discovered = self.discovered.values().cloned().collect::<Vec<_>>();
        discovered.sort_by(|a, b| b.last_seen_ms.cmp(&a.last_seen_ms));

        AppSnapshot {
            identity: self.identity.public_identity(),
            mode: self.config.mode.clone(),
            autostart_required: self.config.autostart_required,
            discovery_active: self.discovery_active,
            trusted_devices: self.config.trusted_devices.clone(),
            discovered_devices: discovered,
            pending_pairing: self.pending_pairing.clone(),
            transfers: self.transfers.clone(),
            screen_session: self.screen_session.clone(),
        }
    }

    fn set_mode(&mut self, mode: AppMode) -> Result<AppSnapshot> {
        self.config.mode = mode.clone();
        self.config.autostart_required = mode == AppMode::Receiver;

        if mode == AppMode::Receiver {
            let identity = self.identity.clone();
            self.discovery.start_receiver(&identity)?;
            self.discovery_active = true;
        } else {
            self.discovery.stop();
            self.discovery_active = false;
        }

        self.save()?;
        Ok(self.snapshot())
    }

    fn merge_discovered(&mut self, devices: Vec<LanDevice>) {
        let own_id = self.config.device_id.as_str();
        for device in devices {
            if device.device_id != own_id {
                self.discovered.insert(device.device_id.clone(), device);
            }
        }
    }

    fn request_pairing(&mut self, device_id: &str) -> Result<PairingResult> {
        if self
            .config
            .trusted_devices
            .iter()
            .any(|device| device.device_id == device_id)
        {
            return Ok(PairingResult {
                trusted: true,
                challenge_required: false,
                code_hint: None,
                message: "设备已受信任，连接已建立。".to_string(),
            });
        }

        let device = self
            .discovered
            .get(device_id)
            .cloned()
            .with_context(|| format!("device {device_id} was not found"))?;
        let code = format!("{:06}", rand::thread_rng().gen_range(0..1_000_000));
        self.pending_pairing = Some(PendingPairing {
            device_id: device.device_id,
            device_name: device.device_name,
            code: code.clone(),
            expires_at_ms: Utc::now().timestamp_millis() + 120_000,
        });

        Ok(PairingResult {
            trusted: false,
            challenge_required: true,
            code_hint: Some(code),
            message: "被控端已生成验证码，2 分钟内有效。".to_string(),
        })
    }

    fn verify_pairing(&mut self, device_id: &str, code: &str) -> Result<PairingResult> {
        let now = Utc::now().timestamp_millis();
        let pending = self
            .pending_pairing
            .clone()
            .context("no pending pairing challenge")?;
        if pending.device_id != device_id {
            bail!("pending pairing target does not match");
        }
        if pending.expires_at_ms < now {
            self.pending_pairing = None;
            bail!("pairing code expired");
        }
        if pending.code != code.trim() {
            bail!("pairing code is incorrect");
        }

        let device = self
            .discovered
            .get(device_id)
            .cloned()
            .context("paired device is no longer available")?;
        self.config.trusted_devices.retain(|item| item.device_id != device_id);
        self.config.trusted_devices.push(TrustedDevice {
            device_id: device.device_id,
            device_name: device.device_name,
            public_key: device.public_key,
            fingerprint: device.fingerprint,
            trusted_at_ms: now,
            last_connected_ms: Some(now),
        });
        self.pending_pairing = None;
        self.save()?;

        Ok(PairingResult {
            trusted: true,
            challenge_required: false,
            code_hint: None,
            message: "配对成功，设备已加入可信列表。".to_string(),
        })
    }
}

#[tauri::command]
fn get_snapshot(state: State<'_, SharedApp>) -> Result<AppSnapshot, String> {
    let core = state.inner.lock().map_err(|_| "state lock poisoned")?;
    Ok(core.snapshot())
}

#[tauri::command]
fn set_mode(mode: AppMode, state: State<'_, SharedApp>) -> Result<AppSnapshot, String> {
    let mut core = state.inner.lock().map_err(|_| "state lock poisoned")?;
    core.set_mode(mode).map_err(to_command_error)
}

#[tauri::command]
fn start_receiver_services(state: State<'_, SharedApp>) -> Result<AppSnapshot, String> {
    let mut core = state.inner.lock().map_err(|_| "state lock poisoned")?;
    let identity = core.identity.clone();
    core.discovery
        .start_receiver(&identity)
        .map_err(to_command_error)?;
    core.discovery_active = true;
    Ok(core.snapshot())
}

#[tauri::command]
fn discover_devices(state: State<'_, SharedApp>) -> Result<AppSnapshot, String> {
    let devices = discovery::browse_once().map_err(to_command_error)?;
    let mut core = state.inner.lock().map_err(|_| "state lock poisoned")?;
    core.merge_discovered(devices);
    Ok(core.snapshot())
}

#[tauri::command]
fn request_pairing(device_id: String, state: State<'_, SharedApp>) -> Result<PairingResult, String> {
    let mut core = state.inner.lock().map_err(|_| "state lock poisoned")?;
    core.request_pairing(&device_id).map_err(to_command_error)
}

#[tauri::command]
fn verify_pairing(
    device_id: String,
    code: String,
    state: State<'_, SharedApp>,
) -> Result<PairingResult, String> {
    let mut core = state.inner.lock().map_err(|_| "state lock poisoned")?;
    core.verify_pairing(&device_id, &code)
        .map_err(to_command_error)
}

#[tauri::command]
fn remove_trusted_device(
    device_id: String,
    state: State<'_, SharedApp>,
) -> Result<AppSnapshot, String> {
    let mut core = state.inner.lock().map_err(|_| "state lock poisoned")?;
    core.config
        .trusted_devices
        .retain(|device| device.device_id != device_id);
    core.save().map_err(to_command_error)?;
    Ok(core.snapshot())
}

#[tauri::command]
fn send_file_to_device(
    request: FileTransferRequest,
    state: State<'_, SharedApp>,
) -> Result<TransferRecord, String> {
    {
        let core = state.inner.lock().map_err(|_| "state lock poisoned")?;
        ensure_trusted_or_local(&core, &request.target_device_id).map_err(to_command_error)?;
    }

    let record = transfer::copy_to_downloads(&request.source_path).map_err(to_command_error)?;
    let mut core = state.inner.lock().map_err(|_| "state lock poisoned")?;
    core.transfers.insert(0, record.clone());
    Ok(record)
}

#[tauri::command]
fn start_screen_share(
    request: StartScreenRequest,
    state: State<'_, SharedApp>,
) -> Result<ScreenSession, String> {
    let mut core = state.inner.lock().map_err(|_| "state lock poisoned")?;
    ensure_trusted_or_local(&core, &request.target_device_id).map_err(to_command_error)?;
    let source = CaptureSource;
    let session = source.start(request);
    core.screen_session = Some(session.clone());
    Ok(session)
}

#[tauri::command]
fn stop_screen_share(state: State<'_, SharedApp>) -> Result<AppSnapshot, String> {
    let mut core = state.inner.lock().map_err(|_| "state lock poisoned")?;
    core.screen_session = None;
    Ok(core.snapshot())
}

#[tauri::command]
fn open_downloads_folder() -> Result<(), String> {
    let path = storage::downloads_dir().map_err(to_command_error)?;
    std::fs::create_dir_all(&path).map_err(to_command_error)?;
    open_path(path).map_err(to_command_error)
}

#[tauri::command]
fn available_display_sources() -> Vec<DisplaySourceKind> {
    let capture = CaptureSource;
    let virtual_display = VirtualDisplaySource;
    vec![capture.kind(), virtual_display.kind()]
}

pub fn run() {
    let core = AppCore::load().expect("failed to load ShArIngM state");

    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .manage(SharedApp {
            inner: Mutex::new(core),
        })
        .setup(|app| {
            let state = app.state::<SharedApp>();
            let mut core = state.inner.lock().map_err(|_| "state lock poisoned")?;
            if core.config.mode == AppMode::Receiver {
                let identity = core.identity.clone();
                core.discovery.start_receiver(&identity)?;
                core.discovery_active = true;
            }
            drop(core);

            #[cfg(desktop)]
            create_tray(app)?;
            Ok(())
        })
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                let should_hide_to_tray = window
                    .state::<SharedApp>()
                    .inner
                    .lock()
                    .map(|core| core.config.mode == AppMode::Receiver)
                    .unwrap_or(false);

                if should_hide_to_tray {
                    api.prevent_close();
                    let _ = window.hide();
                }
            }
        })
        .invoke_handler(tauri::generate_handler![
            get_snapshot,
            set_mode,
            start_receiver_services,
            discover_devices,
            request_pairing,
            verify_pairing,
            remove_trusted_device,
            send_file_to_device,
            start_screen_share,
            stop_screen_share,
            open_downloads_folder,
            available_display_sources
        ])
        .build(tauri::generate_context!())
        .expect("error while building ShArIngM")
        .run(|app, event| {
            if let tauri::RunEvent::Reopen { .. } = event {
                show_main_window(app);
            }
        });
}

fn show_main_window(app: &AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.unminimize();
        let _ = window.set_focus();
    }
}

fn ensure_trusted_or_local(core: &AppCore, device_id: &str) -> Result<()> {
    if core.config.device_id == device_id
        || core
            .config
            .trusted_devices
            .iter()
            .any(|device| device.device_id == device_id)
    {
        Ok(())
    } else {
        bail!("device is not trusted yet")
    }
}

fn open_path(path: PathBuf) -> Result<()> {
    #[cfg(target_os = "windows")]
    {
        Command::new("explorer").arg(path).spawn()?;
        return Ok(());
    }
    #[cfg(target_os = "macos")]
    {
        Command::new("open").arg(path).spawn()?;
        return Ok(());
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        Command::new("xdg-open").arg(path).spawn()?;
        return Ok(());
    }
    #[allow(unreachable_code)]
    Ok(())
}

fn to_command_error(error: impl std::fmt::Display) -> String {
    error.to_string()
}

#[cfg(desktop)]
fn create_tray(app: &tauri::App) -> tauri::Result<()> {
    use tauri::{
        menu::{Menu, MenuItem},
        tray::TrayIconBuilder,
    };

    let show = MenuItem::with_id(app, "show", "打开 ShArIngM", true, None::<&str>)?;
    let quit = MenuItem::with_id(app, "quit", "退出", true, None::<&str>)?;
    let menu = Menu::with_items(app, &[&show, &quit])?;

    let _tray = TrayIconBuilder::new()
        .tooltip("ShArIngM")
        .menu(&menu)
        .on_tray_icon_event(|tray, event| {
            use tauri::tray::{MouseButton, MouseButtonState, TrayIconEvent};

            match event {
                TrayIconEvent::Click {
                    button: MouseButton::Left,
                    button_state: MouseButtonState::Up,
                    ..
                }
                | TrayIconEvent::DoubleClick {
                    button: MouseButton::Left,
                    ..
                } => show_main_window(tray.app_handle()),
                _ => {}
            }
        })
        .on_menu_event(|app, event| match event.id.as_ref() {
            "show" => show_main_window(app),
            "quit" => app.exit(0),
            _ => {}
        })
        .build(app)?;
    Ok(())
}
