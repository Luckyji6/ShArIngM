mod autostart;
mod clipboard;
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
        AppMode, AppSnapshot, ClipboardTextRecord, ClipboardTextRequest, DisplaySourceKind,
        FileTransferRequest, LanDevice, NetworkDiagnosticReport, PairingResult, PendingPairing,
        ScreenFrame, ScreenSession, StartScreenRequest, TransferRecord,
    },
    storage::StoredConfig,
};
use anyhow::{bail, Context, Result};
use std::{
    collections::HashMap,
    path::PathBuf,
    process::Command,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread::{self, JoinHandle},
    time::Duration,
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
    clipboard_texts: Vec<ClipboardTextRecord>,
    screen_session: Option<ScreenSession>,
    screen_stream_shutdown: Option<Arc<AtomicBool>>,
    screen_stream_thread: Option<JoinHandle<()>>,
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
            clipboard_texts: Vec::new(),
            screen_session: None,
            screen_stream_shutdown: None,
            screen_stream_thread: None,
            discovery_active: false,
        })
    }

    fn save(&self) -> Result<()> {
        storage::save_to_path(&self.config_path, &self.config)
    }

    fn sync_runtime_updates(&mut self) -> Result<()> {
        let updates = self.discovery.drain_trusted_updates();
        let transfers = self.discovery.drain_transfer_updates();
        let clipboard_texts = self.discovery.drain_clipboard_updates();
        let mut changed = false;

        for trusted in updates {
            self.config
                .trusted_devices
                .retain(|device| device.device_id != trusted.device_id);
            self.config.trusted_devices.push(trusted);
            changed = true;
        }
        for transfer in transfers {
            self.transfers.insert(0, transfer);
        }
        for record in clipboard_texts {
            self.clipboard_texts.insert(0, record);
        }

        if changed {
            self.save()?;
        }
        Ok(())
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
            pending_pairing: self
                .discovery
                .pending_pairing()
                .or_else(|| self.pending_pairing.clone()),
            transfers: self.transfers.clone(),
            clipboard_texts: self.clipboard_texts.clone(),
            screen_session: self.screen_session.clone(),
        }
    }

    fn set_mode(&mut self, mode: AppMode) -> Result<AppSnapshot> {
        self.config.mode = mode.clone();
        self.config.autostart_required = mode == AppMode::Receiver;

        if mode == AppMode::Receiver {
            autostart::enable_receiver_autostart()?;
            let identity = self.identity.clone();
            let config_path = self.config_path.clone();
            self.discovery.start_receiver(&identity, config_path)?;
            self.discovery_active = true;
        } else {
            autostart::disable_receiver_autostart()?;
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
        let candidates = discovery::candidate_addresses_for(&device);
        let requester = self.identity.public_identity();
        let (reachable, result) =
            discovery::request_remote_pairing(&candidates, device.port, &requester).context(
                "被控端控制端口不可达，请确认另一台电脑已启动被控端服务，并允许防火墙访问",
            )?;
        if let Some(stored) = self.discovered.get_mut(&device.device_id) {
            stored.address = reachable.clone();
            if !stored.extra_addresses.iter().any(|item| item == &reachable) {
                stored.extra_addresses.insert(0, reachable.clone());
            }
        }
        Ok(result)
    }

    fn verify_pairing(&mut self, device_id: &str, code: &str) -> Result<PairingResult> {
        let device = self
            .discovered
            .get(device_id)
            .cloned()
            .context("paired device is no longer available")?;
        let candidates = discovery::candidate_addresses_for(&device);
        let requester = self.identity.public_identity();
        let (reachable, trusted_device, result) =
            discovery::verify_remote_pairing(&candidates, device.port, &requester, code)?;
        if let Some(stored) = self.discovered.get_mut(&device.device_id) {
            stored.address = reachable.clone();
            if !stored.extra_addresses.iter().any(|item| item == &reachable) {
                stored.extra_addresses.insert(0, reachable);
            }
        }

        self.config
            .trusted_devices
            .retain(|item| item.device_id != device_id);
        self.config.trusted_devices.push(trusted_device);
        self.pending_pairing = None;
        self.save()?;

        Ok(result)
    }

    fn stop_screen_stream(&mut self) {
        if let Some(shutdown) = self.screen_stream_shutdown.take() {
            shutdown.store(true, Ordering::SeqCst);
        }
        if let Some(handle) = self.screen_stream_thread.take() {
            let _ = handle.join();
        }
        self.screen_session = None;
    }
}

#[tauri::command]
fn get_snapshot(state: State<'_, SharedApp>) -> Result<AppSnapshot, String> {
    let mut core = state.inner.lock().map_err(|_| "state lock poisoned")?;
    core.sync_runtime_updates().map_err(to_command_error)?;
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
    let config_path = core.config_path.clone();
    core.discovery
        .start_receiver(&identity, config_path)
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
fn request_pairing(
    device_id: String,
    state: State<'_, SharedApp>,
) -> Result<PairingResult, String> {
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
fn clear_trusted_devices(state: State<'_, SharedApp>) -> Result<AppSnapshot, String> {
    let mut core = state.inner.lock().map_err(|_| "state lock poisoned")?;
    core.config.trusted_devices.clear();
    core.pending_pairing = None;
    core.save().map_err(to_command_error)?;
    Ok(core.snapshot())
}

#[tauri::command]
fn send_file_to_device(
    request: FileTransferRequest,
    state: State<'_, SharedApp>,
) -> Result<TransferRecord, String> {
    let (device, requester) = {
        let core = state.inner.lock().map_err(|_| "state lock poisoned")?;
        ensure_trusted_or_local(&core, &request.target_device_id).map_err(to_command_error)?;
        let device = core
            .discovered
            .get(&request.target_device_id)
            .cloned()
            .context("target device was not found")
            .map_err(to_command_error)?;
        (device, core.identity.public_identity())
    };

    let candidates = discovery::candidate_addresses_for(&device);
    let (reachable, record) =
        discovery::send_remote_file(&candidates, device.port, &requester, &request.source_path)
            .map_err(to_command_error)?;
    let mut core = state.inner.lock().map_err(|_| "state lock poisoned")?;
    if let Some(stored) = core.discovered.get_mut(&device.device_id) {
        stored.address = reachable.clone();
        if !stored.extra_addresses.iter().any(|item| item == &reachable) {
            stored.extra_addresses.insert(0, reachable);
        }
    }
    core.transfers.insert(0, record.clone());
    Ok(record)
}

#[tauri::command]
fn send_clipboard_text_to_device(
    request: ClipboardTextRequest,
    state: State<'_, SharedApp>,
) -> Result<ClipboardTextRecord, String> {
    if request.text.trim().is_empty() {
        return Err("剪贴板文本不能为空。".to_string());
    }
    if request.text.len() > 64 * 1024 {
        return Err("剪贴板文本不能超过 64KB。".to_string());
    }

    let (device, requester) = {
        let core = state.inner.lock().map_err(|_| "state lock poisoned")?;
        ensure_trusted_or_local(&core, &request.target_device_id).map_err(to_command_error)?;
        let device = core
            .discovered
            .get(&request.target_device_id)
            .cloned()
            .context("target device was not found")
            .map_err(to_command_error)?;
        (device, core.identity.public_identity())
    };

    let candidates = discovery::candidate_addresses_for(&device);
    let (reachable, record) =
        discovery::send_remote_clipboard_text(&candidates, device.port, &requester, &request.text)
            .map_err(to_command_error)?;

    let mut core = state.inner.lock().map_err(|_| "state lock poisoned")?;
    if let Some(stored) = core.discovered.get_mut(&device.device_id) {
        stored.address = reachable.clone();
        if !stored.extra_addresses.iter().any(|item| item == &reachable) {
            stored.extra_addresses.insert(0, reachable);
        }
    }
    core.clipboard_texts.insert(0, record.clone());
    Ok(record)
}

#[tauri::command]
fn start_screen_share(
    request: StartScreenRequest,
    state: State<'_, SharedApp>,
) -> Result<ScreenSession, String> {
    let (device, sender, session, shutdown) = {
        let mut core = state.inner.lock().map_err(|_| "state lock poisoned")?;
        ensure_trusted_or_local(&core, &request.target_device_id).map_err(to_command_error)?;
        let device = core
            .discovered
            .get(&request.target_device_id)
            .cloned()
            .context("target device was not found")
            .map_err(to_command_error)?;
        core.stop_screen_stream();
        let source = CaptureSource;
        let session = source.start(request);
        let shutdown = Arc::new(AtomicBool::new(false));
        core.screen_session = Some(session.clone());
        (device, core.identity.public_identity(), session, shutdown)
    };

    let thread_shutdown = shutdown.clone();
    let session_for_thread = session.clone();
    let handle = thread::spawn(move || {
        let fps = session_for_thread.fps.clamp(1, 20);
        let delay = Duration::from_millis((1000 / fps as u64).max(80));
        let mut reachable = discovery::candidate_addresses_for(&device);
        while !thread_shutdown.load(Ordering::SeqCst) {
            match display::capture_primary_frame(
                session_for_thread.width,
                session_for_thread.height,
            ) {
                Ok(frame) => {
                    match discovery::send_screen_frame(
                        &reachable,
                        device.port,
                        &sender,
                        &session_for_thread,
                        frame.width,
                        frame.height,
                        frame.mime_type,
                        frame.bytes,
                    ) {
                        Ok(address) => {
                            if reachable.first() != Some(&address) {
                                reachable.retain(|item| item != &address);
                                reachable.insert(0, address);
                            }
                        }
                        Err(error) => eprintln!("screen frame send failed: {error:#}"),
                    }
                }
                Err(error) => eprintln!("screen capture failed: {error:#}"),
            }
            thread::sleep(delay);
        }
    });

    let mut core = state.inner.lock().map_err(|_| "state lock poisoned")?;
    core.screen_stream_shutdown = Some(shutdown);
    core.screen_stream_thread = Some(handle);
    Ok(session)
}

#[tauri::command]
fn stop_screen_share(state: State<'_, SharedApp>) -> Result<AppSnapshot, String> {
    let mut core = state.inner.lock().map_err(|_| "state lock poisoned")?;
    core.stop_screen_stream();
    Ok(core.snapshot())
}

#[tauri::command]
fn get_latest_screen_frame(state: State<'_, SharedApp>) -> Result<Option<ScreenFrame>, String> {
    let core = state.inner.lock().map_err(|_| "state lock poisoned")?;
    Ok(core.discovery.latest_screen_frame())
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

#[tauri::command]
fn run_network_diagnostic(state: State<'_, SharedApp>) -> Result<NetworkDiagnosticReport, String> {
    let mode = {
        let core = state.inner.lock().map_err(|_| "state lock poisoned")?;
        core.config.mode.clone()
    };
    Ok(discovery::run_network_diagnostic(mode))
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
                autostart::enable_receiver_autostart()?;
                let identity = core.identity.clone();
                let config_path = core.config_path.clone();
                core.discovery.start_receiver(&identity, config_path)?;
                core.discovery_active = true;
            }
            drop(core);

            #[cfg(desktop)]
            create_tray(app)?;
            if autostart::is_background_launch() {
                if let Some(window) = app.get_webview_window("main") {
                    let _ = window.hide();
                }
            }
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
            clear_trusted_devices,
            send_file_to_device,
            send_clipboard_text_to_device,
            start_screen_share,
            stop_screen_share,
            get_latest_screen_frame,
            open_downloads_folder,
            available_display_sources,
            run_network_diagnostic
        ])
        .build(tauri::generate_context!())
        .expect("error while building ShArIngM")
        .run(|app, event| {
            #[cfg(target_os = "macos")]
            {
                if let tauri::RunEvent::Reopen { .. } = event {
                    show_main_window(app);
                }
            }

            #[cfg(not(target_os = "macos"))]
            {
                let _ = app;
                let _ = event;
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
