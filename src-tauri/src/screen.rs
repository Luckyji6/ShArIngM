use crate::models::{PermissionState, PermissionStatus, SCREEN_STREAM_PORT};
use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose, Engine};
use image::DynamicImage;
use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};
use tauri::Emitter;
use xcap::Monitor;

// ── macOS screen recording permission ────────────────────────────────────────

#[cfg(target_os = "macos")]
#[link(name = "CoreGraphics", kind = "framework")]
extern "C" {
    fn CGPreflightScreenCaptureAccess() -> bool;
    fn CGRequestScreenCaptureAccess() -> bool;
}

pub fn preflight_screen_capture() -> PermissionStatus {
    #[cfg(target_os = "macos")]
    {
        if unsafe { CGPreflightScreenCaptureAccess() } {
            PermissionStatus::Granted
        } else {
            PermissionStatus::Denied
        }
    }
    #[cfg(not(target_os = "macos"))]
    PermissionStatus::Granted
}

pub fn request_screen_capture_permission() -> PermissionStatus {
    #[cfg(target_os = "macos")]
    {
        // This triggers the system dialog or opens System Settings.
        // It always returns false immediately; the user must restart the app.
        unsafe { CGRequestScreenCaptureAccess() };
        preflight_screen_capture()
    }
    #[cfg(not(target_os = "macos"))]
    PermissionStatus::Granted
}

pub fn check_permission_state() -> PermissionState {
    let screen_capture = preflight_screen_capture();
    let hint = match &screen_capture {
        PermissionStatus::Granted => "屏幕录制权限已授权。".to_string(),
        PermissionStatus::Denied => {
            if cfg!(target_os = "macos") {
                "屏幕录制权限未授权。请在系统设置 -> 隐私与安全 -> 屏幕录制中授权 ShArIngM，然后重启应用。".to_string()
            } else if cfg!(target_os = "windows") {
                "屏幕捕获权限未授权，请在系统设置中允许。".to_string()
            } else {
                "屏幕捕获权限不足，请检查系统设置。".to_string()
            }
        }
        PermissionStatus::Unknown => "无法确定屏幕录制权限状态。".to_string(),
    };
    PermissionState { screen_capture, hint }
}

// ── Frame wire format ─────────────────────────────────────────────────────────
// Header: [magic u32 BE][frame_index u32 BE][jpeg_len u32 BE]  = 12 bytes
// Body  : [jpeg_len bytes of JPEG data]

const FRAME_MAGIC: u32 = 0x534D_4600; // "SMF\0"
const MAX_FRAME_BYTES: usize = 16 * 1024 * 1024; // 16 MiB safety cap

fn encode_jpeg(rgba: image::RgbaImage, quality: u8) -> Result<Vec<u8>> {
    let rgb = DynamicImage::ImageRgba8(rgba).into_rgb8();
    let mut buf = Vec::new();
    let mut enc = image::codecs::jpeg::JpegEncoder::new_with_quality(&mut buf, quality);
    enc.encode_image(&rgb).context("JPEG encode failed")?;
    Ok(buf)
}

fn write_frame(stream: &mut TcpStream, index: u32, jpeg: &[u8]) -> Result<()> {
    let mut header = [0u8; 12];
    header[0..4].copy_from_slice(&FRAME_MAGIC.to_be_bytes());
    header[4..8].copy_from_slice(&index.to_be_bytes());
    header[8..12].copy_from_slice(&(jpeg.len() as u32).to_be_bytes());
    stream.write_all(&header).context("write frame header")?;
    stream.write_all(jpeg).context("write frame body")?;
    Ok(())
}

fn read_frame(stream: &mut TcpStream) -> Result<(u32, Vec<u8>)> {
    let mut header = [0u8; 12];
    stream.read_exact(&mut header).context("read frame header")?;
    let magic = u32::from_be_bytes(header[0..4].try_into().unwrap());
    if magic != FRAME_MAGIC {
        return Err(anyhow!("bad frame magic {:#010x}", magic));
    }
    let index = u32::from_be_bytes(header[4..8].try_into().unwrap());
    let len = u32::from_be_bytes(header[8..12].try_into().unwrap()) as usize;
    if len > MAX_FRAME_BYTES {
        return Err(anyhow!("frame too large ({} bytes)", len));
    }
    let mut jpeg = vec![0u8; len];
    stream.read_exact(&mut jpeg).context("read frame body")?;
    Ok((index, jpeg))
}

// ── Sender: capture → encode → push ──────────────────────────────────────────

pub struct CaptureSession {
    shutdown: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl CaptureSession {
    /// Connect to `target_addr:SCREEN_STREAM_PORT` and start pushing JPEG frames.
    pub fn start(target_addr: String, fps: u32, quality: u8) -> Result<Self> {
        let addr = format!("{target_addr}:{SCREEN_STREAM_PORT}");
        let mut stream =
            TcpStream::connect_timeout(&addr.parse().context("bad target addr")?, Duration::from_secs(5))
                .with_context(|| format!("cannot connect to receiver stream port ({addr})"))?;
        stream.set_nodelay(true).ok();

        let interval =
            Duration::from_millis(1000 / fps.clamp(1, 30) as u64);

        let shutdown = Arc::new(AtomicBool::new(false));
        let tsd = shutdown.clone();

        let handle = thread::spawn(move || {
            let mut index: u32 = 0;
            loop {
                let tick = Instant::now();
                if tsd.load(Ordering::SeqCst) {
                    break;
                }
                if let Some(rgba) = capture_primary() {
                    match encode_jpeg(rgba, quality) {
                        Ok(jpeg) => {
                            if write_frame(&mut stream, index, &jpeg).is_err() {
                                break; // receiver closed connection
                            }
                            index = index.wrapping_add(1);
                        }
                        Err(_) => {}
                    }
                }
                let elapsed = tick.elapsed();
                if elapsed < interval {
                    thread::sleep(interval - elapsed);
                }
            }
        });

        Ok(Self { shutdown, thread: Some(handle) })
    }

    pub fn stop(&mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
        if let Some(h) = self.thread.take() {
            let _ = h.join();
        }
    }
}

impl Drop for CaptureSession {
    fn drop(&mut self) {
        self.stop();
    }
}

fn capture_primary() -> Option<image::RgbaImage> {
    let monitors = Monitor::all().ok()?;
    // xcap lists primary monitor first on most platforms; fall back to index 0
    let primary = monitors
        .into_iter()
        .find(|m| m.is_primary().unwrap_or(false))
        .or_else(|| Monitor::all().ok()?.into_iter().next())?;
    primary.capture_image().ok()
}

// ── Receiver: listen → receive frames → emit Tauri events ────────────────────

pub struct FrameServer {
    shutdown: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl FrameServer {
    pub fn start(app_handle: tauri::AppHandle) -> Result<Self> {
        let listener =
            TcpListener::bind(format!("0.0.0.0:{SCREEN_STREAM_PORT}"))
                .with_context(|| format!("failed to bind screen stream port {SCREEN_STREAM_PORT}"))?;
        listener.set_nonblocking(true).ok();

        let shutdown = Arc::new(AtomicBool::new(false));
        let tsd = shutdown.clone();

        let handle = thread::spawn(move || {
            use std::io::ErrorKind;
            loop {
                if tsd.load(Ordering::SeqCst) {
                    break;
                }
                match listener.accept() {
                    Ok((mut stream, _peer)) => {
                        stream.set_nonblocking(false).ok();
                        let _ = stream.set_read_timeout(Some(Duration::from_secs(15)));
                        let app = app_handle.clone();
                        let stop = tsd.clone();
                        thread::spawn(move || {
                            recv_frames(&mut stream, &app, &stop);
                        });
                    }
                    Err(e) if e.kind() == ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(30));
                    }
                    Err(_) => break,
                }
            }
        });

        Ok(Self { shutdown, thread: Some(handle) })
    }

    pub fn stop(&mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
        if let Some(h) = self.thread.take() {
            let _ = h.join();
        }
    }
}

impl Drop for FrameServer {
    fn drop(&mut self) {
        self.stop();
    }
}

fn recv_frames(stream: &mut TcpStream, app: &tauri::AppHandle, stop: &AtomicBool) {
    loop {
        if stop.load(Ordering::SeqCst) {
            break;
        }
        match read_frame(stream) {
            Ok((index, jpeg)) => {
                let b64 = general_purpose::STANDARD.encode(&jpeg);
                let _ = app.emit(
                    "screen_frame",
                    serde_json::json!({ "index": index, "jpeg_b64": b64 }),
                );
            }
            Err(_) => break,
        }
    }
    // Notify frontend the stream ended
    let _ = app.emit("screen_frame_ended", serde_json::json!({}));
}
