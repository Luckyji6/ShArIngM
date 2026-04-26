use crate::models::{DisplaySourceKind, ScreenSession, StartScreenRequest};
use anyhow::{Context, Result};
use chrono::Utc;
use image::{codecs::jpeg::JpegEncoder, imageops::FilterType, DynamicImage};
use std::io::Cursor;
use uuid::Uuid;
use xcap::Monitor;

#[allow(dead_code)]
pub trait DisplaySource {
    fn kind(&self) -> DisplaySourceKind;
    fn start(&self, request: StartScreenRequest) -> ScreenSession;
}

pub struct CaptureSource;

impl DisplaySource for CaptureSource {
    fn kind(&self) -> DisplaySourceKind {
        DisplaySourceKind::CaptureSource
    }

    fn start(&self, request: StartScreenRequest) -> ScreenSession {
        ScreenSession {
            id: Uuid::new_v4().to_string(),
            device_id: request.target_device_id,
            display_name: request.display_name,
            width: request.width.clamp(640, 3840),
            height: request.height.clamp(360, 2160),
            fps: request.fps.clamp(5, 30),
            bitrate_kbps: request.bitrate_kbps.clamp(1_000, 40_000),
            source_kind: self.kind(),
            started_at_ms: Utc::now().timestamp_millis(),
        }
    }
}

pub struct VirtualDisplaySource;

impl DisplaySource for VirtualDisplaySource {
    fn kind(&self) -> DisplaySourceKind {
        DisplaySourceKind::VirtualDisplaySource
    }

    fn start(&self, request: StartScreenRequest) -> ScreenSession {
        ScreenSession {
            id: Uuid::new_v4().to_string(),
            device_id: request.target_device_id,
            display_name: request.display_name,
            width: request.width,
            height: request.height,
            fps: request.fps,
            bitrate_kbps: request.bitrate_kbps,
            source_kind: self.kind(),
            started_at_ms: Utc::now().timestamp_millis(),
        }
    }
}

#[allow(dead_code)]
pub struct CapturedFrame {
    pub width: u32,
    pub height: u32,
    pub mime_type: String,
    pub bytes: Vec<u8>,
}

#[allow(dead_code)]
pub fn capture_primary_frame(max_width: u32, max_height: u32) -> Result<CapturedFrame> {
    let monitors = Monitor::all().context("failed to enumerate monitors")?;
    let monitor = monitors
        .into_iter()
        .find(|m| m.is_primary().unwrap_or(false))
        .or_else(|| Monitor::all().ok()?.into_iter().next())
        .context("no monitor available for capture")?;

    let rgba = monitor.capture_image().context("failed to capture monitor")?;
    let mut dynamic = DynamicImage::ImageRgba8(rgba);

    let (w, h) = (dynamic.width(), dynamic.height());
    if w > max_width || h > max_height {
        let scale = (max_width as f32 / w as f32).min(max_height as f32 / h as f32);
        let nw = ((w as f32 * scale).round() as u32).max(1);
        let nh = ((h as f32 * scale).round() as u32).max(1);
        dynamic = dynamic.resize(nw, nh, FilterType::Triangle);
    }

    let mut bytes = Vec::new();
    let mut cursor = Cursor::new(&mut bytes);
    JpegEncoder::new_with_quality(&mut cursor, 82)
        .encode_image(&dynamic)
        .context("failed to encode frame")?;

    Ok(CapturedFrame {
        width: dynamic.width(),
        height: dynamic.height(),
        mime_type: "image/jpeg".to_string(),
        bytes,
    })
}
