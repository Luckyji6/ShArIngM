use crate::models::{DisplaySourceKind, ScreenSession, StartScreenRequest};
use anyhow::{Context, Result};
use chrono::Utc;
use image::{codecs::jpeg::JpegEncoder, imageops::FilterType, DynamicImage};
use screenshots::Screen;
use std::io::Cursor;
use uuid::Uuid;

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

pub struct CapturedFrame {
    pub width: u32,
    pub height: u32,
    pub mime_type: String,
    pub bytes: Vec<u8>,
}

pub fn capture_primary_frame(max_width: u32, max_height: u32) -> Result<CapturedFrame> {
    let screens = Screen::all().context("failed to enumerate screens")?;
    let screen = screens.first().context("no screen available for capture")?;
    let image = screen.capture().context("failed to capture screen")?;
    let mut dynamic = DynamicImage::ImageRgba8(image);

    let width = dynamic.width();
    let height = dynamic.height();
    if width > max_width || height > max_height {
        let scale = (max_width as f32 / width as f32).min(max_height as f32 / height as f32);
        let next_width = ((width as f32 * scale).round() as u32).max(1);
        let next_height = ((height as f32 * scale).round() as u32).max(1);
        dynamic = dynamic.resize(next_width, next_height, FilterType::Triangle);
    }

    let mut bytes = Vec::new();
    let mut cursor = Cursor::new(&mut bytes);
    let mut encoder = JpegEncoder::new_with_quality(&mut cursor, 82);
    encoder
        .encode_image(&dynamic)
        .context("failed to encode screen frame")?;

    Ok(CapturedFrame {
        width: dynamic.width(),
        height: dynamic.height(),
        mime_type: "image/jpeg".to_string(),
        bytes,
    })
}
