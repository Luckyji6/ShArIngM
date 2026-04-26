use crate::models::{DisplaySourceKind, ScreenSession, StartScreenRequest};
use chrono::Utc;
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
            fps: request.fps.clamp(15, 60),
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
