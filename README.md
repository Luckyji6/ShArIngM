# ShArIngM

ShArIngM is a cross-platform LAN-first desktop app scaffold for local screen sharing and file transfer. The app uses Tauri for the desktop shell and Rust for identity, pairing, device discovery, persistence, file placement, and screen-source abstractions.

## Current Implementation

- Sender / Receiver mode switching.
- Receiver mDNS advertising on `_sharingm._tcp.local.`.
- Sender one-shot mDNS scanning.
- Persistent local Ed25519 identity and public-key fingerprint.
- First-pairing challenge flow with trusted-device persistence.
- File send flow that copies a local file into the receiver download directory model: `Downloads/ShArIngM/`, with duplicate-name handling and BLAKE3 verification.
- Screen sharing session API backed by `CaptureSource`, with `VirtualDisplaySource` kept as the future driver-backed extension point.
- Tauri UI for LAN devices, pairing, trusted devices, file transfer history, and screen session state.
- Bundled Smiley Sans / 得意黑 for display typography in brand and major headings.

The current media path is intentionally an interface-level implementation. Real low-latency H.264/HEVC capture, hardware encoding, QUIC media transport, and remote receiver rendering should replace the `CaptureSource` session stub without changing the frontend command shape.

## Run

```bash
npm install
npm run tauri dev
```

For frontend-only checks:

```bash
npm run build
cd src-tauri && cargo check
```

## Main Rust Modules

- `src-tauri/src/lib.rs`: Tauri commands and shared app state.
- `src-tauri/src/discovery.rs`: mDNS advertising and browsing.
- `src-tauri/src/identity.rs`: Ed25519 identity and fingerprint generation.
- `src-tauri/src/storage.rs`: local config and downloads directory resolution.
- `src-tauri/src/transfer.rs`: verified local file placement.
- `src-tauri/src/display.rs`: capture/virtual display source abstraction.

## Bundled Fonts

- `src/assets/fonts/SmileySans-Oblique.otf.woff2` is bundled from [atelier-anchor/smiley-sans](https://github.com/atelier-anchor/smiley-sans) release `v2.0.1`.
- Smiley Sans / 得意黑 is licensed under the SIL Open Font License 1.1. The bundled license is stored at `src/assets/fonts/LICENSE-SmileySans-OFL.txt`.

## Next Engineering Milestones

1. Replace local file-copy simulation with receiver-side reliable QUIC file streams.
2. Add a QUIC control channel for pairing, heartbeat, capability exchange, and transfer requests.
3. Implement platform capture and hardware encoder backends:
   - Windows: Desktop Duplication + Media Foundation.
   - macOS: ScreenCaptureKit + VideoToolbox.
   - Linux: PipeWire + VAAPI/software fallback.
4. Add receiver-side video decode/render surface.
5. Add real platform autostart installation and permission checks.
