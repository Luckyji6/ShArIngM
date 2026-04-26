import React, { useEffect, useMemo, useState } from "react";
import { createRoot } from "react-dom/client";
import { invoke } from "@tauri-apps/api/core";
import { getCurrentWebview } from "@tauri-apps/api/webview";
import { Modal, notification, Spin } from "antd";
import {
  AlertTriangle,
  Cast,
  Check,
  ClipboardCopy,
  CircleX,
  Download,
  FolderOpen,
  Info,
  MonitorUp,
  PlugZap,
  Radar,
  RefreshCcw,
  Settings,
  ScreenShare,
  Send,
  ShieldCheck,
  Stethoscope,
  Trash2,
  Wifi,
} from "lucide-react";
import "antd/dist/reset.css";
import "./styles.css";

type AppMode = "sender" | "receiver";

type DeviceIdentity = {
  device_id: string;
  device_name: string;
  public_key: string;
  fingerprint: string;
};

type LanDevice = {
  device_id: string;
  device_name: string;
  address: string;
  port: number;
  public_key: string;
  fingerprint: string;
  protocol_version: string;
  capabilities: string[];
  last_seen_ms: number;
  extra_addresses?: string[];
};

type TrustedDevice = {
  device_id: string;
  device_name: string;
  public_key: string;
  fingerprint: string;
  trusted_at_ms: number;
  last_connected_ms?: number;
};

type PendingPairing = {
  device_id: string;
  device_name: string;
  code: string;
  expires_at_ms: number;
};

type TransferRecord = {
  id: string;
  file_name: string;
  destination: string;
  size_bytes: number;
  hash: string;
  completed_at_ms: number;
};

type ClipboardTextRecord = {
  id: string;
  sender_device_id: string;
  sender_device_name: string;
  preview: string;
  char_count: number;
  received_at_ms: number;
};

type ScreenSession = {
  id: string;
  device_id: string;
  display_name: string;
  width: number;
  height: number;
  fps: number;
  bitrate_kbps: number;
  source_kind: "capture_source" | "virtual_display_source";
  started_at_ms: number;
};

type ScreenFrame = {
  session: ScreenSession;
  width: number;
  height: number;
  mime_type: string;
  data_url: string;
  updated_at_ms: number;
};

type AppSnapshot = {
  identity: DeviceIdentity;
  mode: AppMode;
  autostart_required: boolean;
  discovery_active: boolean;
  trusted_devices: TrustedDevice[];
  discovered_devices: LanDevice[];
  pending_pairing?: PendingPairing;
  transfers: TransferRecord[];
  clipboard_texts: ClipboardTextRecord[];
  screen_session?: ScreenSession;
};

type PairingResult = {
  trusted: boolean;
  challenge_required: boolean;
  code_hint?: string;
  message: string;
};

type DiagnosticStatus = "ok" | "warn" | "fail";

type DiagnosticItem = {
  id: string;
  label: string;
  status: DiagnosticStatus;
  detail: string;
};

type DiagnosticInterface = {
  name: string;
  address: string;
  broadcast?: string;
  is_loopback: boolean;
};

type NetworkDiagnosticReport = {
  mode: AppMode;
  generated_at_ms: number;
  overall_status: DiagnosticStatus;
  items: DiagnosticItem[];
  interfaces: DiagnosticInterface[];
  broadcast_targets: string[];
  firewall_hint?: string;
};

const DEFAULT_DISPLAY = {
  display_name: "Primary Display",
  width: 1920,
  height: 1080,
  fps: 20,
  bitrate_kbps: 12000,
};

function App() {
  const [snapshot, setSnapshot] = useState<AppSnapshot | null>(null);
  const [selectedDeviceId, setSelectedDeviceId] = useState("");
  const [pairingCode, setPairingCode] = useState("");
  const [filePath, setFilePath] = useState("");
  const [clipboardText, setClipboardText] = useState("");
  const [busy, setBusy] = useState(false);
  const [scanning, setScanning] = useState(false);
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [diagnosticOpen, setDiagnosticOpen] = useState(false);
  const [diagnostic, setDiagnostic] = useState<NetworkDiagnosticReport | null>(null);
  const [diagnosticRunning, setDiagnosticRunning] = useState(false);
  const [latestScreenFrame, setLatestScreenFrame] = useState<ScreenFrame | null>(null);

  const selectedDevice = useMemo(() => {
    if (!snapshot) return undefined;
    return snapshot.discovered_devices.find(
      (device) => device.device_id === selectedDeviceId,
    );
  }, [snapshot, selectedDeviceId]);

  const isTrusted = useMemo(() => {
    if (!snapshot || !selectedDeviceId) return false;
    return snapshot.trusted_devices.some(
      (device) => device.device_id === selectedDeviceId,
    );
  }, [snapshot, selectedDeviceId]);

  useEffect(() => {
    refresh();
  }, []);

  useEffect(() => {
    let cleanup: (() => void) | undefined;
    getCurrentWebview()
      .onDragDropEvent((event) => {
        if (event.payload.type === "drop" && event.payload.paths[0]) {
          setFilePath(event.payload.paths[0]);
          notify("info", "已选择文件", event.payload.paths[0]);
        }
      })
      .then((unlisten) => {
        cleanup = unlisten;
      })
      .catch(() => undefined);
    return () => cleanup?.();
  }, []);

  useEffect(() => {
    if (!snapshot || selectedDeviceId) return;
    const first = snapshot.discovered_devices[0];
    if (first) setSelectedDeviceId(first.device_id);
  }, [snapshot, selectedDeviceId]);

  useEffect(() => {
    if (snapshot?.mode !== "receiver") return;
    const timer = window.setInterval(() => {
      invoke<AppSnapshot>("get_snapshot")
        .then(setSnapshot)
        .catch(() => undefined);
      invoke<ScreenFrame | null>("get_latest_screen_frame")
        .then(setLatestScreenFrame)
        .catch(() => undefined);
    }, 1200);
    return () => window.clearInterval(timer);
  }, [snapshot?.mode]);

  function notify(type: "success" | "error" | "info", title: string, body?: string) {
    notification[type]({
      message: title,
      description: body,
      placement: "topRight",
      duration: 3.2,
    });
  }

  async function run<T>(
    task: () => Promise<T>,
    success?: (value: T) => void,
  ): Promise<boolean> {
    setBusy(true);
    try {
      const value = await task();
      success?.(value);
      return true;
    } catch (err) {
      notify("error", "操作失败", err instanceof Error ? err.message : String(err));
      return false;
    } finally {
      setBusy(false);
    }
  }

  async function refresh() {
    await run(
      () => invoke<AppSnapshot>("get_snapshot"),
      (next) => setSnapshot(next),
    );
  }

  async function setMode(mode: AppMode) {
    const previousMode = snapshot?.mode;
    return run(
      () => invoke<AppSnapshot>("set_mode", { mode }),
      (next) => {
        setSnapshot(next);
        if (mode === "receiver" && previousMode === "receiver") {
          notify("success", "被控端服务已刷新", "后台接收服务正在运行。");
        } else if (mode === "receiver") {
          notify("success", "已切换为被控端", "后台接收服务已启动，关闭窗口后会继续运行。");
        } else {
          notify("success", "已切换为控制端", "已停止被控端后台服务。");
        }
      },
    );
  }

  async function refreshReceiverService() {
    await run(
      () => invoke<AppSnapshot>("start_receiver_services"),
      (next) => {
        setSnapshot(next);
        notify("success", "被控端服务已刷新", "后台接收服务正在运行。");
      },
    );
  }

  async function discover() {
    if (scanning) return;
    setScanning(true);
    await nextPaint();
    try {
      const next = await invoke<AppSnapshot>("discover_devices");
      setSnapshot(next);
      notify("success", "扫描完成", `发现 ${next.discovered_devices.length} 台可用设备。`);
    } catch (err) {
      notify("error", "扫描失败", err instanceof Error ? err.message : String(err));
    } finally {
      setScanning(false);
    }
  }

  async function pair() {
    if (!selectedDeviceId) return;
    await run(
      () => invoke<PairingResult>("request_pairing", { deviceId: selectedDeviceId }),
      (result) => {
        setPairingCode("");
        notify("info", "已发送验证码请求", result.message);
      },
    );
  }

  async function verify() {
    if (!selectedDeviceId || !pairingCode) return;
    await run(
      () =>
        invoke<PairingResult>("verify_pairing", {
          deviceId: selectedDeviceId,
          code: pairingCode,
        }),
      (result) => {
        setPairingCode("");
        notify("success", "配对成功", result.message);
        refresh();
      },
    );
  }

  async function sendFile() {
    if (!selectedDeviceId || !filePath.trim()) return;
    await run(
      () =>
        invoke<TransferRecord>("send_file_to_device", {
          request: {
            source_path: filePath.trim(),
            target_device_id: selectedDeviceId,
          },
        }),
      (record) => {
        notify("success", "文件已发送", record.file_name);
        setFilePath("");
        refresh();
      },
    );
  }

  async function sendClipboardText() {
    if (!selectedDeviceId || !clipboardText.trim()) return;
    await run(
      () =>
        invoke<ClipboardTextRecord>("send_clipboard_text_to_device", {
          request: {
            target_device_id: selectedDeviceId,
            text: clipboardText,
          },
        }),
      (record) => {
        notify("success", "已写入被控端剪贴板", `${record.char_count} 个字符`);
        setClipboardText("");
        refresh();
      },
    );
  }

  async function startScreen() {
    if (!selectedDeviceId) return;
    await run(
      () =>
        invoke<ScreenSession>("start_screen_share", {
          request: {
            target_device_id: selectedDeviceId,
            ...DEFAULT_DISPLAY,
          },
        }),
      (session) => {
        notify(
          "success",
          "屏幕共享已启动",
          `${session.width}x${session.height}@${session.fps}`,
        );
        refresh();
      },
    );
  }

  async function stopScreen() {
    await run(
      () => invoke<AppSnapshot>("stop_screen_share"),
      (next) => {
        setSnapshot(next);
        notify("info", "屏幕共享已停止");
      },
    );
  }

  async function openDownloads() {
    await run(() => invoke<void>("open_downloads_folder"));
  }

  async function removeTrusted(deviceId: string) {
    await run(
      () => invoke<AppSnapshot>("remove_trusted_device", { deviceId }),
      (next) => {
        setSnapshot(next);
        notify("success", "已移除可信设备");
      },
    );
  }

  function clearTrusted() {
    Modal.confirm({
      title: "清空可信设备？",
      content: "清空后，所有设备再次连接都需要重新验证码验证。",
      okText: "清空",
      cancelText: "取消",
      okButtonProps: { danger: true },
      onOk: async () => {
        await run(
          () => invoke<AppSnapshot>("clear_trusted_devices"),
          (next) => {
            setSnapshot(next);
            setSelectedDeviceId("");
            setPairingCode("");
            notify("success", "已清空可信设备");
          },
        );
      },
    });
  }

  async function openDiagnostic() {
    setDiagnosticOpen(true);
    await runDiagnostic();
  }

  async function runDiagnostic() {
    if (diagnosticRunning) return;
    setDiagnosticRunning(true);
    try {
      const report = await invoke<NetworkDiagnosticReport>("run_network_diagnostic");
      setDiagnostic(report);
    } catch (err) {
      notify("error", "网络自查失败", err instanceof Error ? err.message : String(err));
    } finally {
      setDiagnosticRunning(false);
    }
  }

  if (!snapshot) {
    return (
      <main className="shell loading">
        <div className="loader" />
      </main>
    );
  }

  return (
    <main className="shell">
      <aside className="sidebar">
        <div>
          <h1>ShArIngM</h1>
          <p className="muted">{snapshot.identity.device_name}</p>
        </div>
        <div className="roleCard">
          {snapshot.mode === "receiver" ? <Cast size={20} /> : <MonitorUp size={20} />}
          <span>当前身份</span>
          <strong>{snapshot.mode === "receiver" ? "被控端" : "控制端"}</strong>
          <small>
            {snapshot.mode === "receiver"
              ? "关闭窗口后继续后台运行"
              : "主动搜索并连接被控端"}
          </small>
        </div>
        <button className="settingsButton" onClick={() => setSettingsOpen(true)}>
          <Settings size={18} />
          设置
        </button>
        <section className="identity">
          <span>设备 ID</span>
          <strong>{compact(snapshot.identity.device_id)}</strong>
          <span>指纹</span>
          <strong>{snapshot.identity.fingerprint}</strong>
        </section>
      </aside>

      <section className="content">
        <header className="topbar">
          <div>
            <p className="eyebrow">
              {snapshot.mode === "receiver" ? "Receiver" : "Sender"}
            </p>
            <h2>
              {snapshot.mode === "receiver"
                ? "后台接收屏幕与文件"
                : "搜索局域网设备并发送内容"}
            </h2>
          </div>
          <div className="statusStrip">
            <StatusPill active={snapshot.discovery_active} label="mDNS" />
            <StatusPill active={snapshot.autostart_required} label="自启" />
          </div>
        </header>

        {settingsOpen ? (
          <SettingsView
            snapshot={snapshot}
            busy={busy}
            onClose={() => setSettingsOpen(false)}
            onSetMode={setMode}
            onOpenDiagnostic={openDiagnostic}
            onClearTrusted={clearTrusted}
          />
        ) : snapshot.mode === "receiver" ? (
          <ReceiverView
            snapshot={snapshot}
            busy={busy}
            onStart={refreshReceiverService}
            onOpenDownloads={openDownloads}
            onRemoveTrusted={removeTrusted}
            onClearTrusted={clearTrusted}
            onOpenDiagnostic={openDiagnostic}
            latestScreenFrame={latestScreenFrame}
          />
        ) : (
          <SenderView
            snapshot={snapshot}
            busy={busy}
            scanning={scanning}
            selectedDeviceId={selectedDeviceId}
            selectedDevice={selectedDevice}
            isTrusted={isTrusted}
            pairingCode={pairingCode}
            filePath={filePath}
            onDiscover={discover}
            onSelect={setSelectedDeviceId}
            onPair={pair}
            onVerify={verify}
            onCodeChange={setPairingCode}
            onFileChange={setFilePath}
            clipboardText={clipboardText}
            onClipboardTextChange={setClipboardText}
            onSendFile={sendFile}
            onSendClipboardText={sendClipboardText}
            onStartScreen={startScreen}
            onStopScreen={stopScreen}
            onOpenDownloads={openDownloads}
            onOpenDiagnostic={openDiagnostic}
          />
        )}
      </section>

      <DiagnosticModal
        open={diagnosticOpen}
        running={diagnosticRunning}
        report={diagnostic}
        onClose={() => setDiagnosticOpen(false)}
        onRefresh={runDiagnostic}
      />
    </main>
  );
}

function SettingsView(props: {
  snapshot: AppSnapshot;
  busy: boolean;
  onClose: () => void;
  onSetMode: (mode: AppMode) => Promise<boolean>;
  onOpenDiagnostic: () => void;
  onClearTrusted: () => void;
}) {
  const [pendingMode, setPendingMode] = useState<AppMode>(props.snapshot.mode);
  const changed = pendingMode !== props.snapshot.mode;

  async function applyMode() {
    const success = await props.onSetMode(pendingMode);
    if (success) {
      props.onClose();
    }
  }

  return (
    <div className="settingsLayout">
      <section className="panel settingsPanel">
        <div className="settingsHeader">
          <PanelTitle icon={<Settings size={19} />} title="应用设置" />
          <button onClick={props.onClose}>完成</button>
        </div>
        <div className="settingBlock">
          <div>
            <strong>设备身份</strong>
            <p>身份切换会改变后台服务和局域网广播行为，因此只在设置里操作。</p>
          </div>
          <div className="roleOptions">
            <button
              className={pendingMode === "sender" ? "selected" : ""}
              onClick={() => setPendingMode("sender")}
              disabled={props.busy}
            >
              <MonitorUp size={20} />
              <span>
                <strong>控制端</strong>
                <small>搜索局域网被控端，发送屏幕和文件。</small>
              </span>
            </button>
            <button
              className={pendingMode === "receiver" ? "selected" : ""}
              onClick={() => setPendingMode("receiver")}
              disabled={props.busy}
            >
              <Cast size={20} />
              <span>
                <strong>被控端</strong>
                <small>启动后台监听服务，关闭窗口后仍在托盘运行。</small>
              </span>
            </button>
          </div>
          <button
            className="primary"
            onClick={applyMode}
            disabled={props.busy || !changed}
          >
            <Check size={17} />
            应用身份变更
          </button>
        </div>
        <div className="settingBlock compact">
          <strong>后台运行</strong>
          <p>
            被控端模式下，关闭主窗口会隐藏到后台并保持局域网服务；需要彻底退出时使用系统托盘菜单的退出。
          </p>
        </div>
        <div className="settingBlock">
          <div>
            <strong>本地网络自查</strong>
            <p>
              检测网卡、广播地址、mDNS 守护进程、UDP/TCP 监听情况，帮助快速定位发现不到设备或无法连接的原因。
            </p>
          </div>
          <button onClick={props.onOpenDiagnostic} disabled={props.busy}>
            <Stethoscope size={17} />
            运行网络自查
          </button>
        </div>
        <div className="settingBlock dangerBlock">
          <div>
            <strong>信任数据</strong>
            <p>
              清空本机记录的所有可信设备。用于重新测试验证码配对，或者撤销之前误保存的设备信任。
            </p>
          </div>
          <button
            className="dangerButton"
            onClick={props.onClearTrusted}
            disabled={props.busy || props.snapshot.trusted_devices.length === 0}
          >
            <Trash2 size={17} />
            清空可信设备
          </button>
        </div>
      </section>
    </div>
  );
}

function SenderView(props: {
  snapshot: AppSnapshot;
  busy: boolean;
  scanning: boolean;
  selectedDeviceId: string;
  selectedDevice?: LanDevice;
  isTrusted: boolean;
  pairingCode: string;
  filePath: string;
  clipboardText: string;
  onDiscover: () => void;
  onSelect: (id: string) => void;
  onPair: () => void;
  onVerify: () => void;
  onCodeChange: (code: string) => void;
  onFileChange: (path: string) => void;
  onClipboardTextChange: (text: string) => void;
  onSendFile: () => void;
  onSendClipboardText: () => void;
  onStartScreen: () => void;
  onStopScreen: () => void;
  onOpenDownloads: () => void;
  onOpenDiagnostic: () => void;
}) {
  return (
    <div className="grid">
      <section className="panel devices">
        <PanelTitle icon={<Radar size={19} />} title="局域网设备" />
        <div className="rowActions">
          <button
            className="primary"
            onClick={props.onDiscover}
            disabled={props.scanning}
          >
            {props.scanning ? <Loading size="small" /> : <RefreshCcw size={17} />}
            {props.scanning ? "扫描中" : "扫描设备"}
          </button>
          <button onClick={props.onOpenDiagnostic} disabled={props.scanning}>
            <Stethoscope size={17} />
            网络自查
          </button>
        </div>
        <div className="deviceList loadingHost">
          {props.scanning && <LoadingOverlay label="正在搜索局域网设备" />}
          {props.snapshot.discovered_devices.length === 0 && (
            <Empty text="当前没有发现被控端。请在另一台设备切换到被控端。" />
          )}
          {props.snapshot.discovered_devices.map((device) => (
            <button
              key={device.device_id}
              className={`deviceRow ${
                props.selectedDeviceId === device.device_id ? "selected" : ""
              }`}
              onClick={() => props.onSelect(device.device_id)}
            >
              <Wifi size={18} />
              <span>
                <strong>{device.device_name}</strong>
                <small>
                  {device.address}:{device.port} · {device.fingerprint}
                </small>
              </span>
              {props.snapshot.trusted_devices.some(
                (trusted) => trusted.device_id === device.device_id,
              ) && <ShieldCheck size={17} className="okIcon" />}
            </button>
          ))}
        </div>
      </section>

      <section className="panel actions">
        <PanelTitle icon={<PlugZap size={19} />} title="连接与验证" />
        {props.selectedDevice ? (
          <>
            <div className="selectedDevice">
              <strong>{props.selectedDevice.device_name}</strong>
              <span>{props.selectedDevice.fingerprint}</span>
            </div>
            {props.isTrusted ? (
              <div className="trustedBanner">
                <ShieldCheck size={18} />
                已受信任
              </div>
            ) : (
              <div className="pairingBox">
                <button onClick={props.onPair} disabled={props.busy}>
                  <ShieldCheck size={17} />
                  请求验证码
                </button>
                <div className="codeLine">
                  <input
                    value={props.pairingCode}
                    onChange={(event) => props.onCodeChange(event.target.value)}
                    placeholder="6 位验证码"
                    maxLength={6}
                  />
                  <button onClick={props.onVerify} disabled={props.busy}>
                    <Check size={17} />
                    验证
                  </button>
                </div>
              </div>
            )}
          </>
        ) : (
          <Empty text="选择一台设备后开始连接。" />
        )}
      </section>

      {props.isTrusted ? (
        <>
          <section className="panel share">
            <PanelTitle icon={<ScreenShare size={19} />} title="屏幕共享" />
            <div className="screenPreview">
              {props.snapshot.screen_session ? (
                <>
                  <div className="liveBadge">LIVE</div>
                  <strong>{props.snapshot.screen_session.display_name}</strong>
                  <span>
                    {props.snapshot.screen_session.width}x
                    {props.snapshot.screen_session.height} ·{" "}
                    {props.snapshot.screen_session.fps}fps ·{" "}
                    {props.snapshot.screen_session.bitrate_kbps / 1000}Mbps
                  </span>
                </>
              ) : (
                <span>未开始共享</span>
              )}
            </div>
            <div className="rowActions">
              <button
                className="primary"
                onClick={props.onStartScreen}
                disabled={props.busy || !props.isTrusted}
              >
                <ScreenShare size={17} />
                开始共享
              </button>
              <button onClick={props.onStopScreen} disabled={props.busy}>
                停止
              </button>
            </div>
          </section>

          <section className="panel transfer">
            <PanelTitle icon={<Send size={19} />} title="文件传输" />
            <div className="fileInput">
              <input
                value={props.filePath}
                onChange={(event) => props.onFileChange(event.target.value)}
                placeholder="输入或拖入本机文件绝对路径"
              />
              <button
                className="primary"
                onClick={props.onSendFile}
                disabled={props.busy || !props.isTrusted || !props.filePath.trim()}
              >
                <Send size={17} />
                发送
              </button>
            </div>
            <button onClick={props.onOpenDownloads}>
              <FolderOpen size={17} />
              打开接收目录
            </button>
            <TransferList transfers={props.snapshot.transfers} />
          </section>

          <section className="panel clipboardPanel">
            <PanelTitle icon={<ClipboardCopy size={19} />} title="剪贴板文本" />
            <textarea
              value={props.clipboardText}
              onChange={(event) => props.onClipboardTextChange(event.target.value)}
              placeholder="输入要复制到被控端剪贴板的文本"
              maxLength={64 * 1024}
            />
            <div className="rowActions">
              <button
                className="primary"
                onClick={props.onSendClipboardText}
                disabled={
                  props.busy || !props.isTrusted || !props.clipboardText.trim()
                }
              >
                <ClipboardCopy size={17} />
                复制到被控端
              </button>
              <span className="muted">{props.clipboardText.length}/65536</span>
            </div>
            <ClipboardList records={props.snapshot.clipboard_texts} />
          </section>
        </>
      ) : (
        <section className="panel placeholderPanel">
          <ShieldCheck size={32} />
          <p>连接并验证设备后，即可解锁屏幕共享和文件传输功能</p>
        </section>
      )}
    </div>
  );
}

function ReceiverView(props: {
  snapshot: AppSnapshot;
  busy: boolean;
  onStart: () => void;
  onOpenDownloads: () => void;
  onRemoveTrusted: (id: string) => void;
  onClearTrusted: () => void;
  onOpenDiagnostic: () => void;
  latestScreenFrame: ScreenFrame | null;
}) {
  const screenAge = props.latestScreenFrame
    ? Date.now() - props.latestScreenFrame.updated_at_ms
    : Infinity;
  const screenStale = screenAge > 3500;

  return (
    <div className="grid receiverGrid">
      <section className="panel receiverHero">
        <PanelTitle icon={<Download size={19} />} title="被控端服务" />
        <div className="receiverState">
          <div className="pulse" />
          <div>
            <strong>静默监听局域网连接</strong>
            <span>关闭窗口后继续后台运行。</span>
            <span>验证码验证通过后，才允许屏幕或文件通道。</span>
          </div>
        </div>
        {props.snapshot.pending_pairing && (
          <div className="receiverCodeBox">
            <span>来自 {props.snapshot.pending_pairing.device_name} 的连接请求</span>
            <strong>{props.snapshot.pending_pairing.code}</strong>
            <small>请在控制端输入此 6 位验证码。</small>
          </div>
        )}
        <button className="primary" onClick={props.onStart} disabled={props.busy}>
          <Radar size={17} />
          {props.snapshot.discovery_active ? "刷新服务" : "启动服务"}
        </button>
        <button onClick={props.onOpenDownloads}>
          <FolderOpen size={17} />
          打开下载目录
        </button>
        <button onClick={props.onOpenDiagnostic}>
          <Stethoscope size={17} />
          网络自查
        </button>
      </section>

      <section className="panel receiverScreen">
        <PanelTitle icon={<ScreenShare size={19} />} title="接收画面" />
        {props.latestScreenFrame ? (
          <>
            <div className="receiverScreenMeta">
              <strong>{props.latestScreenFrame.session.display_name}</strong>
              <span>
                {props.latestScreenFrame.width}x{props.latestScreenFrame.height}
                {screenStale ? " · 已暂停" : " · 实时接收"}
              </span>
            </div>
            <img
              src={props.latestScreenFrame.data_url}
              alt="远端屏幕画面"
              className={`receiverScreenImage ${screenStale ? "stale" : ""}`}
            />
          </>
        ) : (
          <div className="screenPreview">
            <span>等待控制端开始屏幕共享</span>
          </div>
        )}
      </section>

      <section className="panel trusted">
        <div className="trustedHeader">
          <PanelTitle icon={<ShieldCheck size={19} />} title="可信设备" />
          <button
            className="dangerButton ghostDanger"
            onClick={props.onClearTrusted}
            disabled={props.busy || props.snapshot.trusted_devices.length === 0}
          >
            <Trash2 size={16} />
            清空
          </button>
        </div>
        {props.snapshot.trusted_devices.length === 0 && (
          <Empty text="暂无可信设备。首次连接需要验证码。" />
        )}
        {props.snapshot.trusted_devices.map((device) => (
          <div className="trustedRow" key={device.device_id}>
            <span>
              <strong>{device.device_name}</strong>
              <small>{device.fingerprint}</small>
            </span>
            <button onClick={() => props.onRemoveTrusted(device.device_id)}>
              <Trash2 size={16} />
            </button>
          </div>
        ))}
      </section>

      <section className="panel transfer history">
        <PanelTitle icon={<Send size={19} />} title="接收记录" />
        <TransferList transfers={props.snapshot.transfers} />
      </section>

      <section className="panel clipboardPanel">
        <PanelTitle icon={<ClipboardCopy size={19} />} title="剪贴板记录" />
        <ClipboardList records={props.snapshot.clipboard_texts} />
      </section>
    </div>
  );
}

function DiagnosticModal(props: {
  open: boolean;
  running: boolean;
  report: NetworkDiagnosticReport | null;
  onClose: () => void;
  onRefresh: () => void;
}) {
  const overall = props.report?.overall_status;
  const overallLabel =
    overall === "ok"
      ? "整体正常"
      : overall === "warn"
      ? "存在告警"
      : overall === "fail"
      ? "存在阻断项"
      : "等待结果";
  return (
    <Modal
      open={props.open}
      onCancel={props.onClose}
      width={680}
      title={
        <div className="diagnosticTitle">
          <Stethoscope size={19} />
          <span>本地网络自查</span>
          {props.report && (
            <DiagnosticBadge status={props.report.overall_status} label={overallLabel} />
          )}
        </div>
      }
      footer={
        <div className="diagnosticFooter">
          <button onClick={props.onRefresh} disabled={props.running}>
            {props.running ? <Loading size="small" /> : <RefreshCcw size={17} />}
            重新检测
          </button>
          <button className="primary" onClick={props.onClose}>
            完成
          </button>
        </div>
      }
    >
      {props.running && !props.report ? (
        <div className="diagnosticLoading">
          <Loading />
          <span>正在收集网络信息...</span>
        </div>
      ) : props.report ? (
        <div className="diagnosticBody">
          <div className="diagnosticItems">
            {props.report.items.map((item) => (
              <div key={item.id} className={`diagnosticItem status-${item.status}`}>
                <DiagnosticIcon status={item.status} />
                <div>
                  <strong>{item.label}</strong>
                  <p>{item.detail}</p>
                </div>
              </div>
            ))}
          </div>

          <div className="diagnosticInterfaces">
            <h4>本机接口</h4>
            {props.report.interfaces.length === 0 ? (
              <p className="muted">未发现任何接口。</p>
            ) : (
              <div className="diagnosticInterfaceList">
                {props.report.interfaces.map((iface, index) => (
                  <div key={`${iface.name}-${iface.address}-${index}`} className="diagnosticIfaceRow">
                    <strong>{iface.name}</strong>
                    <span>{iface.address}</span>
                    <small>
                      {iface.is_loopback
                        ? "loopback"
                        : iface.broadcast
                        ? `bcast ${iface.broadcast}`
                        : "无广播"}
                    </small>
                  </div>
                ))}
              </div>
            )}
          </div>

          <div className="diagnosticTargets">
            <h4>广播投递目标</h4>
            {props.report.broadcast_targets.length === 0 ? (
              <p className="muted">未生成任何广播目标。</p>
            ) : (
              <ul>
                {props.report.broadcast_targets.map((target) => (
                  <li key={target}>{target}</li>
                ))}
              </ul>
            )}
          </div>

          {props.report.firewall_hint && (
            <div className="diagnosticHint">
              <Info size={16} />
              <span>{props.report.firewall_hint}</span>
            </div>
          )}
        </div>
      ) : (
        <Empty text="暂无自查结果，请点击重新检测。" />
      )}
    </Modal>
  );
}

function DiagnosticIcon({ status }: { status: DiagnosticStatus }) {
  if (status === "ok") return <Check size={18} className="okIcon" />;
  if (status === "warn") return <AlertTriangle size={18} className="warnIcon" />;
  return <CircleX size={18} className="failIcon" />;
}

function DiagnosticBadge({ status, label }: { status: DiagnosticStatus; label: string }) {
  return <span className={`diagnosticBadge status-${status}`}>{label}</span>;
}

function TransferList({ transfers }: { transfers: TransferRecord[] }) {
  if (transfers.length === 0) return <Empty text="还没有文件传输记录。" />;
  return (
    <div className="transferList">
      {transfers.map((transfer) => (
        <div key={transfer.id} className="transferRow">
          <strong>{transfer.file_name}</strong>
          <span>
            {formatBytes(transfer.size_bytes)} · {compact(transfer.hash)}
          </span>
        </div>
      ))}
    </div>
  );
}

function ClipboardList({ records }: { records: ClipboardTextRecord[] }) {
  if (records.length === 0) return <Empty text="还没有剪贴板记录。" />;
  return (
    <div className="clipboardList">
      {records.map((record) => (
        <div key={record.id} className="clipboardRow">
          <strong>{record.sender_device_name}</strong>
          <p>{record.preview || "(空文本)"}</p>
          <span>{record.char_count} 个字符</span>
        </div>
      ))}
    </div>
  );
}

function PanelTitle({ icon, title }: { icon: React.ReactNode; title: string }) {
  return (
    <div className="panelTitle">
      {icon}
      <h3>{title}</h3>
    </div>
  );
}

function StatusPill({ active, label }: { active: boolean; label: string }) {
  return (
    <span className={`statusPill ${active ? "active" : ""}`}>
      <span />
      {label}
    </span>
  );
}

function Loading({ size = "normal" }: { size?: "small" | "normal" }) {
  return <Spin size={size === "small" ? "small" : "default"} />;
}

function LoadingOverlay({ label }: { label: string }) {
  return (
    <div className="loadingOverlay">
      <Loading />
      <span>{label}</span>
    </div>
  );
}

function Empty({ text }: { text: string }) {
  return <p className="empty">{text}</p>;
}

function compact(value: string) {
  if (value.length <= 18) return value;
  return `${value.slice(0, 8)}...${value.slice(-6)}`;
}

function formatBytes(value: number) {
  if (value < 1024) return `${value} B`;
  if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} KB`;
  if (value < 1024 * 1024 * 1024) return `${(value / 1024 / 1024).toFixed(1)} MB`;
  return `${(value / 1024 / 1024 / 1024).toFixed(1)} GB`;
}

function nextPaint() {
  return new Promise<void>((resolve) => {
    requestAnimationFrame(() => {
      requestAnimationFrame(() => resolve());
    });
  });
}

createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
