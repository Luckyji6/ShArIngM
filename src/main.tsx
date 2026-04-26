import React, { useEffect, useMemo, useState } from "react";
import { createRoot } from "react-dom/client";
import { invoke } from "@tauri-apps/api/core";
import { notification, Spin } from "antd";
import {
  Cast,
  Check,
  Download,
  FolderOpen,
  MonitorUp,
  PlugZap,
  Radar,
  RefreshCcw,
  Settings,
  ScreenShare,
  Send,
  ShieldCheck,
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

type AppSnapshot = {
  identity: DeviceIdentity;
  mode: AppMode;
  autostart_required: boolean;
  discovery_active: boolean;
  trusted_devices: TrustedDevice[];
  discovered_devices: LanDevice[];
  pending_pairing?: PendingPairing;
  transfers: TransferRecord[];
  screen_session?: ScreenSession;
};

type PairingResult = {
  trusted: boolean;
  challenge_required: boolean;
  code_hint?: string;
  message: string;
};

const DEFAULT_DISPLAY = {
  display_name: "Primary Display",
  width: 1920,
  height: 1080,
  fps: 30,
  bitrate_kbps: 12000,
};

function App() {
  const [snapshot, setSnapshot] = useState<AppSnapshot | null>(null);
  const [selectedDeviceId, setSelectedDeviceId] = useState("");
  const [pairingCode, setPairingCode] = useState("");
  const [filePath, setFilePath] = useState("");
  const [busy, setBusy] = useState(false);
  const [scanning, setScanning] = useState(false);
  const [settingsOpen, setSettingsOpen] = useState(false);

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
    if (!snapshot || selectedDeviceId) return;
    const first = snapshot.discovered_devices[0];
    if (first) setSelectedDeviceId(first.device_id);
  }, [snapshot, selectedDeviceId]);

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
        if (result.code_hint) setPairingCode(result.code_hint);
        notify("info", "验证码已生成", result.message);
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
          />
        ) : snapshot.mode === "receiver" ? (
          <ReceiverView
            snapshot={snapshot}
            busy={busy}
            onStart={refreshReceiverService}
            onOpenDownloads={openDownloads}
            onRemoveTrusted={removeTrusted}
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
            onSendFile={sendFile}
            onStartScreen={startScreen}
            onStopScreen={stopScreen}
            onOpenDownloads={openDownloads}
          />
        )}
      </section>
    </main>
  );
}

function SettingsView(props: {
  snapshot: AppSnapshot;
  busy: boolean;
  onClose: () => void;
  onSetMode: (mode: AppMode) => Promise<boolean>;
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
  onDiscover: () => void;
  onSelect: (id: string) => void;
  onPair: () => void;
  onVerify: () => void;
  onCodeChange: (code: string) => void;
  onFileChange: (path: string) => void;
  onSendFile: () => void;
  onStartScreen: () => void;
  onStopScreen: () => void;
  onOpenDownloads: () => void;
}) {
  return (
    <div className="grid">
      <section className="panel devices">
        <PanelTitle icon={<Radar size={19} />} title="局域网设备" />
        <button
          className="primary"
          onClick={props.onDiscover}
          disabled={props.scanning}
        >
          {props.scanning ? <Loading size="small" /> : <RefreshCcw size={17} />}
          {props.scanning ? "扫描中" : "扫描设备"}
        </button>
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
}) {
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
        <button className="primary" onClick={props.onStart} disabled={props.busy}>
          <Radar size={17} />
          {props.snapshot.discovery_active ? "刷新服务" : "启动服务"}
        </button>
        <button onClick={props.onOpenDownloads}>
          <FolderOpen size={17} />
          打开下载目录
        </button>
      </section>

      <section className="panel trusted">
        <PanelTitle icon={<ShieldCheck size={19} />} title="可信设备" />
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
    </div>
  );
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
