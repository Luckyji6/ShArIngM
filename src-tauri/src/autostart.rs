use anyhow::{Context, Result};
use std::{env, path::PathBuf};

const APP_ID: &str = "app.sharingm.desktop";

pub fn enable_receiver_autostart() -> Result<()> {
    let exe = env::current_exe().context("failed to resolve current executable")?;
    enable_platform_autostart(exe)
}

pub fn disable_receiver_autostart() -> Result<()> {
    disable_platform_autostart()
}

pub fn is_background_launch() -> bool {
    env::args().any(|arg| arg == "--background")
}

#[cfg(target_os = "windows")]
fn enable_platform_autostart(exe: PathBuf) -> Result<()> {
    let value = format!("\"{}\" --background", exe.display());
    let status = std::process::Command::new("reg")
        .args([
            "add",
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
            "/v",
            "ShArIngM",
            "/t",
            "REG_SZ",
            "/d",
            &value,
            "/f",
        ])
        .status()
        .context("failed to configure Windows autostart")?;
    if !status.success() {
        anyhow::bail!("Windows autostart command failed with status {status}");
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn disable_platform_autostart() -> Result<()> {
    let _ = std::process::Command::new("reg")
        .args([
            "delete",
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
            "/v",
            "ShArIngM",
            "/f",
        ])
        .status();
    Ok(())
}

#[cfg(target_os = "macos")]
fn enable_platform_autostart(exe: PathBuf) -> Result<()> {
    let path = launch_agent_path()?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let plist = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>{APP_ID}</string>
  <key>ProgramArguments</key>
  <array>
    <string>{}</string>
    <string>--background</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <false/>
</dict>
</plist>
"#,
        escape_xml(&exe.to_string_lossy())
    );
    std::fs::write(path, plist).context("failed to write macOS LaunchAgent")?;
    Ok(())
}

#[cfg(target_os = "macos")]
fn disable_platform_autostart() -> Result<()> {
    let path = launch_agent_path()?;
    if path.exists() {
        std::fs::remove_file(path).context("failed to remove macOS LaunchAgent")?;
    }
    Ok(())
}

#[cfg(all(unix, not(target_os = "macos")))]
fn enable_platform_autostart(exe: PathBuf) -> Result<()> {
    let path = linux_autostart_path()?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let desktop = format!(
        "[Desktop Entry]\nType=Application\nName=ShArIngM\nExec=\"{}\" --background\nX-GNOME-Autostart-enabled=true\nTerminal=false\n",
        exe.to_string_lossy().replace('"', "\\\"")
    );
    std::fs::write(path, desktop).context("failed to write Linux autostart entry")?;
    Ok(())
}

#[cfg(all(unix, not(target_os = "macos")))]
fn disable_platform_autostart() -> Result<()> {
    let path = linux_autostart_path()?;
    if path.exists() {
        std::fs::remove_file(path).context("failed to remove Linux autostart entry")?;
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn launch_agent_path() -> Result<PathBuf> {
    let home = env::var_os("HOME").context("HOME is not set")?;
    Ok(PathBuf::from(home)
        .join("Library")
        .join("LaunchAgents")
        .join(format!("{APP_ID}.plist")))
}

#[cfg(all(unix, not(target_os = "macos")))]
fn linux_autostart_path() -> Result<PathBuf> {
    if let Some(config_home) = env::var_os("XDG_CONFIG_HOME") {
        return Ok(PathBuf::from(config_home)
            .join("autostart")
            .join("ShArIngM.desktop"));
    }
    let home = env::var_os("HOME").context("HOME is not set")?;
    Ok(PathBuf::from(home)
        .join(".config")
        .join("autostart")
        .join("ShArIngM.desktop"))
}

#[cfg(target_os = "macos")]
fn escape_xml(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}
