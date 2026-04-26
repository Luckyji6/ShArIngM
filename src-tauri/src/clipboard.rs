use anyhow::{bail, Context, Result};
use std::{
    io::Write,
    process::{Command, Stdio},
};

pub fn write_text(text: &str) -> Result<()> {
    if text.is_empty() {
        bail!("clipboard text is empty");
    }

    #[cfg(target_os = "macos")]
    {
        return write_with_stdin("pbcopy", &[], text);
    }

    #[cfg(target_os = "windows")]
    {
        return write_with_stdin(
            "powershell",
            &["-NoProfile", "-Command", "Set-Clipboard"],
            text,
        );
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    {
        if write_with_stdin("wl-copy", &[], text).is_ok() {
            return Ok(());
        }
        if write_with_stdin("xclip", &["-selection", "clipboard"], text).is_ok() {
            return Ok(());
        }
        if write_with_stdin("xsel", &["--clipboard", "--input"], text).is_ok() {
            return Ok(());
        }
        bail!("no clipboard command found; install wl-copy, xclip, or xsel");
    }

    #[allow(unreachable_code)]
    Ok(())
}

fn write_with_stdin(program: &str, args: &[&str], text: &str) -> Result<()> {
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::piped())
        .spawn()
        .with_context(|| format!("failed to start {program}"))?;

    {
        let stdin = child
            .stdin
            .as_mut()
            .context("failed to open clipboard command stdin")?;
        stdin.write_all(text.as_bytes())?;
    }

    let status = child.wait()?;
    if !status.success() {
        bail!("{program} exited with status {status}");
    }
    Ok(())
}
