use crate::{models::TransferRecord, storage};
use anyhow::{bail, Context, Result};
use blake3::Hasher;
use chrono::Utc;
use std::{
    fs::{self, File},
    io::{Read, Write},
    path::{Path, PathBuf},
};
use uuid::Uuid;

pub struct SourceFile {
    pub path: PathBuf,
    pub file_name: String,
    pub size_bytes: u64,
    pub hash: String,
}

pub fn inspect_source(source_path: &str) -> Result<SourceFile> {
    let source = PathBuf::from(source_path);
    if !source.exists() {
        bail!("source file does not exist");
    }
    if !source.is_file() {
        bail!("source path is not a file");
    }

    let file_name = source
        .file_name()
        .and_then(|name| name.to_str())
        .context("source file name is not valid UTF-8")?
        .to_string();
    let size_bytes = source.metadata()?.len();
    let hash = hash_file(&source)?;

    Ok(SourceFile {
        path: source,
        file_name,
        size_bytes,
        hash,
    })
}

pub fn write_incoming_file<R: Read>(
    file_name: &str,
    mut input: R,
    expected_size: u64,
    expected_hash: &str,
) -> Result<TransferRecord> {
    if file_name.trim().is_empty() {
        bail!("incoming file name is empty");
    }

    let clean_name = Path::new(file_name)
        .file_name()
        .and_then(|name| name.to_str())
        .context("incoming file name is not valid UTF-8")?
        .to_string();

    let destination_dir = storage::downloads_dir()?;
    fs::create_dir_all(&destination_dir)?;
    let destination = unique_destination(&destination_dir, &clean_name);
    let mut output = File::create(&destination)?;
    let mut hasher = Hasher::new();
    let mut buffer = [0_u8; 1024 * 128];
    let mut remaining = expected_size;
    let mut written = 0_u64;

    while remaining > 0 {
        let max_read = buffer.len().min(remaining as usize);
        let read = input.read(&mut buffer[..max_read])?;
        if read == 0 {
            let _ = fs::remove_file(&destination);
            bail!("incoming file stream ended early");
        }
        output.write_all(&buffer[..read])?;
        hasher.update(&buffer[..read]);
        written += read as u64;
        remaining -= read as u64;
    }
    output.flush()?;

    let hash = hasher.finalize().to_hex().to_string();
    if hash != expected_hash {
        let _ = fs::remove_file(&destination);
        bail!("incoming file hash verification failed");
    }

    Ok(TransferRecord {
        id: Uuid::new_v4().to_string(),
        file_name: clean_name,
        destination: destination.to_string_lossy().to_string(),
        size_bytes: written,
        hash,
        completed_at_ms: Utc::now().timestamp_millis(),
    })
}

fn hash_file(path: &Path) -> Result<String> {
    let mut input = File::open(path)?;
    let mut hasher = Hasher::new();
    let mut buffer = [0_u8; 1024 * 128];

    loop {
        let read = input.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }

    Ok(hasher.finalize().to_hex().to_string())
}

fn unique_destination(dir: &Path, file_name: &str) -> PathBuf {
    let candidate = dir.join(file_name);
    if !candidate.exists() {
        return candidate;
    }

    let path = Path::new(file_name);
    let stem = path
        .file_stem()
        .and_then(|value| value.to_str())
        .unwrap_or("file");
    let extension = path.extension().and_then(|value| value.to_str());

    for index in 1..10_000 {
        let name = match extension {
            Some(ext) => format!("{stem} ({index}).{ext}"),
            None => format!("{stem} ({index})"),
        };
        let candidate = dir.join(name);
        if !candidate.exists() {
            return candidate;
        }
    }

    dir.join(format!("{stem} ({})", Uuid::new_v4()))
}
