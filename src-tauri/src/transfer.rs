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

pub fn copy_to_downloads(source_path: &str) -> Result<TransferRecord> {
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

    let destination_dir = storage::downloads_dir()?;
    fs::create_dir_all(&destination_dir)?;
    let destination = unique_destination(&destination_dir, &file_name);
    let (size_bytes, hash) = copy_and_hash(&source, &destination)?;

    Ok(TransferRecord {
        id: Uuid::new_v4().to_string(),
        file_name,
        destination: destination.to_string_lossy().to_string(),
        size_bytes,
        hash,
        completed_at_ms: Utc::now().timestamp_millis(),
    })
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

fn copy_and_hash(source: &Path, destination: &Path) -> Result<(u64, String)> {
    let mut input = File::open(source)?;
    let mut output = File::create(destination)?;
    let mut hasher = Hasher::new();
    let mut buffer = [0_u8; 1024 * 128];
    let mut size = 0_u64;

    loop {
        let read = input.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        output.write_all(&buffer[..read])?;
        hasher.update(&buffer[..read]);
        size += read as u64;
    }

    let source_hash = hasher.finalize().to_hex().to_string();
    let destination_hash = blake3::hash(&fs::read(destination)?).to_hex().to_string();
    if source_hash != destination_hash {
        let _ = fs::remove_file(destination);
        bail!("hash verification failed after copy");
    }

    Ok((size, source_hash))
}
