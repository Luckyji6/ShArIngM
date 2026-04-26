use crate::{models::DeviceIdentity, storage::StoredConfig};
use anyhow::{bail, Result};
use base64::{engine::general_purpose, Engine};
use blake3::Hasher;
use ed25519_dalek::SigningKey;

#[derive(Clone)]
pub struct Identity {
    signing_key: SigningKey,
    device_id: String,
    device_name: String,
}

impl Identity {
    pub fn from_config(config: &StoredConfig) -> Result<Self> {
        let seed = general_purpose::STANDARD.decode(&config.identity_seed)?;
        if seed.len() != 32 {
            bail!("identity seed must be 32 bytes");
        }
        let mut bytes = [0_u8; 32];
        bytes.copy_from_slice(&seed);
        Ok(Self {
            signing_key: SigningKey::from_bytes(&bytes),
            device_id: config.device_id.clone(),
            device_name: config.device_name.clone(),
        })
    }

    pub fn public_key_base64(&self) -> String {
        general_purpose::STANDARD.encode(self.signing_key.verifying_key().as_bytes())
    }

    pub fn fingerprint(&self) -> String {
        fingerprint_for_key(&self.public_key_base64())
    }

    pub fn public_identity(&self) -> DeviceIdentity {
        DeviceIdentity {
            device_id: self.device_id.clone(),
            device_name: self.device_name.clone(),
            public_key: self.public_key_base64(),
            fingerprint: self.fingerprint(),
        }
    }
}

pub fn fingerprint_for_key(public_key: &str) -> String {
    let mut hasher = Hasher::new();
    hasher.update(public_key.as_bytes());
    let hash = hasher.finalize();
    hash.as_bytes()[..8]
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect::<Vec<_>>()
        .join(":")
}
