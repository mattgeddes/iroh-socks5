//! Loading and generating persistent iroh secret keys.

use std::path::Path;
use std::str::FromStr;

use anyhow::{Context, Result};
use iroh::SecretKey;

/// Loads the secret key stored at `path`, or generates and persists a new one.
///
/// Key files are written as the raw 32 secret key bytes (with restrictive
/// permissions). A text form (base32, as parsed by [`SecretKey::from_str`]) is
/// also accepted when reading.
pub async fn load_or_create(path: &Path) -> Result<SecretKey> {
    match tokio::fs::read(path).await {
        Ok(bytes) => parse_key(&bytes, path),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let key = SecretKey::generate();
            let bytes = key.to_bytes();
            tokio::fs::write(path, bytes)
                .await
                .with_context(|| format!("write key file {}", path.display()))?;
            restrict_permissions(path).await;
            tracing::info!(path = %path.display(), endpoint_id = %key.public(), "generated new secret key");
            Ok(key)
        }
        Err(e) => Err(e).with_context(|| format!("read key file {}", path.display())),
    }
}

fn parse_key(bytes: &[u8], path: &Path) -> Result<SecretKey> {
    if bytes.len() == 32 {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(bytes);
        return Ok(SecretKey::from_bytes(&arr));
    }
    let text = std::str::from_utf8(bytes).context("key file is neither raw 32 bytes nor text")?;
    let key = SecretKey::from_str(text.trim())
        .with_context(|| format!("invalid secret key in {}", path.display()))?;
    Ok(key)
}

#[cfg(unix)]
async fn restrict_permissions(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    if let Ok(metadata) = tokio::fs::metadata(path).await {
        let mut permissions = metadata.permissions();
        permissions.set_mode(0o600);
        let _ = tokio::fs::set_permissions(path, permissions).await;
    }
}

#[cfg(not(unix))]
async fn restrict_permissions(_path: &Path) {}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use iroh::EndpointId;

    use super::*;

    #[tokio::test]
    async fn generate_then_load() {
        let dir = std::env::temp_dir().join(format!("iroh-socks5-key-{}", std::process::id()));
        let _ = tokio::fs::remove_dir_all(&dir).await;
        tokio::fs::create_dir_all(&dir).await.unwrap();
        let path = dir.join("key.bin");

        let key = load_or_create(&path).await.unwrap();
        let loaded = load_or_create(&path).await.unwrap();
        assert_eq!(key.to_bytes(), loaded.to_bytes());

        let endpoint_id: EndpointId = key.public();
        let display = endpoint_id.to_string();
        assert_eq!(display.parse::<EndpointId>().unwrap(), endpoint_id);

        let _ = (Ipv4Addr::LOCALHOST, display);
        let _ = tokio::fs::remove_dir_all(&dir).await;
    }
}
