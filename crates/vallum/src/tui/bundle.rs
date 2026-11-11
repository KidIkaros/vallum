// SPDX-License-Identifier: Apache-2.0

//! A self-contained client bundle: config TOML + key-file TOML.

use std::path::{Path, PathBuf};

pub use crate::bundle::Bundle;

use super::app::{DeviceView, PeerView};

/// Build a client bundle for a generated key and one server-side peer.
///
/// The template lives in [`crate::bundle::build`] so both consoles mint the
/// same bundle; this wrapper only reads the key file and writes the result.
///
/// # Errors
///
/// If the peer has no allowed address, the key cannot be read, or the bundle
/// cannot be written.
pub fn build(
    device: &DeviceView,
    peer: &PeerView,
    key_path: &Path,
    endpoint: &str,
) -> Result<(Bundle, PathBuf), String> {
    let address = peer.allowed_ips.first().map(String::as_str).unwrap_or("");
    let key = std::fs::read_to_string(key_path).map_err(|error| format!("read key: {error}"))?;
    let key_name = key_path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("client.key");
    let bundle = crate::bundle::build(
        &device.public_line,
        &device.interface,
        address,
        &key,
        key_name,
        endpoint,
    )?;
    let path = key_path.with_extension("vallum-bundle");
    write_private(
        &path,
        serde_json::to_string_pretty(&bundle)
            .map_err(|e| e.to_string())?
            .as_bytes(),
    )?;
    Ok((bundle, path))
}

fn write_private(path: &Path, bytes: &[u8]) -> Result<(), String> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .map_err(|error| format!("write bundle: {error}"))?;
    file.write_all(bytes)
        .map_err(|error| format!("write bundle: {error}"))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn tui_built_bundle_carries_fwmark_and_parses_as_valid_config() {
        let dir = std::env::temp_dir().join(format!("vallum-tui-bundle-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let key_path = dir.join("laptop.key");
        std::fs::write(&key_path, "suite = 3\n").unwrap();

        let response = crate::uapi::parse_response(
            "vallum_interface=vallum0\nvallum_suite=0x0003\nvallum_public_line=vallum1:0003:aa:-\nerrno=0\n\npublic_key=bb\nvallum_name=laptop\nallowed_ip=10.7.0.2/32\nerrno=0\n",
        );
        let device = DeviceView::from_response(&response);
        let (bundle, bundle_path) =
            build(&device, &device.peers[0], &key_path, "203.0.113.5:51820").unwrap();
        assert!(bundle_path.exists());
        assert!(
            bundle.config.contains("fwmark = 51820"),
            "full-tunnel TUI bundle must carry a fwmark: {}",
            bundle.config
        );
        let config_path = dir.join("laptop.toml");
        std::fs::write(&config_path, &bundle.config).unwrap();
        let parsed = vallum_config::Config::load(&config_path).unwrap();
        assert_eq!(parsed.interface.fwmark, Some(51820));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
