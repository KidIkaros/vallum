// SPDX-License-Identifier: Apache-2.0

//! A self-contained client bundle: config TOML + key-file TOML.

use std::path::{Path, PathBuf};

use std::net::SocketAddr;

pub use crate::bundle::Bundle;

use super::app::{DeviceView, PeerView};

/// Build a client bundle for a generated key and one server-side peer.
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
    let endpoint = endpoint.trim();
    if endpoint.is_empty() {
        return Err("server endpoint is empty".to_owned());
    }
    if endpoint
        .parse::<SocketAddr>()
        .is_ok_and(|address| address.ip().is_unspecified())
        || endpoint.starts_with("0.0.0.0:")
        || endpoint.starts_with("[::]:")
    {
        return Err("server endpoint is unspecified; use a reachable host:port".to_owned());
    }
    let address = peer
        .allowed_ips
        .first()
        .ok_or_else(|| "the peer has no allowed address to use as the client address".to_owned())?;
    let key = std::fs::read_to_string(key_path).map_err(|error| format!("read key: {error}"))?;
    let name = format!("{}-client", device.interface);
    let key_name = key_path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("client.key");
    let config = format!(
        "[interface]\n\
         name = \"{name}\"\n\
         private_key = \"{key_name}\"\n\
         addresses = [\"{address}\"]\n\
         listen = \"0.0.0.0:0\"\n\
         \n\
         [log]\n\
         level = \"info\"\n\
         \n\
         [[peer]]\n\
         name = \"server\"\n\
         public_key = \"{}\"\n\
         endpoint = \"{}\"\n\
         allowed_ips = [\"0.0.0.0/0\", \"::/0\"]\n\
         persistent_keepalive = 25\n",
        device.public_line, endpoint
    );
    let bundle = Bundle {
        version: 1,
        name,
        config,
        key,
    };
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
