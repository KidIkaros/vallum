// SPDX-License-Identifier: Apache-2.0

//! The versioned client bundle: config TOML plus key-file TOML.

use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Bundle {
    pub version: u32,
    pub name: String,
    pub config: String,
    pub key: String,
}

#[derive(Debug, Clone)]
pub struct Imported {
    pub config: PathBuf,
    pub key: PathBuf,
}

/// Read and validate a bundle.
///
/// # Errors
///
/// If the file cannot be read, is not JSON, or has an unsupported version.
pub fn read(path: &Path) -> Result<Bundle, String> {
    let bytes = std::fs::read(path).map_err(|error| format!("read bundle: {error}"))?;
    let bundle: Bundle =
        serde_json::from_slice(&bytes).map_err(|error| format!("parse bundle: {error}"))?;
    if bundle.version != 1 {
        return Err(format!("unsupported bundle version {}", bundle.version));
    }
    if bundle.config.trim().is_empty() || bundle.key.trim().is_empty() {
        return Err("bundle has an empty config or key".to_owned());
    }
    Ok(bundle)
}

/// Import a bundle into `directory`: write the config and a 0600 key file.
///
/// # Errors
///
/// If the config does not parse, references a path outside the bundle, the
/// target exists and `force` is false, or a write fails.
pub fn import(bundle: &Bundle, directory: &Path, force: bool) -> Result<Imported, String> {
    if bundle.version != 1 {
        return Err(format!("unsupported bundle version {}", bundle.version));
    }
    let config: vallum_config::Config =
        toml::from_str(&bundle.config).map_err(|error| format!("bundle config: {error}"))?;
    let declared = &config.interface.private_key;
    if declared
        .parent()
        .is_some_and(|parent| !parent.as_os_str().is_empty())
    {
        return Err(format!(
            "bundle key path `{}` must be a file name, not a path",
            declared.display()
        ));
    }
    let key_name = declared
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| "bundle config has no key file name".to_owned())?;
    let stem = sanitize(&bundle.name);
    let config_path = directory.join(format!("{stem}.toml"));
    let key_path = directory.join(key_name);
    if !force && (config_path.exists() || key_path.exists()) {
        return Err(format!(
            "refusing to overwrite {} or {}; pass --force",
            config_path.display(),
            key_path.display()
        ));
    }
    std::fs::create_dir_all(directory)
        .map_err(|error| format!("create {}: {error}", directory.display()))?;
    write_private(&key_path, bundle.key.as_bytes())?;
    // The mark is the client's own routing detail: a bundle minted by a
    // server that predates `fwmark` still has to run here.
    let config_text = vallum_config::with_local_fwmark(&bundle.config);
    write_private(&config_path, config_text.as_bytes())?;
    vallum_config::Config::load(&config_path)
        .map_err(|error| format!("written config: {error}"))?;
    Ok(Imported {
        config: config_path,
        key: key_path,
    })
}

fn sanitize(name: &str) -> String {
    let cleaned: String = name
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || character == '-' || character == '_' {
                character
            } else {
                '-'
            }
        })
        .collect();
    let cleaned = cleaned.trim_matches('-');
    if cleaned.is_empty() {
        "vallum-client".to_owned()
    } else {
        cleaned.to_owned()
    }
}

fn write_private(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .map_err(|error| format!("write {}: {error}", path.display()))?;
    file.write_all(bytes)
        .map_err(|error| format!("write {}: {error}", path.display()))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn bundle(name: &str) -> Bundle {
        Bundle {
            version: 1,
            name: name.to_owned(),
            config: "[interface]\nname = \"vallum0\"\nprivate_key = \"client.key\"\naddress = \"10.7.0.2/24\"\n\n[[peer]]\nname = \"server\"\npublic_key = \"vallum1:0003:00:-\"\nallowed_ips = [\"0.0.0.0/0\"]\n".to_owned(),
            key: "[key]\nversion = 1\nsuite = 3\nseed = \"00\"\n".to_owned(),
        }
    }

    #[test]
    fn an_import_writes_a_config_and_a_0600_key() {
        let dir = std::env::temp_dir().join(format!("vallum-bundle-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let imported = import(&bundle("laptop"), &dir, false).expect("import");
        assert!(imported.config.exists());
        let mode = std::fs::metadata(&imported.key)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_import_refuses_to_overwrite() {
        let dir =
            std::env::temp_dir().join(format!("vallum-bundle-overwrite-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        import(&bundle("laptop"), &dir, false).expect("first");
        assert!(import(&bundle("laptop"), &dir, false).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_traversal_key_path_is_rejected() {
        let mut value = bundle("laptop");
        value.config = value.config.replace("client.key", "../client.key");
        let dir =
            std::env::temp_dir().join(format!("vallum-bundle-traversal-{}", std::process::id()));
        assert!(import(&value, &dir, false).is_err());
    }
}
