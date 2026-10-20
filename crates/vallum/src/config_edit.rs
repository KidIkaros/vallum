// SPDX-License-Identifier: Apache-2.0

//! Editing an operator's TOML without destroying it.
//!
//! `vallum peer` writes to a file a person also edits, so the file is parsed
//! with `toml_edit` — comments, ordering and formatting survive an edit that
//! only touches one peer. Writes are atomic and keep a timestamped backup, and
//! the file is left `0600` because a peer entry may name a PSK file.

use std::net::IpAddr;
use std::path::{Path, PathBuf};

use ipnet::IpNet;
use toml_edit::{Array, ArrayOfTables, DocumentMut, Item, Table, Value};

use crate::Error;

/// The most addresses a scan will walk before asking the operator to be
/// specific. A `/8` has 16 million; nobody wants a command that walks them.
const MAX_SCAN: usize = 65_536;

/// One `[[peer]]` entry, as the file expresses it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerRecord {
    /// The operator's name for the peer.
    pub name: String,
    /// The `vallum1:` public line.
    pub public_key: String,
    /// The prefixes routed to this peer.
    pub allowed_ips: Vec<String>,
    /// The address dialled, if any.
    pub endpoint: Option<String>,
    /// Keepalive cadence.
    pub keepalive: Option<u16>,
    /// A PSK file to write for a new peer, relative to the config.
    pub preshared_key_file: Option<String>,
    /// Whether a preshared key is configured (read from an existing entry).
    pub has_psk: bool,
}

/// A configuration file that can be edited and written back.
#[derive(Debug)]
pub struct ConfigFile {
    path: PathBuf,
    doc: DocumentMut,
}

impl ConfigFile {
    /// Parse a config file.
    ///
    /// # Errors
    ///
    /// If the file cannot be read or does not parse.
    pub fn load(path: &Path) -> Result<Self, Error> {
        let text = std::fs::read_to_string(path).map_err(|source| Error::IoPath {
            action: "read config",
            path: path.to_path_buf(),
            source,
        })?;
        let doc: DocumentMut = text.parse().map_err(|source: toml_edit::TomlError| {
            Error::Usage(format!("{}: {source}", path.display()))
        })?;
        Ok(Self {
            path: path.to_path_buf(),
            doc,
        })
    }

    /// The file this came from.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The directory relative paths resolve against.
    #[must_use]
    pub fn directory(&self) -> PathBuf {
        self.path
            .parent()
            .map_or_else(|| PathBuf::from("."), Path::to_path_buf)
    }

    /// The interface's own addresses.
    #[must_use]
    pub fn interface_addresses(&self) -> Vec<IpNet> {
        let Some(interface) = self.doc.get("interface").and_then(Item::as_table) else {
            return Vec::new();
        };
        let mut addresses = Vec::new();
        if let Some(address) = string(interface, "address").and_then(|text| text.parse().ok()) {
            addresses.push(address);
        }
        if let Some(list) = interface.get("addresses").and_then(Item::as_array) {
            for value in list.iter().filter_map(Value::as_str) {
                if let Ok(address) = value.parse::<IpNet>() {
                    addresses.push(address);
                }
            }
        }
        addresses
    }

    /// The interface's own host addresses, which a peer may not take.
    #[must_use]
    pub fn own_addresses(&self) -> Vec<IpAddr> {
        self.interface_addresses()
            .into_iter()
            .map(|network| network.addr())
            .collect()
    }

    /// The peer entries, in file order.
    #[must_use]
    pub fn peers(&self) -> Vec<PeerRecord> {
        let Some(entries) = self.doc.get("peer").and_then(Item::as_array_of_tables) else {
            return Vec::new();
        };
        entries.iter().map(record).collect()
    }

    /// Whether a peer with this name exists.
    #[must_use]
    pub fn has_peer(&self, name: &str) -> bool {
        self.peers().iter().any(|peer| peer.name == name)
    }

    /// Append a peer.
    ///
    /// # Errors
    ///
    /// If a peer with the same name already exists.
    pub fn add_peer(&mut self, peer: &PeerRecord) -> Result<(), Error> {
        if self.has_peer(&peer.name) {
            return Err(Error::Usage(format!(
                "a peer named `{}` already exists; remove it first, or choose another name",
                peer.name
            )));
        }
        if !self.doc.contains_key("peer") {
            self.doc["peer"] = Item::ArrayOfTables(ArrayOfTables::new());
        }
        let entries = self
            .doc
            .get_mut("peer")
            .and_then(Item::as_array_of_tables_mut)
            .ok_or_else(|| {
                Error::Usage("`peer` in the config is not a list of tables".to_owned())
            })?;
        entries.push(table_for(peer));
        Ok(())
    }

    /// Remove a peer by name.
    ///
    /// # Errors
    ///
    /// If no peer has that name.
    pub fn remove_peer(&mut self, name: &str) -> Result<PeerRecord, Error> {
        let existing = self
            .peers()
            .into_iter()
            .find(|peer| peer.name == name)
            .ok_or_else(|| Error::Usage(format!("no peer named `{name}`")))?;
        let entries = self
            .doc
            .get_mut("peer")
            .and_then(Item::as_array_of_tables_mut)
            .ok_or_else(|| {
                Error::Usage("`peer` in the config is not a list of tables".to_owned())
            })?;
        let mut kept = ArrayOfTables::new();
        for entry in entries.iter() {
            let same = entry
                .get("name")
                .and_then(Item::as_str)
                .is_some_and(|value| value == name);
            if !same {
                kept.push(entry.clone());
            }
        }
        *entries = kept;
        Ok(existing)
    }

    /// Check that the edited document still describes a config the daemon can
    /// load, before it is written.
    ///
    /// # Errors
    ///
    /// If the document does not parse as a Vallum config.
    pub fn validate(&self) -> Result<(), Error> {
        toml::from_str::<vallum_config::Config>(&self.doc.to_string())
            .map(|_| ())
            .map_err(|error| Error::Usage(format!("the edited config does not parse: {error}")))
    }

    /// Write the file back, atomically, with a timestamped backup.
    ///
    /// # Errors
    ///
    /// If the backup or the write fails.
    pub fn save(&self) -> Result<PathBuf, Error> {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;

        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |duration| duration.as_secs());
        let backup = PathBuf::from(format!("{}.bak.{stamp}", self.path.display()));
        std::fs::copy(&self.path, &backup).map_err(|source| Error::IoPath {
            action: "back up",
            path: self.path.clone(),
            source,
        })?;

        let temporary = PathBuf::from(format!("{}.new", self.path.display()));
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create(true).truncate(true).mode(0o600);
        let mut file = options.open(&temporary).map_err(|source| Error::IoPath {
            action: "write",
            path: temporary.clone(),
            source,
        })?;
        file.write_all(self.doc.to_string().as_bytes())
            .map_err(|source| Error::IoPath {
                action: "write",
                path: temporary.clone(),
                source,
            })?;
        drop(file);
        std::fs::rename(&temporary, &self.path).map_err(|source| Error::IoPath {
            action: "rename",
            path: self.path.clone(),
            source,
        })?;
        Ok(backup)
    }
}

fn string(table: &Table, key: &str) -> Option<String> {
    table.get(key)?.as_str().map(str::to_owned)
}

fn record(table: &Table) -> PeerRecord {
    PeerRecord {
        name: string(table, "name").unwrap_or_default(),
        public_key: string(table, "public_key").unwrap_or_default(),
        allowed_ips: table
            .get("allowed_ips")
            .and_then(Item::as_array)
            .map(|array| {
                array
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default(),
        endpoint: string(table, "endpoint"),
        keepalive: table
            .get("persistent_keepalive")
            .and_then(Item::as_integer)
            .and_then(|value| u16::try_from(value).ok()),
        preshared_key_file: string(table, "preshared_key_file"),
        has_psk: table.contains_key("preshared_key") || table.contains_key("preshared_key_file"),
    }
}

fn table_for(peer: &PeerRecord) -> Table {
    let mut table = Table::new();
    table.insert("name", Item::Value(Value::from(peer.name.as_str())));
    table.insert(
        "public_key",
        Item::Value(Value::from(peer.public_key.as_str())),
    );
    let mut allowed = Array::new();
    for prefix in &peer.allowed_ips {
        allowed.push(prefix.as_str());
    }
    table.insert("allowed_ips", Item::Value(Value::Array(allowed)));
    if let Some(endpoint) = &peer.endpoint {
        table.insert("endpoint", Item::Value(Value::from(endpoint.as_str())));
    }
    if let Some(keepalive) = peer.keepalive {
        table.insert(
            "persistent_keepalive",
            Item::Value(Value::from(i64::from(keepalive))),
        );
    }
    if let Some(file) = &peer.preshared_key_file {
        table.insert(
            "preshared_key_file",
            Item::Value(Value::from(file.as_str())),
        );
    }
    table
}

/// The next free host address in the tunnel's own networks.
///
/// Skips the interface's own addresses, anything already routed to a peer, and
/// (through `IpNet::hosts`) the network and broadcast addresses.
#[must_use]
pub fn next_host_address(networks: &[IpNet], taken: &[IpNet], own: &[IpAddr]) -> Option<IpNet> {
    for network in networks {
        // `IpNet::hosts()` excludes the network and broadcast addresses for
        // IPv4 but not the subnet-router address for IPv6, so it is skipped
        // explicitly — unless the prefix has only that one address.
        let max = match network {
            IpNet::V4(_) => 32,
            IpNet::V6(_) => 128,
        };
        let skip_network = network.prefix_len() < max;
        let mut candidates = network.hosts();
        for _ in 0..MAX_SCAN {
            let Some(address) = candidates.next() else {
                break;
            };
            if skip_network && address == network.network() {
                continue;
            }
            if own.contains(&address) {
                continue;
            }
            if taken.iter().any(|prefix| prefix.contains(&address)) {
                continue;
            }
            let prefix = match address {
                IpAddr::V4(_) => 32,
                IpAddr::V6(_) => 128,
            };
            return IpNet::new(address, prefix).ok();
        }
    }
    None
}

/// Parse `--allowed-ips`: comma- or space-separated prefixes.
///
/// # Errors
///
/// If an entry is not a prefix.
pub fn parse_prefixes(text: &str) -> Result<Vec<String>, Error> {
    let mut prefixes = Vec::new();
    for entry in text
        .split([',', ' '])
        .filter(|entry| !entry.trim().is_empty())
    {
        let entry = entry.trim();
        entry.parse::<IpNet>().map_err(|error| {
            Error::Usage(format!(
                "`{entry}` is not a prefix (e.g. 10.7.0.2/32): {error}"
            ))
        })?;
        prefixes.push(entry.to_owned());
    }
    Ok(prefixes)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    const CONFIG: &str = "\
# the operator's own notes
[interface]
name = \"vallum0\"
private_key = \"server.key\"
address = \"10.7.0.1/24\"
listen = \"0.0.0.0:51820\"

[log]
level = \"info\"

[[peer]]
name = \"phone\"
public_key = \"vallum1:0003:aa:-\"
allowed_ips = [\"10.7.0.2/32\"]
";

    fn file(name: &str) -> (PathBuf, ConfigFile) {
        let dir = std::env::temp_dir().join(format!("vallum-edit-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("vallum0.toml");
        std::fs::write(&path, CONFIG).unwrap();
        let config = ConfigFile::load(&path).unwrap();
        (path, config)
    }

    fn peer(name: &str, address: &str) -> PeerRecord {
        PeerRecord {
            name: name.to_owned(),
            public_key: "vallum1:0003:bb:-".to_owned(),
            allowed_ips: vec![address.to_owned()],
            endpoint: None,
            keepalive: None,
            preshared_key_file: None,
            has_psk: false,
        }
    }

    #[test]
    fn adding_a_peer_keeps_the_operator_comments_and_order() {
        let (path, mut config) = file("add");
        config.add_peer(&peer("laptop", "10.7.0.3/32")).unwrap();
        config.save().unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains("# the operator's own notes"));
        assert!(text.find("phone").unwrap() < text.find("laptop").unwrap());
        let reloaded = ConfigFile::load(&path).unwrap();
        assert_eq!(reloaded.peers().len(), 2);
    }

    #[test]
    fn a_duplicate_name_is_refused() {
        let (_path, mut config) = file("dup");
        assert!(config.add_peer(&peer("phone", "10.7.0.4/32")).is_err());
    }

    #[test]
    fn removing_a_peer_keeps_the_others() {
        let (path, mut config) = file("remove");
        config.add_peer(&peer("laptop", "10.7.0.3/32")).unwrap();
        config.save().unwrap();
        let mut config = ConfigFile::load(&path).unwrap();
        config.remove_peer("phone").unwrap();
        config.save().unwrap();
        let reloaded = ConfigFile::load(&path).unwrap();
        let names: Vec<String> = reloaded.peers().into_iter().map(|peer| peer.name).collect();
        assert_eq!(names, vec!["laptop".to_owned()]);
    }

    #[test]
    fn the_first_free_address_skips_the_server_and_existing_peers() {
        let networks: Vec<IpNet> = vec!["10.7.0.1/24".parse().unwrap()];
        let own = vec!["10.7.0.1".parse().unwrap()];
        let taken: Vec<IpNet> = vec!["10.7.0.2/32".parse().unwrap()];
        let next = next_host_address(&networks, &taken, &own).unwrap();
        assert_eq!(next.to_string(), "10.7.0.3/32");
    }

    #[test]
    fn a_full_subnet_reports_nothing_rather_than_wrapping() {
        let networks: Vec<IpNet> = vec!["10.7.0.0/30".parse().unwrap()];
        let own = vec!["10.7.0.1".parse().unwrap()];
        let taken: Vec<IpNet> = vec![
            "10.7.0.2/32".parse().unwrap(),
            "10.7.0.3/32".parse().unwrap(),
        ];
        assert!(next_host_address(&networks, &taken, &own).is_none());
    }

    #[test]
    fn a_v6_tunnel_allocates_v6_addresses() {
        let networks: Vec<IpNet> = vec!["fd00:7::1/64".parse().unwrap()];
        let own = vec!["fd00:7::1".parse().unwrap()];
        let next = next_host_address(&networks, &[], &own).unwrap();
        assert_eq!(next.to_string(), "fd00:7::2/128");
    }

    #[test]
    fn allowed_ips_accept_commas_and_spaces() {
        assert_eq!(
            parse_prefixes("10.7.0.2/32, fd00:7::2/128").unwrap().len(),
            2
        );
        assert!(parse_prefixes("not-a-prefix").is_err());
    }
}
