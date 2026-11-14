// SPDX-License-Identifier: Apache-2.0

//! Settings migration chain (Mullvad §10.2).
//!
//! Unversioned configs minted before `schema_version` existed are treated as
//! version `0` and stepped forward sequentially to [`CURRENT_SCHEMA_VERSION`].
//! Configs from a *newer* schema version are refused explicitly so downgrades
//! never silently misinterpret fields.

use std::fmt;

/// Latest configuration schema version understood by this build.
pub const CURRENT_SCHEMA_VERSION: u32 = 1;

/// Summary of the migrations applied to a configuration string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MigrationReport {
    /// Schema version found in the input (`0` when `schema_version` was absent).
    pub from_version: u32,
    /// Schema version after migration.
    pub to_version: u32,
    /// Human-readable description of each transformation applied.
    pub steps: Vec<&'static str>,
}

/// Error returned when a configuration cannot be migrated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MigrationError {
    /// The input was not valid TOML.
    Parse(String),
    /// `schema_version` was present but not a non-negative integer.
    InvalidVersion(String),
    /// The config declares a schema version newer than [`CURRENT_SCHEMA_VERSION`].
    UnsupportedFutureVersion { found: u32, supported: u32 },
}

impl fmt::Display for MigrationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Parse(msg) => write!(f, "invalid TOML during migration: {msg}"),
            Self::InvalidVersion(msg) => write!(f, "invalid `schema_version`: {msg}"),
            Self::UnsupportedFutureVersion { found, supported } => write!(
                f,
                "config schema_version {found} is newer than supported ({supported}); upgrade vallum"
            ),
        }
    }
}

impl std::error::Error for MigrationError {}

/// Migrate a TOML configuration string from its declared `schema_version`
/// (default `0`) up to [`CURRENT_SCHEMA_VERSION`].
pub fn migrate_toml(text: &str) -> Result<(String, MigrationReport), MigrationError> {
    let mut table: toml::Table =
        toml::from_str(text).map_err(|e| MigrationError::Parse(e.to_string()))?;

    let from_version = match table.get("schema_version") {
        None => 0,
        Some(toml::Value::Integer(n)) if *n >= 0 => u32::try_from(*n)
            .map_err(|_| MigrationError::InvalidVersion(format!("{n} is out of range")))?,
        Some(other) => {
            return Err(MigrationError::InvalidVersion(format!(
                "expected non-negative integer, got {other}"
            )));
        }
    };

    if from_version > CURRENT_SCHEMA_VERSION {
        return Err(MigrationError::UnsupportedFutureVersion {
            found: from_version,
            supported: CURRENT_SCHEMA_VERSION,
        });
    }

    let mut version = from_version;
    let mut steps = Vec::new();

    if version == 0 {
        migrate_v0_to_v1(&mut table, &mut steps);
        version = 1;
    }

    let out = if steps.is_empty() && from_version == CURRENT_SCHEMA_VERSION {
        text.to_owned()
    } else {
        toml::to_string_pretty(&table).map_err(|e| MigrationError::Parse(e.to_string()))?
    };

    Ok((
        out,
        MigrationReport {
            from_version,
            to_version: version,
            steps,
        },
    ))
}

fn migrate_v0_to_v1(table: &mut toml::Table, steps: &mut Vec<&'static str>) {
    // 1. Canonicalize legacy [quick].failure_policy aliases.
    if let Some(toml::Value::Table(quick)) = table.get_mut("quick") {
        if let Some(toml::Value::String(policy)) = quick.get_mut("failure_policy") {
            let normalized = match policy.trim().to_ascii_lowercase().as_str() {
                "block-on-failure" | "closed" | "fail-closed" => Some("block"),
                "open" | "fail-open" => Some("restore"),
                _ => None,
            };
            if let Some(canonical) = normalized {
                *policy = canonical.to_owned();
                steps.push("canonicalized [quick].failure_policy alias");
            }
        }
    }

    // 2. Ensure full-tunnel configs carry an explicit interface.fwmark.
    let full_tunnel = table
        .get("peer")
        .and_then(toml::Value::as_array)
        .is_some_and(|peers| {
            peers.iter().any(|peer| {
                peer.get("allowed_ips")
                    .and_then(toml::Value::as_array)
                    .is_some_and(|cidrs| {
                        cidrs.iter().any(|c| {
                            c.as_str()
                                .is_some_and(|s| matches!(s.trim(), "0.0.0.0/0" | "::/0"))
                        })
                    })
            })
        });

    if full_tunnel {
        if let Some(toml::Value::Table(iface)) = table.get_mut("interface") {
            if !iface.contains_key("fwmark") {
                iface.insert(
                    "fwmark".to_owned(),
                    toml::Value::Integer(i64::from(crate::DEFAULT_FWMARK)),
                );
                steps.push("added default interface.fwmark for full-tunnel config");
            }
        }
    }

    // 3. Stamp schema_version = 1.
    table.insert("schema_version".to_owned(), toml::Value::Integer(1));
    steps.push("stamped schema_version = 1");
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn v0_full_tunnel_migrates_to_v1_with_fwmark_and_canonical_policy() {
        let legacy = r#"
[interface]
private_key = "test.key"

[[peer]]
name = "exit"
public_key = "server.pub"
allowed_ips = ["0.0.0.0/0"]

[quick]
failure_policy = "fail-closed"
"#;
        let (migrated, report) = migrate_toml(legacy).unwrap();
        assert_eq!(report.from_version, 0);
        assert_eq!(report.to_version, 1);
        assert!(report.steps.len() >= 2);
        let parsed: crate::Config = toml::from_str(&migrated).unwrap();
        assert_eq!(parsed.schema_version, Some(1));
        assert_eq!(parsed.interface.fwmark, Some(crate::DEFAULT_FWMARK));
        assert_eq!(parsed.quick.failure_policy.as_deref(), Some("block"));
    }

    #[test]
    fn future_schema_version_is_refused() {
        let future = "schema_version = 99\n[interface]\nprivate_key = \"a.key\"\n";
        let err = migrate_toml(future).unwrap_err();
        assert!(matches!(
            err,
            MigrationError::UnsupportedFutureVersion {
                found: 99,
                supported: 1
            }
        ));
    }

    #[test]
    fn current_v1_config_is_a_no_op() {
        let current = "schema_version = 1\n[interface]\nprivate_key = \"a.key\"\n";
        let (out, report) = migrate_toml(current).unwrap();
        assert_eq!(report.from_version, 1);
        assert_eq!(report.to_version, 1);
        assert!(report.steps.is_empty());
        assert_eq!(out, current);
    }
}
