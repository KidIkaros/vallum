// SPDX-License-Identifier: Apache-2.0

//! Unprivileged host probes every console shares: systemd unit state, the
//! operator's own ssh config, and the shape of `vallum-ops` output.
//!
//! Every probe answers `Option`/`None` where "cannot see" is a different
//! answer from "down". A console that cannot tell must not claim a state —
//! the guidance rules above these probes suppress themselves on `None`.

use std::process::Command;

/// systemd's `ActiveState`, in the spellings a tunnel unit takes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceState {
    Active,
    Inactive,
    Failed,
    Activating,
    Deactivating,
}

impl ServiceState {
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim() {
            "active" => Some(Self::Active),
            "inactive" => Some(Self::Inactive),
            "failed" => Some(Self::Failed),
            "activating" => Some(Self::Activating),
            "deactivating" => Some(Self::Deactivating),
            _ => None,
        }
    }

    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Inactive => "inactive",
            Self::Failed => "failed",
            Self::Activating => "starting",
            Self::Deactivating => "stopping",
        }
    }
}

/// `systemctl is-active` on `{prefix}{stem}.service` — `vallum@vallum0`,
/// `vallum-guard@vallum0`, `vallum-enroll@vallum0` are all this shape.
#[must_use]
pub fn unit_state(stem: &str, prefix: &str) -> Option<ServiceState> {
    let unit = format!("{prefix}{stem}.service");
    let output = Command::new("systemctl")
        .args(["--no-ask-password", "is-active", &unit])
        .output()
        .ok()?;
    ServiceState::parse(&String::from_utf8_lossy(&output.stdout))
}

/// `systemctl list-units` on a glob — true when at least one unit matching
/// `pattern` is active. Used for the families an interface stem cannot name:
/// `vallum-enroll@*` and `vallum-guard@*` span interfaces.
#[must_use]
pub fn any_unit_active(pattern: &str) -> Option<bool> {
    let output = Command::new("systemctl")
        .args([
            "--no-ask-password",
            "list-units",
            pattern,
            "--state=active",
            "--no-legend",
        ])
        .output()
        .ok()?;
    Some(!String::from_utf8_lossy(&output.stdout).trim().is_empty())
}

/// Whether `vallum@{stem}.service` starts at boot. `masked`, `static` and
/// `indirect` all mean the unit does not enable the tunnel itself.
#[must_use]
pub fn unit_enabled(stem: &str) -> Option<bool> {
    let output = Command::new("systemctl")
        .args([
            "--no-ask-password",
            "is-enabled",
            &format!("vallum@{stem}.service"),
        ])
        .output()
        .ok()?;
    match String::from_utf8_lossy(&output.stdout).trim() {
        "enabled" => Some(true),
        "disabled" | "masked" | "static" | "indirect" => Some(false),
        _ => None,
    }
}

/// systemd's restart counter for `vallum@{stem}.service`.
#[must_use]
pub fn unit_restarts(stem: &str) -> Option<u64> {
    let output = Command::new("systemctl")
        .args([
            "--no-ask-password",
            "show",
            "-p",
            "NRestarts",
            "--value",
            &format!("vallum@{stem}.service"),
        ])
        .output()
        .ok()?;
    String::from_utf8_lossy(&output.stdout).trim().parse().ok()
}

/// One usable ssh target from the operator's `~/.ssh/config`: an alias plus
/// what the block resolves it to. Wildcards and negations are not targets.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct SshHost {
    pub alias: String,
    pub hostname: String,
    pub user: Option<String>,
}

/// Non-wildcard SSH targets the operator's config already knows. Consoles use
/// the list to offer one-click SSH targets and to match a client's tunnel
/// peer endpoint to its SSH alias — never to start a connection unasked.
#[must_use]
pub fn ssh_hosts() -> Vec<SshHost> {
    let Some(home) = std::env::var_os("HOME") else {
        return Vec::new();
    };
    let path = std::path::Path::new(&home).join(".ssh/config");
    let Ok(text) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    parse_ssh_config(&text)
}

/// How many non-wildcard SSH targets the operator's config knows — the fact
/// guidance uses for hint quality.
#[must_use]
pub fn ssh_host_count() -> usize {
    ssh_hosts().len()
}

/// Parse `~/.ssh/config` into targets. One `Host a b` line is two targets —
/// OpenSSH gives every name in a Host pattern the block, so a picker that
/// keeps only the first alias silently loses the rest.
#[must_use]
fn parse_ssh_config(text: &str) -> Vec<SshHost> {
    let mut out = Vec::new();
    let mut aliases: Vec<String> = Vec::new();
    let mut hostname: Option<String> = None;
    let mut user: Option<String> = None;
    let flush = |out: &mut Vec<SshHost>,
                 aliases: &mut Vec<String>,
                 hostname: &mut Option<String>,
                 user: &mut Option<String>| {
        if aliases.is_empty() {
            *hostname = None;
            *user = None;
            return;
        }
        for alias in aliases.drain(..) {
            out.push(SshHost {
                hostname: hostname.clone().unwrap_or_else(|| alias.clone()),
                alias,
                user: user.clone(),
            });
        }
        *hostname = None;
        *user = None;
    };
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, rest)) = line.split_once(|c: char| c.is_ascii_whitespace() || c == '=')
        else {
            continue;
        };
        let value = rest
            .trim_start_matches(|c: char| c.is_ascii_whitespace() || c == '=')
            .trim();
        if key.eq_ignore_ascii_case("host") {
            flush(&mut out, &mut aliases, &mut hostname, &mut user);
            aliases = value
                .split_whitespace()
                .filter(|name| !name.contains('*') && !name.contains('?') && !name.starts_with('!'))
                .map(str::to_owned)
                .collect();
        } else if !aliases.is_empty() {
            if key.eq_ignore_ascii_case("hostname") && !value.is_empty() {
                hostname = Some(value.to_owned());
            } else if key.eq_ignore_ascii_case("user") && !value.is_empty() {
                user = Some(value.to_owned());
            }
        }
    }
    flush(&mut out, &mut aliases, &mut hostname, &mut user);
    out
}

/// The verdict line of a `vallum-ops sync*` run. stderr is merged into the
/// captured output, so a naive last-line read can land on the
/// untrusted-source warning's tail — the script's own lines all carry the
/// `sync` prefix.
#[must_use]
pub fn sync_verdict(text: &str) -> &str {
    text.lines()
        .map(str::trim)
        .rfind(|line| line.starts_with("sync"))
        .unwrap_or("sync complete")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_state_parses_systemd_spellings() {
        assert_eq!(ServiceState::parse("active\n"), Some(ServiceState::Active));
        assert_eq!(ServiceState::parse("failed"), Some(ServiceState::Failed));
        assert_eq!(
            ServiceState::parse("activating"),
            Some(ServiceState::Activating)
        );
        assert_eq!(
            ServiceState::parse("deactivating"),
            Some(ServiceState::Deactivating)
        );
        assert_eq!(ServiceState::parse("whatever"), None);
    }

    #[test]
    fn parse_reads_alias_hostname_and_user() {
        let hosts =
            parse_ssh_config("Host vps\n  HostName 1.2.3.4\n  User ops\n\nHost *\n  User me\n");
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0].alias, "vps");
        assert_eq!(hosts[0].hostname, "1.2.3.4");
        assert_eq!(hosts[0].user.as_deref(), Some("ops"));
    }

    #[test]
    fn a_multi_name_host_block_yields_every_alias() {
        let hosts = parse_ssh_config("Host vps wingman-vps\n  HostName 1.2.3.4\n");
        assert_eq!(hosts.len(), 2);
        assert_eq!(hosts[1].alias, "wingman-vps");
    }

    #[test]
    fn wildcards_and_negations_are_not_targets() {
        let hosts = parse_ssh_config("Host *\nHost !bastion *.corp\nHost real\n");
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0].alias, "real");
    }

    #[test]
    fn equals_syntax_and_comments_are_tolerated() {
        let hosts = parse_ssh_config("Host=vps\n# Host ignored\nHostName=1.2.3.4\n");
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0].hostname, "1.2.3.4");
    }

    #[test]
    fn sync_verdict_takes_the_last_sync_prefixed_line() {
        let out = "sync check: host current\nvallum-ops: WARNING: untrusted source\n";
        assert_eq!(sync_verdict(out), "sync check: host current");
    }

    #[test]
    fn sync_verdict_defaults_when_nothing_matches() {
        assert_eq!(sync_verdict("only warnings\n"), "sync complete");
    }
}
