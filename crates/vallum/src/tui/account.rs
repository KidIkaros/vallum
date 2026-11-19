// SPDX-License-Identifier: Apache-2.0

//! The account panel's state and words (ADR-0046).
//!
//! The desk read itself is [`crate::commands::account::read_report`] — the
//! crate's one verified-HTTPS path, shared with `vallum account`. This module
//! only shapes the answer for the panel: plain words on the surface, and
//! `unknown` wherever the desk has not answered — never a confident false
//! state (the same discipline as the desk's own `bytes_used`).

use crate::commands::account::Report;

/// What the panel knows about the desk account.
///
/// The read is a blocking HTTPS call, so it runs off the render path and the
/// panel renders the last cached answer — `NotFetched` until the first one
/// lands.
#[derive(Debug, Default)]
pub enum AccountState {
    /// No read has completed yet.
    #[default]
    NotFetched,
    /// The interface was discovered from its socket — no config to read.
    NoConfig,
    /// The config could not be read (root-only 0600 is the common case).
    /// Carries the raw error line, the way failure cards do.
    Unreadable(String),
    /// The desk read completed; the report itself says what is unknown.
    /// Boxed: the report dwarfs the other variants (clippy's large-variant
    /// rule), and the panel holds exactly one.
    Read(Box<Report>),
}

/// The panel's account section, one plain line per fact.
#[must_use]
pub fn lines(state: &AccountState) -> Vec<String> {
    match state {
        AccountState::NotFetched => vec!["account    unknown — reading the desk".to_owned()],
        AccountState::NoConfig => vec![
            "account    unknown — this interface has no config file to read an account from"
                .to_owned(),
        ],
        AccountState::Unreadable(error) => vec![
            "account    unknown — the config could not be read".to_owned(),
            format!("note       {error}"),
        ],
        AccountState::Read(report) if report.has_account && report.reachable == Some(true) => {
            read_lines(report)
        }
        AccountState::Read(report) if report.has_account => {
            // The desk did not answer (or there was nothing to ask): unknown,
            // with the raw line kept — never a confident false state.
            let headline = if report.reachable == Some(false) {
                "account    unknown — the desk did not answer"
            } else {
                "account    unknown"
            };
            vec![
                format!(
                    "desk       {}",
                    report
                        .endpoint
                        .as_deref()
                        .unwrap_or("unknown (no endpoint recorded)")
                ),
                headline.to_owned(),
                format!("note       {}", report.detail),
            ]
        }
        AccountState::Read(report) => vec![format!("account    {}", report.detail)],
    }
}

/// The desk answered: usage vs cap, expiry, devices — the account's facts.
fn read_lines(report: &Report) -> Vec<String> {
    let or_unknown = |value: &Option<String>| value.clone().unwrap_or_else(|| "unknown".to_owned());
    let gib = 1024.0 * 1024.0 * 1024.0;
    let usage = match (report.bytes_used, report.bytes_cap) {
        (Some(used), Some(cap)) => format!(
            "{:.2} / {:.1} GiB used (shared across devices)",
            used as f64 / gib,
            cap as f64 / gib
        ),
        (None, Some(cap)) => format!(
            "unknown / {:.1} GiB used (shared across devices)",
            cap as f64 / gib
        ),
        _ => "unknown".to_owned(),
    };
    let mut out = vec![
        format!(
            "desk       {}",
            report.endpoint.as_deref().unwrap_or("unknown")
        ),
        format!(
            "account    {} — {}",
            or_unknown(&report.peer),
            or_unknown(&report.label)
        ),
        format!("plan       {}", or_unknown(&report.plan)),
        format!("status     {}", or_unknown(&report.status)),
        format!("expires    {}", or_unknown(&report.expires)),
        format!("bytes      {usage}"),
    ];
    match &report.devices {
        Some(devices) => {
            out.push(format!("devices    {} on this account", devices.len()));
            if let Some(conversion) = &report.conversion {
                match conversion.devices_connected {
                    Some(connected) => out.push(format!(
                        "connected  {connected} of {} devices have connected",
                        conversion.devices_total
                    )),
                    None => out.push(format!(
                        "connected  unknown of {} devices (the daemon could not be asked)",
                        conversion.devices_total
                    )),
                }
            }
        }
        None => out.push("devices    unknown".to_owned()),
    }
    out
}
