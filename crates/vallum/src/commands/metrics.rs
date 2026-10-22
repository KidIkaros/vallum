// SPDX-License-Identifier: Apache-2.0

//! `vallum metrics`: one Prometheus scrape, read from the control socket.
//!
//! WireGuard has no metrics endpoint, which is why an exporter ecosystem exists
//! to parse `wg show`. Vallum's control socket already returns everything a
//! scrape needs, so this command is a formatter: one `get=1`, one exposition.
//!
//! There is no listener on purpose. A cron job or a systemd timer writes the
//! output into `node_exporter`'s textfile directory, or a scraper runs the
//! command over SSH. Nothing new is exposed to the network.

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use clap::Args;

use crate::config::{self, Config};
use crate::uapi::{self, Response};
use crate::{control, say, Error};

#[derive(Debug, Args)]
pub struct MetricsArgs {
    /// The configuration file, for its `control` path.
    #[arg(long, short, value_name = "FILE")]
    pub config: Option<PathBuf>,

    /// The control socket path, instead of a config.
    #[arg(long, value_name = "SOCKET")]
    pub control: Option<PathBuf>,

    /// The metric name prefix.
    #[arg(long, default_value = "vallum", value_name = "PREFIX")]
    pub prefix: String,

    /// Write the exposition to a file instead of stdout.
    ///
    /// The write is atomic — a temp file renamed into place — so a
    /// `node_exporter` textfile collector never reads a half-written scrape.
    /// When the daemon does not answer, the file still gets `up 0` (staleness
    /// hides a dead daemon) while the command exits nonzero.
    #[arg(long, value_name = "FILE")]
    pub output: Option<PathBuf>,
}

/// `vallum metrics`.
///
/// # Errors
///
/// If no socket is configured, the socket does not answer, or the prefix is not
/// a valid Prometheus metric name.
pub fn metrics(args: &MetricsArgs) -> Result<(), Error> {
    if !valid_prefix(&args.prefix) {
        return Err(Error::Usage(format!(
            "`{}` is not a valid metric name prefix; use letters, digits, `_` or `:`",
            args.prefix
        )));
    }
    let socket = socket_path(args.config.as_deref(), args.control.as_deref())?;
    let reply = control::request(&socket, "get=1\n").and_then(|reply| {
        if reply.lines().any(|line| line == "errno=0") {
            Ok(reply)
        } else {
            Err(Error::Usage(format!(
                "control request failed: {}",
                reply.trim()
            )))
        }
    });
    let text = match &reply {
        Ok(reply) => {
            let response = uapi::parse_response(reply);
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |duration| duration.as_secs());
            render(&response, &args.prefix, now)
        }
        Err(_) => {
            // A scrape should see `up 0`, not silence: staleness hides a dead
            // daemon. The command still exits nonzero, so scripts can gate on it.
            format!(
                "# HELP {0}_up Whether the control socket answered.\n\
                 # TYPE {0}_up gauge\n\
                 {0}_up 0\n",
                args.prefix
            )
        }
    };
    // One trailing newline: the textfile collector tolerates it missing but
    // promtool and humans do not.
    let text = format!("{}\n", text.trim_end());
    if let Some(path) = &args.output {
        write_atomic(path, &text)?;
    } else {
        say!("{}", text.trim_end());
    }
    reply.map(|_| ())
}

/// Write via a sibling temp file renamed into place. A partial file under
/// `node_exporter`'s textfile collector reads as corrupt metrics; a rename
/// reads as either the old scrape or the new one.
fn write_atomic(path: &Path, contents: &str) -> Result<(), Error> {
    let temp = path.with_extension("prom.tmp");
    std::fs::write(&temp, contents).map_err(|source| Error::IoPath {
        action: "write",
        path: temp.clone(),
        source,
    })?;
    std::fs::rename(&temp, path).map_err(|source| Error::IoPath {
        action: "rename into place",
        path: path.to_path_buf(),
        source,
    })
}

fn socket_path(config: Option<&Path>, control: Option<&Path>) -> Result<PathBuf, Error> {
    if let Some(control) = control {
        return Ok(control.to_path_buf());
    }
    let Some(config) = config else {
        return Err(Error::Precondition(
            "give --control <socket>, or --config <file> with a `control` field".to_owned(),
        ));
    };
    let loaded = Config::load(config)?;
    loaded
        .interface
        .control
        .as_ref()
        .map(|declared| config::resolve_key_path(config, declared))
        .ok_or_else(|| Error::Invalid {
            path: config.to_path_buf(),
            what: "interface.control is not set, so there is no socket to scrape".to_owned(),
        })
}

fn valid_prefix(prefix: &str) -> bool {
    let mut characters = prefix.chars();
    let Some(first) = characters.next() else {
        return false;
    };
    (first.is_ascii_alphabetic() || first == '_' || first == ':')
        && characters.all(|c| c.is_ascii_alphanumeric() || c == '_' || c == ':')
}

/// Render a `get` response as Prometheus text exposition.
///
/// `now` is passed in so the handshake age is testable without a clock.
fn render(response: &Response, prefix: &str, now: u64) -> String {
    let interface = response
        .field(uapi::field::VALLUM_INTERFACE)
        .unwrap_or("unknown");
    let suite = response
        .field(uapi::field::VALLUM_SUITE)
        .unwrap_or("unknown");
    let mut out = String::new();

    out.push_str(&format!(
        "# HELP {prefix}_up Whether the control socket answered.\n\
         # TYPE {prefix}_up gauge\n\
         {prefix}_up 1\n"
    ));
    out.push_str(&format!(
        "# HELP {prefix}_interface_info The interface, suite and build this scrape describes.\n\
         # TYPE {prefix}_interface_info gauge\n\
         {prefix}_interface_info{{interface=\"{}\",suite=\"{}\",version=\"{}\"}} 1\n",
        escape(interface),
        escape(suite),
        escape(env!("CARGO_PKG_VERSION"))
    ));

    // Dataplane counters, emitted only when the daemon reported them — a
    // missing field stays missing rather than becoming a false zero.
    for (field, metric, help) in [
        (
            uapi::field::VALLUM_DATAGRAMS_SENT,
            "loop_datagrams_sent_total",
            "Datagrams handed to the socket.",
        ),
        (
            uapi::field::VALLUM_DATAGRAMS_FAILED,
            "loop_datagrams_failed_total",
            "Datagrams the socket refused to send.",
        ),
        (
            uapi::field::VALLUM_PACKETS_DELIVERED,
            "loop_packets_delivered_total",
            "Packets written to the tunnel interface.",
        ),
        (
            uapi::field::VALLUM_PACKETS_FAILED,
            "loop_packets_failed_total",
            "Packets the interface write failed on.",
        ),
        (
            uapi::field::VALLUM_HANDSHAKES,
            "loop_handshakes_established_total",
            "Completed peer handshakes.",
        ),
        (
            uapi::field::VALLUM_REFUSALS,
            "loop_handshakes_refused_total",
            "Handshakes refused on policy (expired identity, pinned endpoint).",
        ),
        (
            uapi::field::VALLUM_REASSEMBLED,
            "loop_reassembled_total",
            "Messages delivered out of reassembled fragments.",
        ),
        (
            uapi::field::VALLUM_FRAGMENTS_DROPPED,
            "loop_fragments_dropped_total",
            "Fragments refused or half-assembled messages abandoned.",
        ),
    ] {
        let Some(value) = response.field(field) else {
            continue;
        };
        out.push_str(&format!(
            "# HELP {prefix}_{metric} {help}\n\
             # TYPE {prefix}_{metric} counter\n\
             {prefix}_{metric}{{interface=\"{interface}\"}} {value}\n",
            interface = escape(interface)
        ));
    }

    let peers = response.peers.len();
    let handshaked = (0..peers)
        .filter(|index| {
            response
                .peer_field(*index, uapi::field::LAST_HANDSHAKE_TIME_SEC)
                .and_then(|value| value.parse::<u64>().ok())
                .is_some_and(|value| value > 0)
        })
        .count();
    out.push_str(&format!(
        "# HELP {prefix}_peers_total Configured peers.\n\
         # TYPE {prefix}_peers_total gauge\n\
         {prefix}_peers_total {peers}\n\
         # HELP {prefix}_peers_handshaked Peers that have completed a handshake.\n\
         # TYPE {prefix}_peers_handshaked gauge\n\
         {prefix}_peers_handshaked {handshaked}\n"
    ));

    if peers == 0 {
        return out;
    }

    for metric in [
        (
            "peer_rx_bytes_total",
            "counter",
            "Bytes received from the peer.",
        ),
        ("peer_tx_bytes_total", "counter", "Bytes sent to the peer."),
        (
            "peer_delivery_ratio",
            "gauge",
            "Datagrams received over datagrams sent in the last window; 1 when \
             nothing was sent. Below 1 means the tunnel is sending and not \
             getting answers, which handshake age cannot show.",
        ),
        (
            "peer_last_handshake_seconds",
            "gauge",
            "Unix time of the peer's last handshake, or 0.",
        ),
        (
            "peer_handshake_age_seconds",
            "gauge",
            "Seconds since the peer's last handshake, or -1 if never.",
        ),
        ("peer_epoch", "gauge", "The peer's current key epoch."),
        (
            "peer_handshaked",
            "gauge",
            "1 if the peer has completed a handshake, 0 otherwise.",
        ),
    ] {
        out.push_str(&format!(
            "# HELP {prefix}_{} {}\n# TYPE {prefix}_{} {}\n",
            metric.0, metric.2, metric.0, metric.1
        ));
        for index in 0..peers {
            let peer = response
                .peer_field(index, uapi::field::VALLUM_NAME)
                .filter(|name| !name.is_empty())
                .or_else(|| response.peer_field(index, uapi::field::VALLUM_FINGERPRINT))
                .unwrap_or("unnamed");
            let fingerprint = response
                .peer_field(index, uapi::field::VALLUM_FINGERPRINT)
                .unwrap_or("-");
            let labels = format!(
                "interface=\"{}\",peer=\"{}\",fingerprint=\"{}\"",
                escape(interface),
                escape(peer),
                escape(fingerprint)
            );
            let value = match metric.0 {
                "peer_rx_bytes_total" => number(response, index, uapi::field::RX_BYTES).to_string(),
                "peer_tx_bytes_total" => number(response, index, uapi::field::TX_BYTES).to_string(),
                "peer_delivery_ratio" => {
                    let sent = number(response, index, uapi::field::WINDOW_SENT);
                    let received = number(response, index, uapi::field::WINDOW_RECEIVED);
                    if sent == 0 {
                        // Nothing to judge: an idle tunnel is not a broken one.
                        "1".to_owned()
                    } else {
                        let ratio = received as f64 / sent as f64;
                        format!("{:.4}", ratio.min(1.0))
                    }
                }
                "peer_last_handshake_seconds" => {
                    number(response, index, uapi::field::LAST_HANDSHAKE_TIME_SEC).to_string()
                }
                "peer_handshake_age_seconds" => {
                    let last = number(response, index, uapi::field::LAST_HANDSHAKE_TIME_SEC);
                    if last == 0 {
                        "-1".to_owned()
                    } else {
                        now.saturating_sub(last).to_string()
                    }
                }
                "peer_epoch" => number(response, index, uapi::field::VALLUM_EPOCH).to_string(),
                _ => u64::from(number(response, index, uapi::field::LAST_HANDSHAKE_TIME_SEC) > 0)
                    .to_string(),
            };
            out.push_str(&format!("{prefix}_{}{{{labels}}} {value}\n", metric.0));
        }
    }
    out
}

fn number(response: &Response, index: usize, field: &str) -> u64 {
    response
        .peer_field(index, field)
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(0)
}

/// Prometheus label values need `\`, `"` and newlines escaped.
fn escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            other => out.push(other),
        }
    }
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    const GET: &str = "private_key=(hidden)\n\
vallum_interface=vallum0\n\
vallum_suite=0x0003\n\
listen_port=51820\n\
errno=0\n\
\n\
public_key=aaa\n\
vallum_name=laptop\n\
vallum_fingerprint=f1e20541fb69\n\
rx_bytes=1234\n\
tx_bytes=5678\n\
vallum_window_sent=1000\n\
vallum_window_received=12\n\
last_handshake_time_sec=1792522000\n\
vallum_epoch=3\n\
errno=0\n\
\n\
public_key=bbb\n\
vallum_name=phone\n\
vallum_fingerprint=0ca326366885\n\
rx_bytes=0\n\
tx_bytes=10\n\
vallum_window_sent=0\n\
vallum_window_received=0\n\
last_handshake_time_sec=0\n\
vallum_epoch=0\n\
errno=0\n";

    fn response() -> Response {
        uapi::parse_response(GET)
    }

    #[test]
    fn a_scrape_names_every_peer_and_its_age() {
        let text = render(&response(), "vallum", 1792522042);
        assert!(text.contains("vallum_up 1"));
        assert!(text.contains("vallum_peers_total 2"));
        assert!(text.contains("vallum_peers_handshaked 1"));
        assert!(text.contains(
            "vallum_peer_rx_bytes_total{interface=\"vallum0\",peer=\"laptop\",fingerprint=\"f1e20541fb69\"} 1234"
        ));
        assert!(text.contains(
            "vallum_peer_handshake_age_seconds{interface=\"vallum0\",peer=\"laptop\",fingerprint=\"f1e20541fb69\"} 42"
        ));
        // A peer that never handshook reports -1, not "now".
        assert!(text.contains(
            "vallum_peer_handshake_age_seconds{interface=\"vallum0\",peer=\"phone\",fingerprint=\"0ca326366885\"} -1"
        ));
        assert!(text.contains(
            "vallum_peer_handshaked{interface=\"vallum0\",peer=\"phone\",fingerprint=\"0ca326366885\"} 0"
        ));
    }

    #[test]
    fn the_delivery_ratio_exposes_a_tunnel_that_is_sending_into_the_void() {
        // The shape of the real failure: 12 datagrams back against 1000 sent,
        // while the handshake is only 42 s old and looks perfectly healthy.
        let text = render(&response(), "vallum", 1792522042);
        assert!(
            text.contains(
                "vallum_peer_delivery_ratio{interface=\"vallum0\",peer=\"laptop\",fingerprint=\"f1e20541fb69\"} 0.0120"
            ),
            "the ratio must show a tunnel that is sending and not being answered"
        );
        assert!(text.contains(
            "vallum_peer_handshake_age_seconds{interface=\"vallum0\",peer=\"laptop\",fingerprint=\"f1e20541fb69\"} 42"
        ));
    }

    #[test]
    fn an_idle_peer_reports_a_full_ratio_rather_than_zero() {
        // Nothing sent is not the same as nothing delivered: an idle tunnel is
        // not a broken one, and reporting 0 here would make every quiet peer
        // look like an outage.
        let text = render(&response(), "vallum", 1792522042);
        assert!(text.contains(
            "vallum_peer_delivery_ratio{interface=\"vallum0\",peer=\"phone\",fingerprint=\"0ca326366885\"} 1"
        ));
    }

    #[test]
    fn every_metric_family_has_a_help_and_type_line() {
        let text = render(&response(), "vallum", 1792522042);
        for metric in [
            "vallum_up",
            "vallum_interface_info",
            "vallum_peers_total",
            "vallum_peer_rx_bytes_total",
            "vallum_peer_tx_bytes_total",
            "vallum_peer_handshake_age_seconds",
            "vallum_peer_epoch",
        ] {
            assert!(text.contains(&format!("# HELP {metric} ")), "{metric}");
            assert!(text.contains(&format!("# TYPE {metric} ")), "{metric}");
        }
    }

    #[test]
    fn the_prefix_renames_every_metric() {
        let text = render(&response(), "vpn_a", 1792522042);
        assert!(text.contains("vpn_a_up 1"));
        assert!(!text.contains("vallum_up"));
    }

    #[test]
    fn interface_info_carries_the_build_version() {
        let text = render(&response(), "vallum", 0);
        assert!(text.contains(&format!("version=\"{}\"", env!("CARGO_PKG_VERSION"))));
    }

    #[test]
    fn write_atomic_leaves_only_the_final_file() {
        let dir = std::env::temp_dir().join(format!("vallum-metrics-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("vallum.prom");
        write_atomic(&path, "vallum_up 1\n").unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "vallum_up 1\n");
        assert!(!dir.join("vallum.prom.tmp").exists());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_peer_name_with_a_quote_is_escaped() {
        let text = render(&response(), "vallum", 0);
        assert!(text.contains("peer=\"laptop\""));
        assert_eq!(escape("a\"b\\c"), "a\\\"b\\\\c");
    }

    #[test]
    fn a_device_with_no_peers_still_scrapes() {
        let empty = uapi::parse_response("vallum_interface=vallum0\nerrno=0\n");
        let text = render(&empty, "vallum", 0);
        assert!(text.contains("vallum_peers_total 0"));
        assert!(text.contains("vallum_peers_handshaked 0"));
        assert!(!text.contains("vallum_peer_rx_bytes_total{"));
    }

    #[test]
    fn loop_counters_scrape_as_counters_and_stay_absent_when_unknown() {
        let with = uapi::parse_response(
            "vallum_interface=vallum0\n\
             vallum_datagrams_sent=42\n\
             vallum_datagrams_failed=1\n\
             vallum_packets_delivered=7\n\
             vallum_packets_failed=0\n\
             vallum_handshakes_established=3\n\
             vallum_handshakes_refused=0\n\
             vallum_reassembled=5\n\
             vallum_fragments_dropped=2\n\
             errno=0\n",
        );
        let text = render(&with, "vallum", 0);
        assert!(text.contains("# TYPE vallum_loop_datagrams_sent_total counter"));
        assert!(text.contains("vallum_loop_datagrams_sent_total{interface=\"vallum0\"} 42"));
        assert!(text.contains("vallum_loop_fragments_dropped_total{interface=\"vallum0\"} 2"));
        assert!(text.contains("# HELP vallum_loop_handshakes_refused_total"));

        // An older daemon without telemetry fields: the families are absent,
        // not reported as a false zero.
        let without = uapi::parse_response("vallum_interface=vallum0\nerrno=0\n");
        let text = render(&without, "vallum", 0);
        assert!(!text.contains("vallum_loop_datagrams_sent_total"));
        assert!(text.contains("vallum_up 1"));
    }

    #[test]
    fn a_prefix_must_be_a_metric_name() {
        assert!(valid_prefix("vallum"));
        assert!(valid_prefix("vpn:one"));
        assert!(!valid_prefix("1vallum"));
        assert!(!valid_prefix("vallum-gap"));
        assert!(!valid_prefix(""));
    }
}
