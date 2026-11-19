//! `vallum account` — the client reads its account from the desk (ADR-0046).
//!
//! The daemon stays account-ignorant (ADR-0044/0045): this verb asks the
//! desk directly, over HTTPS, with the bearer token already sealed in
//! `[account]`. The read is best-effort — a desk that cannot be reached
//! renders `unknown`, never a confident false state. The endpoint is shown
//! before the call, so the user can see where their token goes.

use std::path::PathBuf;
use std::time::Duration;

use clap::Args;
use serde::{Deserialize, Serialize};

use crate::error::Error;

/// A desk origin: `https://host[:port]` (or loopback `http://` for a local
/// desk). No path — the account API lives at a fixed `POST /api/account`.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct DeskEndpoint {
    pub tls: bool,
    pub host: String,
    pub port: u16,
}

/// Parse the desk origin recorded at join (`[account] endpoint`).
///
/// The token is a bearer credential: it may only travel over TLS, or over
/// plain HTTP on loopback where no network sits between client and desk.
/// A non-loopback `http://` origin is refused, not silently downgraded.
pub(crate) fn parse_desk_endpoint(raw: &str) -> Result<DeskEndpoint, Error> {
    let trimmed = raw.trim();
    let (tls, rest) = if let Some(r) = trimmed.strip_prefix("https://") {
        (true, r)
    } else if let Some(r) = trimmed.strip_prefix("http://") {
        (false, r)
    } else {
        return Err(Error::Usage(
            "the desk endpoint must be an `https://host[:port]` origin".to_owned(),
        ));
    };
    if rest.contains(['/', '?', '#', '@']) {
        return Err(Error::Usage(
            "the desk endpoint is an origin — no path, query, or userinfo".to_owned(),
        ));
    }
    let default_port = if tls { 443 } else { 80 };
    let (host, port) = if let Some(bracketed) = rest.strip_prefix('[') {
        let end = bracketed
            .find(']')
            .ok_or_else(|| Error::Usage("malformed IPv6 host in the desk endpoint".to_owned()))?;
        let host = bracketed[..end].to_owned();
        let after = &bracketed[end + 1..];
        let port = if let Some(p) = after.strip_prefix(':') {
            p.parse::<u16>()
                .map_err(|_| Error::Usage("invalid port in the desk endpoint".to_owned()))?
        } else if after.is_empty() {
            default_port
        } else {
            return Err(Error::Usage(
                "invalid authority in the desk endpoint".to_owned(),
            ));
        };
        (host, port)
    } else if let Some((h, p)) = rest.rsplit_once(':') {
        let port = p
            .parse::<u16>()
            .map_err(|_| Error::Usage("invalid port in the desk endpoint".to_owned()))?;
        (h.to_owned(), port)
    } else {
        (rest.to_owned(), default_port)
    };
    if host.is_empty() {
        return Err(Error::Usage(
            "the desk endpoint is missing a host".to_owned(),
        ));
    }
    if !tls && !is_loopback_host(&host) {
        return Err(Error::Usage(
            "the desk endpoint must be https:// off loopback — the account token \
             never crosses a network in cleartext"
                .to_owned(),
        ));
    }
    Ok(DeskEndpoint { tls, host, port })
}

fn is_loopback_host(host: &str) -> bool {
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    host.parse::<std::net::IpAddr>()
        .is_ok_and(|ip| ip.is_loopback())
}

#[derive(Debug, Args)]
pub struct AccountArgs {
    /// The config whose desk account to read.
    #[arg(long, short)]
    pub config: PathBuf,
    /// Machine-readable output.
    #[arg(long)]
    pub json: bool,
}

/// One account read, in a shape agents can branch on. Every key is always
/// present: `null` means "not known", never a confident zero. `reachable`
/// is `null` when no call was attempted (no token, or no endpoint).
#[derive(Debug, Default, Serialize)]
pub struct Report {
    pub has_account: bool,
    pub endpoint: Option<String>,
    pub reachable: Option<bool>,
    pub detail: String,
    pub peer: Option<String>,
    pub label: Option<String>,
    pub plan: Option<String>,
    pub status: Option<String>,
    pub expires: Option<String>,
    pub paid_until: Option<String>,
    pub bytes_cap: Option<u64>,
    pub bytes_used: Option<u64>,
    pub conversion: Option<Conversion>,
    pub devices: Option<Vec<Device>>,
}

/// The desk's funnel for this account. `devices_connected` is null when
/// the daemon could not be asked — the desk's own discipline, kept.
#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct Conversion {
    pub devices_total: u64,
    pub devices_connected: Option<u64>,
}

/// One device under the account, as the desk describes it.
#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct Device {
    pub peer: Option<String>,
    pub label: Option<String>,
    pub status: Option<String>,
    pub created: Option<String>,
    pub connection: Option<String>,
    pub last_seen_seconds: Option<u64>,
    pub connection_sentence: Option<String>,
}

/// The desk's `POST /api/account` answer.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct DeskAccount {
    peer: Option<String>,
    label: Option<String>,
    plan: Option<String>,
    status: Option<String>,
    expires: Option<String>,
    paid_until: Option<String>,
    bytes_cap: Option<u64>,
    bytes_used: Option<u64>,
    conversion: Option<Conversion>,
    devices: Vec<Device>,
}

/// Run the verb.
///
/// # Errors
/// A missing config, or a config that cannot be read. An unreachable desk
/// is not an error: the read is best-effort and renders `unknown`.
pub fn account(args: &AccountArgs) -> Result<(), Error> {
    let config = vallum_config::Config::load(&args.config).map_err(|source| Error::IoPath {
        action: "read the config",
        path: args.config.clone(),
        source: std::io::Error::other(source.to_string()),
    })?;
    let report = read_report(&config);
    if args.json {
        crate::say!("{}", render_json(&report)?);
    } else {
        crate::say!("{}", render_human(&report));
    }
    Ok(())
}

/// Read `[account]` and, when there is something to ask, ask the desk.
fn read_report(config: &vallum_config::Config) -> Report {
    let Some(token) = config.account.token.as_deref() else {
        return Report {
            detail: "this config has no desk account — it was enrolled from a file \
                     or over SSH, so there is nothing to ask a desk"
                .to_owned(),
            ..Report::default()
        };
    };
    let Some(raw_endpoint) = config.account.endpoint.as_deref() else {
        return Report {
            has_account: true,
            detail: "this config carries an account token but no desk endpoint — \
                     re-join from the desk's connect link to record it"
                .to_owned(),
            ..Report::default()
        };
    };
    let endpoint_display = raw_endpoint.trim().to_owned();
    let endpoint = match parse_desk_endpoint(raw_endpoint) {
        Ok(endpoint) => endpoint,
        Err(error) => {
            return Report {
                has_account: true,
                endpoint: Some(endpoint_display),
                reachable: Some(false),
                detail: format!("the recorded desk endpoint is not usable: {error}"),
                ..Report::default()
            };
        }
    };
    match desk_account_post(&endpoint, token) {
        Ok(answer) => Report {
            has_account: true,
            endpoint: Some(endpoint_display),
            reachable: Some(true),
            detail: "the desk answered".to_owned(),
            peer: answer.peer,
            label: answer.label,
            plan: answer.plan,
            status: answer.status,
            expires: answer.expires,
            paid_until: answer.paid_until,
            bytes_cap: answer.bytes_cap,
            bytes_used: answer.bytes_used,
            conversion: answer.conversion,
            devices: Some(answer.devices),
        },
        Err(error) => Report {
            has_account: true,
            endpoint: Some(endpoint_display),
            reachable: Some(false),
            detail: error.to_string(),
            ..Report::default()
        },
    }
}

/// `POST {endpoint}/api/account` with the token in the JSON body — never
/// in the URL (the desk's security rule). Same round-trip shape as the
/// enrolment front client (`enroll::front_round_trip`), but the TLS
/// certificate is verified against the system trust store: the account
/// read has no inner handshake to authenticate the desk, so the outer
/// TLS must do it (ADR-0046's token-exposure mitigation).
fn desk_account_post(endpoint: &DeskEndpoint, token: &str) -> Result<DeskAccount, Error> {
    use std::io::Write;
    use std::net::ToSocketAddrs;

    let addr = (endpoint.host.as_str(), endpoint.port)
        .to_socket_addrs()
        .map_err(|e| Error::Usage(format!("resolve the desk host: {e}")))?
        .next()
        .ok_or_else(|| Error::Usage("the desk host resolved to no addresses".to_owned()))?;
    let stream = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(5))
        .map_err(|e| Error::Usage(format!("connect to the desk {addr}: {e}")))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(|e| Error::Usage(format!("desk socket: {e}")))?;
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .map_err(|e| Error::Usage(format!("desk socket: {e}")))?;
    let _ = stream.set_nodelay(true);

    let body = serde_json::json!({ "token": token }).to_string();
    let default_port = if endpoint.tls { 443 } else { 80 };
    let host_header = if endpoint.port == default_port {
        endpoint.host.clone()
    } else {
        format!("{}:{}", endpoint.host, endpoint.port)
    };
    let req_head = format!(
        "POST /api/account HTTP/1.1\r\nHost: {host_header}\r\n\
         Content-Type: application/json\r\nAccept: application/json\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );

    let mut raw = Vec::with_capacity(4096);
    if endpoint.tls {
        let cfg = desk_tls_config()?;
        let server_name = crate::tls_quic::server_name_for(&endpoint.host)
            .map_err(|e| Error::Usage(format!("desk SNI: {e}")))?;
        let conn = rustls::ClientConnection::new(cfg, server_name)
            .map_err(|e| Error::Usage(format!("desk TLS init: {e}")))?;
        let mut tls_stream = rustls::StreamOwned::new(conn, stream);
        tls_stream
            .write_all(req_head.as_bytes())
            .and_then(|()| tls_stream.write_all(body.as_bytes()))
            .and_then(|()| tls_stream.flush())
            .map_err(|e| Error::Usage(format!("write to the desk: {e}")))?;
        read_http_response(&mut tls_stream, &mut raw)?;
    } else {
        let mut plain = stream;
        plain
            .write_all(req_head.as_bytes())
            .and_then(|()| plain.write_all(body.as_bytes()))
            .and_then(|()| plain.flush())
            .map_err(|e| Error::Usage(format!("write to the desk: {e}")))?;
        read_http_response(&mut plain, &mut raw)?;
    }

    let Some(hdr_end) = raw.windows(4).position(|w| w == b"\r\n\r\n") else {
        return Err(Error::Usage(
            "malformed HTTP response from the desk".to_owned(),
        ));
    };
    let head = std::str::from_utf8(&raw[..hdr_end])
        .map_err(|_| Error::Usage("non-UTF-8 HTTP header from the desk".to_owned()))?;
    let status_line = head.lines().next().unwrap_or("");
    let body_bytes = &raw[hdr_end + 4..];
    if !status_line.contains(" 200 ") {
        let snippet: String = String::from_utf8_lossy(body_bytes)
            .chars()
            .take(200)
            .collect();
        return Err(Error::Usage(format!(
            "the desk refused: {status_line} {}",
            snippet.trim()
        )));
    }
    serde_json::from_slice(body_bytes)
        .map_err(|e| Error::Usage(format!("the desk's answer did not parse: {e}")))
}

/// Read one HTTP response: the head, then exactly `Content-Length` bytes
/// when the desk names one, else to the close our `Connection: close` asks
/// for.
fn read_http_response(stream: &mut impl std::io::Read, raw: &mut Vec<u8>) -> Result<(), Error> {
    let mut chunk = [0u8; 4096];
    let head_end = loop {
        let n = stream
            .read(&mut chunk)
            .map_err(|e| Error::Usage(format!("read the desk's answer: {e}")))?;
        if n == 0 {
            return Err(Error::Usage("the desk closed without an answer".to_owned()));
        }
        raw.extend_from_slice(&chunk[..n]);
        if let Some(pos) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
            break pos + 4;
        }
    };
    let head = String::from_utf8_lossy(&raw[..head_end]);
    let length = head.lines().find_map(|line| {
        let (key, value) = line.split_once(':')?;
        key.eq_ignore_ascii_case("content-length")
            .then(|| value.trim().parse::<usize>().ok())?
    });
    match length {
        Some(length) => {
            while raw.len() < head_end + length {
                let n = stream
                    .read(&mut chunk)
                    .map_err(|e| Error::Usage(format!("read the desk's answer: {e}")))?;
                if n == 0 {
                    break;
                }
                raw.extend_from_slice(&chunk[..n]);
            }
        }
        None => {
            stream
                .read_to_end(raw)
                .map_err(|e| Error::Usage(format!("read the desk's answer: {e}")))?;
        }
    }
    Ok(())
}

/// The system CA bundles, in the order the common Linux distributions
/// ship them. The daemon is Linux-only, so this list is the platform.
const CA_BUNDLES: [&str; 5] = [
    "/etc/ssl/certs/ca-certificates.crt",
    "/etc/pki/tls/certs/ca-bundle.crt",
    "/etc/ssl/ca-bundle.pem",
    "/etc/pki/tls/cacert.pem",
    "/etc/ssl/cert.pem",
];

/// A rustls client that verifies the desk's certificate against the
/// system trust store. Fails closed when no trust store can be read: an
/// unverified desk is a phishing risk for the bearer token (ADR-0046).
fn desk_tls_config() -> Result<std::sync::Arc<rustls::ClientConfig>, Error> {
    let mut roots = rustls::RootCertStore::empty();
    for path in CA_BUNDLES {
        let Ok(pem) = std::fs::read(path) else {
            continue;
        };
        roots.add_parsable_certificates(pem_certificates(&pem));
    }
    if roots.is_empty() {
        return Err(Error::Usage(
            "no system CA trust store found — cannot verify the desk's certificate".to_owned(),
        ));
    }
    let provider = std::sync::Arc::new(rustls::crypto::ring::default_provider());
    let cfg = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| Error::Usage(format!("desk TLS setup: {e}")))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(std::sync::Arc::new(cfg))
}

/// The DER certificates inside a PEM bundle.
fn pem_certificates(pem: &[u8]) -> Vec<rustls::pki_types::CertificateDer<'static>> {
    let text = String::from_utf8_lossy(pem);
    let mut certs = Vec::new();
    let mut rest = text.as_ref();
    while let Some(start) = rest.find("-----BEGIN CERTIFICATE-----") {
        let after = &rest[start + "-----BEGIN CERTIFICATE-----".len()..];
        let Some(end) = after.find("-----END CERTIFICATE-----") else {
            break;
        };
        if let Some(der) = base64_decode(&after[..end]) {
            certs.push(rustls::pki_types::CertificateDer::from(der));
        }
        rest = &after[end + "-----END CERTIFICATE-----".len()..];
    }
    certs
}

/// Standard-alphabet base64 (RFC 4648), whitespace-tolerant, for the PEM
/// bundles. No new dependency for a decoder this small.
fn base64_decode(input: &str) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    for c in input.chars() {
        if c.is_ascii_whitespace() {
            continue;
        }
        if c == '=' {
            break;
        }
        let value = match c {
            'A'..='Z' => c as u32 - 'A' as u32,
            'a'..='z' => c as u32 - 'a' as u32 + 26,
            '0'..='9' => c as u32 - '0' as u32 + 52,
            '+' => 62,
            '/' => 63,
            _ => return None,
        };
        acc = ((acc << 6) | value) & 0xFFFF;
        bits += 6;
        while bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Some(out)
}

/// The human report. Unknown is spelled out, never a confident zero.
fn render_human(report: &Report) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    if !report.has_account {
        let _ = writeln!(out, "{:<10} {}", "account", report.detail);
        return out;
    }
    let desk = report
        .endpoint
        .as_deref()
        .unwrap_or("unknown (no endpoint recorded)");
    let _ = writeln!(out, "{:<10} {desk} (POST /api/account)", "desk");
    if report.reachable != Some(true) {
        for label in [
            "account",
            "plan",
            "status",
            "expires",
            "paid until",
            "bytes",
            "devices",
            "connected",
        ] {
            let _ = writeln!(out, "{:<10} unknown", label);
        }
        let _ = writeln!(out, "{:<10} {}", "note", report.detail);
        return out;
    }
    let or_unknown = |value: &Option<String>| value.clone().unwrap_or_else(|| "unknown".to_owned());
    let _ = writeln!(
        out,
        "{:<10} {} — {}",
        "account",
        or_unknown(&report.peer),
        or_unknown(&report.label)
    );
    let _ = writeln!(out, "{:<10} {}", "plan", or_unknown(&report.plan));
    let _ = writeln!(out, "{:<10} {}", "status", or_unknown(&report.status));
    let _ = writeln!(out, "{:<10} {}", "expires", or_unknown(&report.expires));
    let _ = writeln!(
        out,
        "{:<10} {}",
        "paid until",
        or_unknown(&report.paid_until)
    );
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
    let _ = writeln!(out, "{:<10} {usage}", "bytes");
    if let Some(devices) = &report.devices {
        let _ = writeln!(out, "{:<10} {} on this account", "devices", devices.len());
        for device in devices {
            let sentence = device
                .connection_sentence
                .as_deref()
                .or(device.connection.as_deref())
                .unwrap_or("unknown");
            let _ = writeln!(
                out,
                "  {}  {}  {sentence}",
                device.peer.as_deref().unwrap_or("?"),
                device.label.as_deref().unwrap_or("")
            );
        }
    } else {
        let _ = writeln!(out, "{:<10} unknown", "devices");
    }
    match &report.conversion {
        Some(conversion) => match conversion.devices_connected {
            Some(connected) => {
                let _ = writeln!(
                    out,
                    "{:<10} {connected} of {} devices have connected",
                    "connected", conversion.devices_total
                );
            }
            None => {
                let _ = writeln!(
                    out,
                    "{:<10} unknown of {} devices (the daemon could not be asked)",
                    "connected", conversion.devices_total
                );
            }
        },
        None => {
            let _ = writeln!(out, "{:<10} unknown", "connected");
        }
    }
    out
}

/// The agent report: every key always present, `null` for the unknowns.
fn render_json(report: &Report) -> Result<String, Error> {
    serde_json::to_string_pretty(report).map_err(|e| Error::Usage(format!("json: {e}")))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    /// The crate's HTTP-stub pattern (see `enroll.rs`): a real TcpListener
    /// on loopback speaking HTTP/1.1, so the verb's fetch path is exercised
    /// end to end without a network. Returns the origin and a handle that
    /// yields the request the stub received.
    fn stub_desk(
        status: &'static str,
        body: &'static str,
    ) -> (String, std::thread::JoinHandle<String>) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let handle = std::thread::spawn(move || {
            use std::io::{Read, Write};
            let (mut stream, _) = listener.accept().unwrap();
            let mut buf = Vec::new();
            let mut chunk = [0u8; 4096];
            // Read the head, then exactly Content-Length bytes of body.
            let head_end = loop {
                let n = stream.read(&mut chunk).unwrap();
                assert!(n > 0, "the client closed before sending a request");
                buf.extend_from_slice(&chunk[..n]);
                if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                    break pos + 4;
                }
            };
            let head = String::from_utf8_lossy(&buf[..head_end]).into_owned();
            let length: usize = head
                .lines()
                .find_map(|l| {
                    let (k, v) = l.split_once(':')?;
                    k.eq_ignore_ascii_case("content-length")
                        .then(|| v.trim().parse().ok())?
                })
                .unwrap_or(0);
            while buf.len() < head_end + length {
                let n = stream.read(&mut chunk).unwrap();
                assert!(n > 0, "the client closed mid-body");
                buf.extend_from_slice(&chunk[..n]);
            }
            let response = format!(
                "HTTP/1.1 {status}\r\nContent-Type: application/json\r\n\
                 Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            stream.write_all(response.as_bytes()).unwrap();
            String::from_utf8_lossy(&buf).into_owned()
        });
        (origin, handle)
    }

    fn config_with_account(
        dir: &std::path::Path,
        token: Option<&str>,
        endpoint: Option<&str>,
    ) -> std::path::PathBuf {
        let mut text = String::from(
            "[interface]\nname = \"v0\"\nprivate_key = \"k\"\n\n[[peer]]\nname = \"p\"\n",
        );
        if token.is_some() || endpoint.is_some() {
            text.push_str("\n[account]\n");
            if let Some(token) = token {
                text.push_str(&format!("token = \"{token}\"\n"));
            }
            if let Some(endpoint) = endpoint {
                text.push_str(&format!("endpoint = \"{endpoint}\"\n"));
            }
        }
        let path = dir.join("client.toml");
        std::fs::write(&path, text).unwrap();
        path
    }

    fn temp_dir(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "vallum-account-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    const FULL_ANSWER: &str = r#"{
        "peer": "u0001", "label": "laptop", "plan": "trial", "status": "active",
        "expires": "2026-12-02", "paid_until": null,
        "bytes_cap": 5368709120, "bytes_used": 1073741824,
        "conversion": {"devices_total": 2, "devices_connected": 1},
        "devices": [
            {"peer": "u0001", "label": "laptop", "status": "active",
             "created": "2026-11-18", "connection": "live",
             "last_seen_seconds": 3, "connection_sentence": "connected now"},
            {"peer": "u0002", "label": "phone", "status": "active",
             "created": "2026-11-18", "connection": "never",
             "last_seen_seconds": null, "connection_sentence": "never connected"}
        ]
    }"#;

    /// The verb renders the desk's fields, and the token travels in the
    /// POST body — never in the request target (the desk's security rule).
    #[test]
    fn the_account_read_renders_the_desks_answer() {
        let (origin, handle) = stub_desk("200 OK", FULL_ANSWER);
        let dir = temp_dir("render");
        let token = "0123456789abcdef0123456789abcdef";
        let path = config_with_account(&dir, Some(token), Some(&origin));
        let config = vallum_config::Config::load(&path).unwrap();
        let report = read_report(&config);
        let request = handle.join().unwrap();

        assert!(report.has_account);
        assert_eq!(report.reachable, Some(true));
        assert_eq!(report.plan.as_deref(), Some("trial"));
        assert_eq!(report.status.as_deref(), Some("active"));
        assert_eq!(report.expires.as_deref(), Some("2026-12-02"));
        assert_eq!(report.bytes_cap, Some(5_368_709_120));
        assert_eq!(report.bytes_used, Some(1_073_741_824));
        assert_eq!(report.devices.as_ref().map(Vec::len), Some(2));

        // The request line carries no token; the JSON body does.
        let request_line = request.lines().next().unwrap();
        assert_eq!(request_line, "POST /api/account HTTP/1.1");
        assert!(!request_line.contains(token));
        let body = request.split_once("\r\n\r\n").unwrap().1;
        assert_eq!(body, format!("{{\"token\":\"{token}\"}}"));

        let human = render_human(&report);
        assert!(human.contains(&origin), "{human}");
        assert!(human.contains("trial"), "{human}");
        assert!(human.contains("active"), "{human}");
        assert!(human.contains("2026-12-02"), "{human}");
        assert!(human.contains("1.00 / 5.0 GiB"), "{human}");
        assert!(human.contains("u0002"), "{human}");
        assert!(human.contains("1 of 2"), "{human}");

        let json: serde_json::Value = serde_json::from_str(&render_json(&report).unwrap()).unwrap();
        assert_eq!(json["plan"], "trial");
        assert_eq!(json["bytes_used"], 1_073_741_824u64);
        assert_eq!(json["conversion"]["devices_connected"], 1);
        assert_eq!(json["devices"].as_array().unwrap().len(), 2);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `bytes_used: null` means the desk could not ask the daemon. It must
    /// render `unknown`, never a confident zero.
    #[test]
    fn null_bytes_used_renders_unknown_not_zero() {
        let body = r#"{
            "peer": "u0001", "label": "laptop", "plan": "trial", "status": "active",
            "expires": "2026-12-02", "paid_until": null,
            "bytes_cap": 5368709120, "bytes_used": null,
            "conversion": {"devices_total": 1, "devices_connected": null},
            "devices": []
        }"#;
        let (origin, handle) = stub_desk("200 OK", body);
        let dir = temp_dir("null");
        let path = config_with_account(
            &dir,
            Some("0123456789abcdef0123456789abcdef"),
            Some(&origin),
        );
        let config = vallum_config::Config::load(&path).unwrap();
        let report = read_report(&config);
        let _ = handle.join().unwrap();

        assert_eq!(report.reachable, Some(true));
        assert_eq!(report.bytes_used, None);
        let human = render_human(&report);
        assert!(human.contains("unknown / 5.0 GiB"), "{human}");
        assert!(!human.contains("0.00"), "{human}");
        let json: serde_json::Value = serde_json::from_str(&render_json(&report).unwrap()).unwrap();
        assert!(json["bytes_used"].is_null());
        assert!(json["conversion"]["devices_connected"].is_null());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A desk that cannot be reached is `unknown`, not an error and not a
    /// confident false state — the read is best-effort (ADR-0046).
    #[test]
    fn an_unreachable_desk_renders_unknown() {
        // Bind then drop: the port is almost certainly closed now.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        drop(listener);
        let dir = temp_dir("unreachable");
        let path = config_with_account(
            &dir,
            Some("0123456789abcdef0123456789abcdef"),
            Some(&origin),
        );
        let config = vallum_config::Config::load(&path).unwrap();
        let report = read_report(&config);

        assert!(report.has_account);
        assert_eq!(report.reachable, Some(false));
        assert!(report.plan.is_none());
        let human = render_human(&report);
        assert!(human.contains("unknown"), "{human}");
        assert!(human.contains(&origin), "{human}");
        let json: serde_json::Value = serde_json::from_str(&render_json(&report).unwrap()).unwrap();
        assert_eq!(json["reachable"], false);
        assert!(json["plan"].is_null());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A file/SSH enrolment has no desk account; the verb says so plainly.
    #[test]
    fn a_config_without_a_token_says_it_has_no_desk_account() {
        let dir = temp_dir("noaccount");
        let path = config_with_account(&dir, None, None);
        let config = vallum_config::Config::load(&path).unwrap();
        let report = read_report(&config);
        assert!(!report.has_account);
        assert_eq!(report.reachable, None);
        let human = render_human(&report);
        assert!(human.contains("no desk account"), "{human}");
        let json: serde_json::Value = serde_json::from_str(&render_json(&report).unwrap()).unwrap();
        assert_eq!(json["has_account"], false);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A token recorded before the endpoint field existed cannot call
    /// anywhere; the verb says what is missing instead of guessing a desk.
    #[test]
    fn a_token_without_an_endpoint_cannot_call() {
        let dir = temp_dir("noendpoint");
        let path = config_with_account(&dir, Some("0123456789abcdef0123456789abcdef"), None);
        let config = vallum_config::Config::load(&path).unwrap();
        let report = read_report(&config);
        assert!(report.has_account);
        assert_eq!(report.reachable, None);
        assert!(report.detail.contains("endpoint"), "{}", report.detail);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The desk's own refusal is quoted, not turned into a guess about the
    /// account's state.
    #[test]
    fn the_desks_refusal_is_reported_not_guessed() {
        let (origin, handle) = stub_desk("404 Not Found", r#"{"error": "unknown account token"}"#);
        let dir = temp_dir("refused");
        let path = config_with_account(
            &dir,
            Some("0123456789abcdef0123456789abcdef"),
            Some(&origin),
        );
        let config = vallum_config::Config::load(&path).unwrap();
        let report = read_report(&config);
        let _ = handle.join().unwrap();
        assert_eq!(report.reachable, Some(false));
        assert!(
            report.detail.contains("unknown account token"),
            "{}",
            report.detail
        );
        assert!(report.plan.is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn desk_origins_parse_with_default_and_explicit_ports() {
        assert_eq!(
            parse_desk_endpoint("https://desk.example.com").unwrap(),
            DeskEndpoint {
                tls: true,
                host: "desk.example.com".to_owned(),
                port: 443,
            }
        );
        assert_eq!(
            parse_desk_endpoint("https://desk.example.com:8443").unwrap(),
            DeskEndpoint {
                tls: true,
                host: "desk.example.com".to_owned(),
                port: 8443,
            }
        );
        assert_eq!(
            parse_desk_endpoint("https://[::1]:8443").unwrap(),
            DeskEndpoint {
                tls: true,
                host: "::1".to_owned(),
                port: 8443,
            }
        );
    }

    #[test]
    fn plain_http_is_only_for_loopback_desks() {
        // A local desk (and the stub tests) speak plain HTTP on loopback,
        // where no network sits between client and desk.
        assert!(parse_desk_endpoint("http://127.0.0.1:8080").is_ok());
        assert!(parse_desk_endpoint("http://localhost:8080").is_ok());
        assert!(parse_desk_endpoint("http://[::1]:8080").is_ok());
        // Off loopback the token would cross a network in cleartext.
        let err = parse_desk_endpoint("http://desk.example.com").unwrap_err();
        assert!(err.to_string().contains("https://"), "{err}");
    }

    #[test]
    fn malformed_desk_origins_are_refused() {
        assert!(parse_desk_endpoint("ftp://desk.example.com").is_err());
        assert!(parse_desk_endpoint("desk.example.com").is_err());
        assert!(parse_desk_endpoint("https://").is_err());
        assert!(parse_desk_endpoint("https://desk.example.com/path").is_err());
        assert!(parse_desk_endpoint("https://desk.example.com:notaport").is_err());
        assert!(parse_desk_endpoint("https://user@desk.example.com").is_err());
    }

    /// RFC 4648 test vectors — the PEM decoder must not invent bytes.
    #[test]
    fn base64_decode_matches_the_rfc_vectors() {
        assert_eq!(base64_decode("").unwrap(), b"");
        assert_eq!(base64_decode("Zg==").unwrap(), b"f");
        assert_eq!(base64_decode("Zm8=").unwrap(), b"fo");
        assert_eq!(base64_decode("Zm9v").unwrap(), b"foo");
        assert_eq!(base64_decode("Zm9vYg==").unwrap(), b"foob");
        assert_eq!(base64_decode("Zm9vYmE=").unwrap(), b"fooba");
        assert_eq!(base64_decode("Zm9vYmFy").unwrap(), b"foobar");
        // PEM wraps its lines; whitespace is not data.
        assert_eq!(base64_decode("Zm9v\r\nYmFy").unwrap(), b"foobar");
        assert!(base64_decode("not base64!").is_none());
    }

    /// A PEM bundle yields one DER certificate per BEGIN/END pair.
    #[test]
    fn pem_certificates_extracts_each_block() {
        // "foobar" and "f" stand in for DER bodies; the extractor must not
        // care what the bytes are — the trust store parses them later.
        let pem = b"-----BEGIN CERTIFICATE-----\nZm9vYmFy\n-----END CERTIFICATE-----\n\
                    -----BEGIN CERTIFICATE-----\nZg==\n-----END CERTIFICATE-----\n";
        let certs = pem_certificates(pem);
        assert_eq!(certs.len(), 2);
        assert_eq!(certs[0].as_ref(), b"foobar");
        assert_eq!(certs[1].as_ref(), b"f");
    }
}
