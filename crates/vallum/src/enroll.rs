//! Token-gated enrolment over UDP, for machines that cannot SSH to the server.
//!
//! This is transport B on top of the same primitive as `--remote`: the client
//! generates its key locally, only its public line travels, and the server
//! hands back non-secret config. The difference is how the line arrives: not
//! SSH, but one sealed datagram on `listen + 1`.
//!
//! ```text
//! REQ = "VEN1" | client_nonce(24) | name_len(1) | name | seal(K_req, client_nonce, ad=name, pt=public_line)
//! RES = "VEN2" | server_nonce(24) | seal(K_res, server_nonce, ad=client_nonce, pt=status || "\n" || config)
//! ```
//!
//! The name is in the clear because the server cannot find the invite — and
//! therefore the token — without it. It is bound into the seal's associated
//! data, so a captured seal is useless under another name. The response's AD
//! is the request's nonce, which binds it to that request: a replayed or
//! substituted answer will not open.
//!
//! Failure modes are deliberately asymmetric: a bad tag is dropped silently
//! (the sender learns nothing), while post-auth failures — expired, used,
//! enrolment refused — are answered with a sealed `err` so a legitimate
//! client is told rather than left timing out.

use std::net::{IpAddr, UdpSocket};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use vallum_crypto::CryptoSuite;
use vallum_crypto_sdk::SdkSuite;

use crate::commands::peer::write_private;
use crate::error::Error;
use crate::say;

const REQ_MAGIC: &[u8; 4] = b"VEN1";
const RES_MAGIC: &[u8; 4] = b"VEN2";
const MAX_DATAGRAM: usize = 16384;
const MAX_NAME: usize = 32;
/// Requests per source IP per second; beyond that the source is dropped.
const RATE_PER_SECOND: u32 = 8;
/// How long an invite lives. One sitting: enough to walk to the other machine.
pub const INVITE_TTL_SECS: u64 = 15 * 60;

fn suite() -> SdkSuite {
    SdkSuite::tri_hybrid()
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// ---------------------------------------------------------------------------
// The token: 128 bits, shown as eight dashed groups so it can be read aloud.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Token([u8; 16]);

impl Token {
    pub fn generate() -> Self {
        let seed = crate::entropy::seed();
        let mut bytes = [0u8; 16];
        bytes.copy_from_slice(&seed[..16]);
        Self(bytes)
    }

    /// `xxxx-xxxx-…` or bare hex; dashes and spaces are ignored.
    pub fn parse(text: &str) -> Result<Self, Error> {
        let hex: String = text
            .chars()
            .filter(|c| !matches!(c, '-' | ' ' | '\t'))
            .collect();
        if hex.len() != 32 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(Error::Usage(
                "the token is eight groups of four characters, like `a1b2-c3d4-…`".to_owned(),
            ));
        }
        let bytes = crate::keys::hex_decode(&hex)
            .map_err(|_| Error::Usage("the token is not valid hex".to_owned()))?;
        let mut out = [0u8; 16];
        out.copy_from_slice(&bytes);
        Ok(Self(out))
    }

    pub fn display(&self) -> String {
        let hex = crate::keys::hex_encode(&self.0);
        hex.as_bytes()
            .chunks(4)
            .map(|chunk| std::str::from_utf8(chunk).unwrap_or("????").to_owned())
            .collect::<Vec<_>>()
            .join("-")
    }

    fn bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

// ---------------------------------------------------------------------------
// The invite: what `peer invite` writes and `enroll-serve` consumes.

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Invite {
    pub name: String,
    pub token_hex: String,
    pub expires: u64,
    /// The public line the invite was first spent on. An identical re-request
    /// is a retransmit and gets the stored answer again; a *different* line
    /// under the same token is refused — the invite is single-use.
    #[serde(default)]
    pub public_line: Option<String>,
    #[serde(default)]
    pub response: Option<String>,
}

impl Invite {
    fn token(&self) -> Result<Token, Error> {
        Token::parse(&self.token_hex)
    }
}

/// Where invites live. Runtime state, not config: they die with the machine,
/// which is the right behaviour for a 15-minute credential.
fn run_dir() -> PathBuf {
    std::env::var("VALLUM_RUN_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/run/vallum"))
}

pub fn invite_path(interface: &str, name: &str) -> PathBuf {
    run_dir().join(format!("enroll-{interface}-{name}.json"))
}

/// A name is a label, not a path: letters, digits, `-` and `_` only.
fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_NAME
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
}

// ---------------------------------------------------------------------------
// Keys: request and response get separate keys, both bound to the token and
// the nonces, so neither direction can be replayed into the other.

fn request_key(token: &Token, nonce: &[u8; 24]) -> Result<[u8; 32], Error> {
    let mut key = [0u8; 32];
    suite()
        .kdf(nonce, token.bytes(), b"vallum-enroll request", &mut key)
        .map_err(|error| Error::Usage(format!("enroll kdf: {error}")))?;
    Ok(key)
}

fn response_key(
    token: &Token,
    client_nonce: &[u8; 24],
    server_nonce: &[u8; 24],
) -> Result<[u8; 32], Error> {
    let mut salt = Vec::with_capacity(48);
    salt.extend_from_slice(client_nonce);
    salt.extend_from_slice(server_nonce);
    let mut key = [0u8; 32];
    suite()
        .kdf(&salt, token.bytes(), b"vallum-enroll response", &mut key)
        .map_err(|error| Error::Usage(format!("enroll kdf: {error}")))?;
    Ok(key)
}

// ---------------------------------------------------------------------------
// Wire format.

/// Build a request: `VEN1 | client_nonce | name_len | name | sealed line`.
pub fn encode_request(
    token: &Token,
    name: &str,
    public_line: &str,
    client_nonce: &[u8; 24],
) -> Result<Vec<u8>, Error> {
    if !valid_name(name) {
        return Err(Error::Usage(format!(
            "`{name}` is not a usable peer name (letters, digits, - _ .)"
        )));
    }
    let key = request_key(token, client_nonce)?;
    let sealed = suite()
        .aead_seal(&key, client_nonce, name.as_bytes(), public_line.as_bytes())
        .map_err(|error| Error::Usage(format!("enroll seal: {error}")))?;
    let mut out = Vec::with_capacity(4 + 24 + 1 + name.len() + sealed.len());
    out.extend_from_slice(REQ_MAGIC);
    out.extend_from_slice(client_nonce);
    out.push(name.len() as u8);
    out.extend_from_slice(name.as_bytes());
    out.extend_from_slice(&sealed);
    Ok(out)
}

/// What a request claims, once parsed but before the tag is verified.
#[derive(Debug)]
pub struct ParsedRequest {
    pub name: String,
    pub client_nonce: [u8; 24],
    /// The sealed remainder; only `open_request` can read it.
    sealed: Vec<u8>,
}

/// Parse the unsealed framing of a request. Cheap; no crypto yet.
pub fn parse_request(datagram: &[u8]) -> Option<ParsedRequest> {
    if datagram.len() < 4 + 24 + 1 || &datagram[..4] != REQ_MAGIC {
        return None;
    }
    let mut nonce = [0u8; 24];
    nonce.copy_from_slice(&datagram[4..28]);
    let name_len = datagram[28] as usize;
    if name_len == 0 || datagram.len() < 29 + name_len + 16 {
        return None;
    }
    let name = std::str::from_utf8(&datagram[29..29 + name_len])
        .ok()?
        .to_owned();
    if !valid_name(&name) {
        return None;
    }
    Some(ParsedRequest {
        name,
        client_nonce: nonce,
        sealed: datagram[29 + name_len..].to_vec(),
    })
}

/// Open the sealed line under the invite's token. `None` on a bad tag.
pub fn open_request(token: &Token, request: &ParsedRequest) -> Option<String> {
    let key = request_key(token, &request.client_nonce).ok()?;
    let open = suite()
        .aead_open(
            &key,
            &request.client_nonce,
            request.name.as_bytes(),
            &request.sealed,
        )
        .ok()?;
    String::from_utf8(open).ok()
}

/// Build a response: `VEN2 | server_nonce | sealed(status\nbody)`, bound to
/// the request's nonce via both the key's salt and the AD.
pub fn encode_response(
    token: &Token,
    client_nonce: &[u8; 24],
    server_nonce: &[u8; 24],
    status: &str,
    body: &str,
) -> Result<Vec<u8>, Error> {
    let key = response_key(token, client_nonce, server_nonce)?;
    let payload = format!("{status}\n{body}");
    let sealed = suite()
        .aead_seal(&key, server_nonce, client_nonce, payload.as_bytes())
        .map_err(|error| Error::Usage(format!("enroll seal: {error}")))?;
    let mut out = Vec::with_capacity(4 + 24 + sealed.len());
    out.extend_from_slice(RES_MAGIC);
    out.extend_from_slice(server_nonce);
    out.extend_from_slice(&sealed);
    Ok(out)
}

/// Open a response against the token and the request's nonce.
pub fn open_response(
    token: &Token,
    client_nonce: &[u8; 24],
    datagram: &[u8],
) -> Option<(String, String)> {
    if datagram.len() < 4 + 24 + 16 || &datagram[..4] != RES_MAGIC {
        return None;
    }
    let mut server_nonce = [0u8; 24];
    server_nonce.copy_from_slice(&datagram[4..28]);
    let key = response_key(token, client_nonce, &server_nonce).ok()?;
    let open = suite()
        .aead_open(&key, &server_nonce, client_nonce, &datagram[28..])
        .ok()?;
    let text = String::from_utf8(open).ok()?;
    let (status, body) = text.split_once('\n')?;
    Some((status.to_owned(), body.to_owned()))
}

// ---------------------------------------------------------------------------
// Server side: `peer invite` writes, `enroll-serve` serves.

/// Mint an invite and write it where `enroll-serve` will find it.
pub fn issue_invite(interface: &str, name: &str, ttl_secs: u64) -> Result<(Token, PathBuf), Error> {
    if !valid_name(name) {
        return Err(Error::Usage(format!(
            "`{name}` is not a usable peer name (letters, digits, - _ .)"
        )));
    }
    let token = Token::generate();
    let invite = Invite {
        name: name.to_owned(),
        token_hex: crate::keys::hex_encode(token.bytes()),
        expires: unix_now() + ttl_secs,
        public_line: None,
        response: None,
    };
    let dir = run_dir();
    std::fs::create_dir_all(&dir).map_err(|source| Error::IoPath {
        action: "create the invite directory",
        path: dir.clone(),
        source,
    })?;
    let path = invite_path(interface, name);
    write_private(
        &path,
        serde_json::to_vec_pretty(&invite)
            .map_err(|error| Error::Usage(format!("invite: {error}")))?
            .as_slice(),
    )?;
    Ok((token, path))
}

fn load_invite(interface: &str, name: &str) -> Option<Invite> {
    let path = invite_path(interface, name);
    let bytes = std::fs::read(&path).ok()?;
    serde_json::from_slice(&bytes).ok()
}

fn store_invite(interface: &str, invite: &Invite) -> Result<(), Error> {
    let path = invite_path(interface, &invite.name);
    write_private(
        &path,
        serde_json::to_vec_pretty(invite)
            .map_err(|error| Error::Usage(format!("invite: {error}")))?
            .as_slice(),
    )
}

/// Remove an invite (after `peer remove`, or manual revocation).
pub fn revoke_invite(interface: &str, name: &str) {
    let _ = std::fs::remove_file(invite_path(interface, name));
}

/// Per-source-IP admission: a token check is cheap but not free, and there is
/// no reason to do more than a handful per second for any one address.
struct RateLimit {
    window_start: Instant,
    counts: std::collections::HashMap<IpAddr, u32>,
}

impl RateLimit {
    fn new() -> Self {
        Self {
            window_start: Instant::now(),
            counts: std::collections::HashMap::new(),
        }
    }

    fn admit(&mut self, source: IpAddr) -> bool {
        if self.window_start.elapsed() >= Duration::from_secs(1) {
            self.counts.clear();
            self.window_start = Instant::now();
        }
        let count = self.counts.entry(source).or_insert(0);
        *count += 1;
        *count <= RATE_PER_SECOND
    }
}

/// The responder: bind `enroll.port` (default `listen + 1`), answer sealed
/// requests by invoking `peer enroll`, and drop everything else quietly.
///
/// This is a separate process rather than a daemon socket because the daemon
/// runs with `ProtectSystem=strict` and dropped capabilities — it cannot and
/// should not write `/etc/vallum`. The responder runs as root under its own
/// unit, off unless `[enroll] enabled = true`.
pub fn serve(config_path: &Path) -> Result<(), Error> {
    let config = vallum_config::Config::load(config_path)?;
    let enroll = config.enroll.clone();
    if !enroll.enabled {
        return Err(Error::Usage(
            "[enroll] is not enabled in this config; set `enabled = true`".to_owned(),
        ));
    }
    let listen = config
        .interface
        .listen
        .as_deref()
        .and_then(|listen| {
            listen
                .rsplit_once(':')
                .and_then(|(_, port)| port.parse::<u16>().ok())
        })
        .unwrap_or(51820);
    let port = enroll.port.unwrap_or_else(|| listen.saturating_add(1));
    let interface = config
        .interface
        .name
        .clone()
        .unwrap_or_else(|| "vallum0".to_owned());
    let binary = std::env::var("VALLUM_BIN").unwrap_or_else(|_| "vallum".to_owned());

    let socket = UdpSocket::bind(("0.0.0.0", port)).map_err(|source| Error::IoPath {
        action: "bind the enrolment port",
        path: PathBuf::from(format!("0.0.0.0:{port}")),
        source,
    })?;
    say!("enrolment on :{port} (interface {interface})");

    let mut limit = RateLimit::new();
    let mut buf = vec![0u8; MAX_DATAGRAM];
    loop {
        let Ok((size, source)) = socket.recv_from(&mut buf) else {
            continue;
        };
        if !limit.admit(source.ip()) {
            continue;
        }
        let Some(request) = parse_request(&buf[..size]) else {
            continue; // not for us, or malformed: silently
        };
        let Some(invite) = load_invite(&interface, &request.name) else {
            continue; // no such invite: silently
        };
        let Ok(token) = invite.token() else {
            continue;
        };
        let Some(line) = open_request(&token, &request) else {
            continue; // wrong token or tampered: silently
        };
        let server_nonce = crate::entropy::seed()[..24]
            .try_into()
            .map_err(|_| Error::Usage("nonce".to_owned()))?;
        let answer = answer_request(&invite, &request.name, &line, config_path, &binary);
        let issued = matches!(&answer, Answer::Issued(_));
        match answer {
            Answer::Reuse(response) | Answer::Issued(response) => {
                if let Ok(datagram) = encode_response(
                    &token,
                    &request.client_nonce,
                    &server_nonce,
                    "ok",
                    &response,
                ) {
                    let _ = socket.send_to(&datagram, source);
                }
                if issued {
                    let mut spent = invite.clone();
                    spent.public_line = Some(line);
                    spent.response = Some(response);
                    let _ = store_invite(&interface, &spent);
                    eprintln!(
                        "vallum: enrolled `{}` for {} (token enrolment)",
                        request.name,
                        source.ip()
                    );
                }
            }
            Answer::Refused(message) => {
                if let Ok(datagram) = encode_response(
                    &token,
                    &request.client_nonce,
                    &server_nonce,
                    "err",
                    &message,
                ) {
                    let _ = socket.send_to(&datagram, source);
                }
            }
        }
    }
}

enum Answer {
    /// The same request again: re-send the stored answer.
    Reuse(String),
    /// A new enrolment: the config `peer enroll` produced.
    Issued(String),
    /// A sealed, honest refusal.
    Refused(String),
}

fn answer_request(
    invite: &Invite,
    name: &str,
    line: &str,
    config_path: &Path,
    binary: &str,
) -> Answer {
    if invite.expires < unix_now() {
        return Answer::Refused("this invite has expired; ask the server for a new one".into());
    }
    match (&invite.public_line, &invite.response) {
        (Some(old), Some(response)) if old == line => return Answer::Reuse(response.clone()),
        (Some(_), _) => {
            return Answer::Refused("this invite was already used with a different key".to_owned())
        }
        _ => {}
    }
    let mut child = match std::process::Command::new(binary)
        .args([
            "peer",
            "enroll",
            name,
            "--config",
            &config_path.to_string_lossy(),
            "--public-key-file",
            "/dev/stdin",
            "--json",
        ])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
    {
        Ok(child) => child,
        Err(error) => return Answer::Refused(format!("could not enrol: {error}")),
    };
    use std::io::Write as _;
    if let Some(stdin) = child.stdin.as_mut() {
        let _ = stdin.write_all(line.as_bytes());
    }
    let Ok(output) = child.wait_with_output() else {
        return Answer::Refused("could not enrol".to_owned());
    };
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Answer::Refused(format!("the server refused: {}", stderr.trim()));
    }
    let Ok(report) = serde_json::from_slice::<serde_json::Value>(&output.stdout) else {
        return Answer::Refused("the server's answer was malformed".to_owned());
    };
    match report.get("config").and_then(|config| config.as_str()) {
        Some(config) => Answer::Issued(config.to_owned()),
        None => Answer::Refused("the server's answer had no config".to_owned()),
    }
}

// ---------------------------------------------------------------------------
// Client side: send a request, wait for the sealed answer.

/// Ask `server` (a `host:port` string) to enrol `name` with `public_line`,
/// returning the config the server hands back.
pub fn join(server: &str, token: &Token, name: &str, public_line: &str) -> Result<String, Error> {
    let socket = UdpSocket::bind("0.0.0.0:0").map_err(|source| Error::IoPath {
        action: "bind",
        path: PathBuf::from("0.0.0.0:0"),
        source,
    })?;
    socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .map_err(|error| Error::Usage(format!("socket: {error}")))?;

    let client_nonce = crate::entropy::seed()[..24]
        .try_into()
        .map_err(|_| Error::Usage("nonce".to_owned()))?;
    let request = encode_request(token, name, public_line, &client_nonce)?;

    let mut buf = vec![0u8; MAX_DATAGRAM];
    let mut last_error = None;
    for _attempt in 0..3 {
        if socket.send_to(&request, server).is_err() {
            last_error = Some("could not reach the server".to_owned());
            continue;
        }
        match socket.recv_from(&mut buf) {
            Ok((size, _)) => {
                match open_response(token, &client_nonce, &buf[..size]) {
                    Some((status, body)) if status == "ok" => return Ok(body),
                    Some((_, body)) => {
                        return Err(Error::Usage(format!("the server refused: {body}")))
                    }
                    // Not ours, or not for this request: keep waiting.
                    None => continue,
                }
            }
            Err(_) => last_error = Some("timed out".to_owned()),
        }
    }
    Err(Error::Usage(format!(
        "no answer from {server}: {}. Is the invite still valid, and was it \
         made for `{name}`?",
        last_error.unwrap_or_else(|| "no response".to_owned())
    )))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn nonce(byte: u8) -> [u8; 24] {
        [byte; 24]
    }

    #[test]
    fn a_request_opens_for_the_right_token_and_no_other() {
        let token = Token::generate();
        let wrong = Token::generate();
        let client_nonce = nonce(1);
        let datagram = encode_request(&token, "laptop", "vallum1:0003:aa", &client_nonce).unwrap();
        let parsed = parse_request(&datagram).unwrap();
        assert_eq!(parsed.name, "laptop");
        assert_eq!(
            open_request(&token, &parsed).as_deref(),
            Some("vallum1:0003:aa")
        );
        assert!(open_request(&wrong, &parsed).is_none());
    }

    #[test]
    fn a_seal_copied_to_another_name_fails() {
        let token = Token::generate();
        let client_nonce = nonce(2);
        let datagram = encode_request(&token, "laptop", "line", &client_nonce).unwrap();
        // Re-frame the same seal under a different name.
        let mut forged = Vec::new();
        forged.extend_from_slice(REQ_MAGIC);
        forged.extend_from_slice(&datagram[4..28]);
        forged.push(4);
        forged.extend_from_slice(b"eved");
        forged.extend_from_slice(&datagram[29 + 6..]);
        let parsed = parse_request(&forged).unwrap();
        assert!(open_request(&token, &parsed).is_none());
    }

    #[test]
    fn a_response_is_bound_to_its_request() {
        let token = Token::generate();
        let client_nonce = nonce(3);
        let server_nonce = nonce(4);
        let datagram =
            encode_response(&token, &client_nonce, &server_nonce, "ok", "[interface]").unwrap();
        assert_eq!(
            open_response(&token, &client_nonce, &datagram),
            Some(("ok".to_owned(), "[interface]".to_owned()))
        );
        // A different request nonce — a replay into another conversation.
        assert!(open_response(&token, &nonce(9), &datagram).is_none());
        // A wrong token.
        assert!(open_response(&Token::generate(), &client_nonce, &datagram).is_none());
    }

    #[test]
    fn malformed_datagrams_are_dropped_not_parsed() {
        assert!(parse_request(b"").is_none());
        assert!(parse_request(b"VEN1").is_none());
        assert!(parse_request(&b"NOPE.....................".repeat(4)).is_none());
        // The magic alone, with a garbage body.
        let mut bad = b"VEN1".to_vec();
        bad.extend_from_slice(&[0xff; 100]);
        assert!(parse_request(&bad).is_none());
    }

    #[test]
    fn a_token_survives_display_and_parse() {
        let token = Token::generate();
        assert_eq!(Token::parse(&token.display()).unwrap(), token);
        assert!(Token::parse("not a token").is_err());
    }

    #[test]
    fn a_name_with_path_characters_is_rejected() {
        let token = Token::generate();
        assert!(encode_request(&token, "../etc", "line", &nonce(0)).is_err());
        assert!(!valid_name("a/b"));
        assert!(!valid_name(""));
        assert!(valid_name("laptop-1.home"));
    }
}
