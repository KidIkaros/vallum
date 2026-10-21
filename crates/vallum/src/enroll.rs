//! Token-gated enrolment over UDP, for machines that cannot SSH to the server.
//!
//! This is transport B on top of the same primitive as `--remote`: the client
//! generates its key locally, only its public line travels, and the server
//! hands back non-secret config. The difference is how the line arrives: not
//! SSH, but a sealed exchange on `listen + 1`.
//!
//! The exchange has the same shape as the tunnel handshake — see
//! `docs/adr/0015-enrolment-v2.md` and Algorithm 2 of *Post-quantum
//! WireGuard* (Hülsing, Ning, Schwabe, Weber, Zimmermann, 2023):
//!
//! ```text
//! HELLO  = VEN2 | 0x01 | flags | invite_id(16) | client_nonce(24) | epk | line | [cookie(16)] | tag(32)
//! COOKIE = VEN2 | 0x02 | cookie(16)
//! REPLY  = VEN2 | 0x03 | server_nonce(24) | ct | sealed(status ‖ payload)
//! ```
//!
//! - The **invite id** replaces the peer name on the wire: the server needs a
//!   lookup key, and an opaque one leaks nothing. The AEAD's AD binds the seal
//!   to it, so a captured seal fails under another id.
//! - The **cookie** is the paper's `m2`: issued for the source address before
//!   any invite lookup or KEM work, so a spoofed source never gets past it.
//! - The **admission tag** is the paper's `m1` role, keyed by the token (the
//!   client has no static key yet): one KDF, no filesystem, no KEM.
//! - The **reply key** is `KDF(salt = nonces, ikm = frame(token, ss))` — the
//!   paper's `KDF1(σ, r)` with σ = token and r = the ephemeral shared secret.
//!   That buys forward secrecy *and* MEX resistance: after the exchange `ss` is
//!   gone, so a later token compromise opens nothing; and a subverted client
//!   RNG leaves the attacker without the token.
//!
//! Failure modes stay asymmetric: a bad cookie, tag or invite id is dropped
//! silently (the sender learns nothing), while post-auth failures — expired,
//! pinned to another key, spent on another key, enrolment refused — are
//! answered with a sealed `err` so a legitimate client is told.

use std::net::{IpAddr, UdpSocket};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use vallum_core::cookie::{CookieSecret, COOKIE_ROTATION_SECONDS, COOKIE_SIZE};
use vallum_crypto::{frame, CryptoSuite, KemPublicKey, KemRole};
use vallum_crypto_sdk::SdkSuite;

use crate::commands::peer::write_private;
use crate::error::Error;
use crate::say;

const MAGIC: &[u8; 4] = b"VEN2";
const TYPE_HELLO: u8 = 0x01;
const TYPE_COOKIE: u8 = 0x02;
const TYPE_REPLY: u8 = 0x03;

const ID_LEN: usize = 16;
const NONCE_LEN: usize = 24;
const TAG_LEN: usize = 32;
/// `HELLO` flag: a cookie is present.
const FLAG_COOKIE: u8 = 0x01;

const MAX_DATAGRAM: usize = 16384;
const MAX_NAME: usize = 32;
/// Requests per source IP per second; beyond that the source is dropped.
const RATE_PER_SECOND: u32 = 8;
/// How long an invite lives. One sitting: enough to walk to the other machine.
pub const INVITE_TTL_SECS: u64 = 15 * 60;

const ADMISSION_INFO: &[u8] = b"vallum-enroll/v2/admission";
const REPLY_INFO: &[u8] = b"vallum-enroll/v2/reply";
const INVITE_VERSION: u32 = 2;

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
    pub version: u32,
    /// The opaque lookup key that travels on the wire instead of the name.
    pub id: String,
    pub name: String,
    pub token_hex: String,
    pub expires: u64,
    /// When set, the invite only enrols this public line — a stolen token is
    /// then useless without the private key that line belongs to.
    #[serde(default)]
    pub expect_public_line: Option<String>,
    /// The line the invite was first spent on, and the config it produced, so
    /// a retransmit re-seals the same answer under a fresh ephemeral key.
    #[serde(default)]
    pub public_line: Option<String>,
    #[serde(default)]
    pub config: Option<String>,
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

pub fn invite_path(interface: &str, id: &str) -> PathBuf {
    run_dir().join(format!("enroll-{interface}-{id}.json"))
}

/// A name is a label, not a path: letters, digits, `-` and `_` only.
fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_NAME
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
}

/// An invite id is 32 hex characters — never a path.
fn valid_id(id: &str) -> bool {
    id.len() == ID_LEN * 2 && id.chars().all(|c| c.is_ascii_hexdigit())
}

// ---------------------------------------------------------------------------
// Keys.

/// The key that authenticates a `HELLO`: derived from the token alone, so the
/// server can reject a request before reading the invite body or running a KEM.
fn admission_key(token: &Token) -> Result<[u8; 32], Error> {
    let mut key = [0u8; 32];
    suite()
        .kdf(
            b"vallum-enroll/v2/admission/salt",
            token.bytes(),
            ADMISSION_INFO,
            &mut key,
        )
        .map_err(|error| Error::Usage(format!("enroll kdf: {error}")))?;
    Ok(key)
}

/// The admission tag over everything that precedes it.
fn admission_tag(key: &[u8; 32], input: &[u8]) -> Result<[u8; TAG_LEN], Error> {
    let mut tag = [0u8; TAG_LEN];
    suite()
        .kdf(key, input, ADMISSION_INFO, &mut tag)
        .map_err(|error| Error::Usage(format!("enroll kdf: {error}")))?;
    Ok(tag)
}

/// The reply key: `KDF1(σ = token, r = ephemeral shared secret)`.
fn reply_key(
    token: &Token,
    shared: &[u8],
    client_nonce: &[u8; NONCE_LEN],
    server_nonce: &[u8; NONCE_LEN],
) -> Result<[u8; 32], Error> {
    let mut salt = Vec::with_capacity(NONCE_LEN * 2);
    salt.extend_from_slice(client_nonce);
    salt.extend_from_slice(server_nonce);
    let combined = frame(&[token.bytes(), shared]);
    let mut key = [0u8; 32];
    suite()
        .kdf(&salt, &combined, REPLY_INFO, &mut key)
        .map_err(|error| Error::Usage(format!("enroll kdf: {error}")))?;
    Ok(key)
}

/// Combine the suite's per-leg secrets into one, as the handshake does.
fn combine_legs(legs: &[vallum_crypto::SharedSecret]) -> Vec<u8> {
    let parts: Vec<&[u8]> = legs.iter().map(|leg| leg.as_bytes() as &[u8]).collect();
    frame(&parts)
}

// ---------------------------------------------------------------------------
// Wire format.

/// A parsed `HELLO`, before any cryptographic check.
#[derive(Debug)]
pub struct Hello {
    pub id: String,
    pub client_nonce: [u8; NONCE_LEN],
    pub ephemeral_pk: Vec<u8>,
    pub public_line: String,
    pub cookie: Option<[u8; COOKIE_SIZE]>,
    /// Everything before the tag — what the admission tag covers.
    tag_input: Vec<u8>,
    tag: [u8; TAG_LEN],
}

/// Build a `HELLO`. `cookie` is `None` on the first attempt.
pub fn encode_hello(
    invite_id: &str,
    client_nonce: &[u8; NONCE_LEN],
    ephemeral_pk: &[u8],
    public_line: &str,
    cookie: Option<&[u8; COOKIE_SIZE]>,
    token: &Token,
) -> Result<Vec<u8>, Error> {
    if !valid_id(invite_id) {
        return Err(Error::Usage("that is not an invite id".to_owned()));
    }
    if public_line.len() > MAX_DATAGRAM {
        return Err(Error::Usage("the public line is too long".to_owned()));
    }
    let mut out = Vec::with_capacity(4 + 1 + 1 + ID_LEN + NONCE_LEN + ephemeral_pk.len() + 64);
    out.extend_from_slice(MAGIC);
    out.push(TYPE_HELLO);
    out.push(if cookie.is_some() { FLAG_COOKIE } else { 0 });
    out.extend_from_slice(
        &crate::keys::hex_decode(invite_id)
            .map_err(|_| Error::Usage("that is not an invite id".to_owned()))?,
    );
    out.extend_from_slice(client_nonce);
    out.extend_from_slice(&(ephemeral_pk.len() as u16).to_be_bytes());
    out.extend_from_slice(ephemeral_pk);
    out.extend_from_slice(&(public_line.len() as u16).to_be_bytes());
    out.extend_from_slice(public_line.as_bytes());
    if let Some(cookie) = cookie {
        out.extend_from_slice(cookie);
    }
    let key = admission_key(token)?;
    let tag = admission_tag(&key, &out)?;
    out.extend_from_slice(&tag);
    Ok(out)
}

/// Parse a datagram's framing. Cheap: no crypto, no allocation beyond copies.
pub fn parse_hello(datagram: &[u8]) -> Option<Hello> {
    if datagram.len() < 4 + 2 + ID_LEN + NONCE_LEN + 2 || &datagram[..4] != MAGIC {
        return None;
    }
    if datagram[4] != TYPE_HELLO {
        return None;
    }
    let flags = datagram[5];
    let has_cookie = flags & FLAG_COOKIE != 0;
    let mut offset = 6;
    let id = crate::keys::hex_encode(datagram.get(offset..offset + ID_LEN)?);
    offset += ID_LEN;
    let mut client_nonce = [0u8; NONCE_LEN];
    client_nonce.copy_from_slice(datagram.get(offset..offset + NONCE_LEN)?);
    offset += NONCE_LEN;
    let pk_len = u16::from_be_bytes(datagram.get(offset..offset + 2)?.try_into().ok()?) as usize;
    offset += 2;
    let ephemeral_pk = datagram.get(offset..offset + pk_len)?.to_vec();
    offset += pk_len;
    let line_len = u16::from_be_bytes(datagram.get(offset..offset + 2)?.try_into().ok()?) as usize;
    offset += 2;
    let public_line = std::str::from_utf8(datagram.get(offset..offset + line_len)?)
        .ok()?
        .to_owned();
    offset += line_len;
    let cookie = if has_cookie {
        let bytes = datagram.get(offset..offset + COOKIE_SIZE)?;
        offset += COOKIE_SIZE;
        let mut cookie = [0u8; COOKIE_SIZE];
        cookie.copy_from_slice(bytes);
        Some(cookie)
    } else {
        None
    };
    if datagram.len() != offset + TAG_LEN {
        return None;
    }
    let mut tag = [0u8; TAG_LEN];
    tag.copy_from_slice(&datagram[offset..]);
    Some(Hello {
        id,
        client_nonce,
        ephemeral_pk,
        public_line,
        cookie,
        tag_input: datagram[..offset].to_vec(),
        tag,
    })
}

/// Verify the admission tag. `false` means "not a token holder": drop it.
pub fn verify_hello(token: &Token, hello: &Hello) -> bool {
    let Ok(key) = admission_key(token) else {
        return false;
    };
    let Ok(expected) = admission_tag(&key, &hello.tag_input) else {
        return false;
    };
    constant_time_eq(&expected, &hello.tag)
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0u8, |acc, (a, b)| acc | (a ^ b))
        == 0
}

pub fn encode_cookie(cookie: &[u8; COOKIE_SIZE]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + 1 + COOKIE_SIZE);
    out.extend_from_slice(MAGIC);
    out.push(TYPE_COOKIE);
    out.extend_from_slice(cookie);
    out
}

pub fn parse_cookie(datagram: &[u8]) -> Option<[u8; COOKIE_SIZE]> {
    if datagram.len() != 4 + 1 + COOKIE_SIZE || &datagram[..4] != MAGIC {
        return None;
    }
    if datagram[4] != TYPE_COOKIE {
        return None;
    }
    let mut cookie = [0u8; COOKIE_SIZE];
    cookie.copy_from_slice(&datagram[5..]);
    Some(cookie)
}

/// Build the sealed reply: `ct` carries the ephemeral shared secret.
pub fn encode_reply(
    token: &Token,
    hello: &Hello,
    ciphertext: &[u8],
    shared: &[u8],
    server_nonce: &[u8; NONCE_LEN],
    status: &str,
    body: &str,
) -> Result<Vec<u8>, Error> {
    let key = reply_key(token, shared, &hello.client_nonce, server_nonce)?;
    let payload = format!("{status}\n{body}");
    let mut ad = Vec::with_capacity(ID_LEN + NONCE_LEN);
    ad.extend_from_slice(
        &crate::keys::hex_decode(&hello.id)
            .map_err(|_| Error::Usage("bad invite id".to_owned()))?,
    );
    ad.extend_from_slice(&hello.client_nonce);
    let sealed = suite()
        .aead_seal(&key, server_nonce, &ad, payload.as_bytes())
        .map_err(|error| Error::Usage(format!("enroll seal: {error}")))?;
    let mut out = Vec::with_capacity(4 + 1 + NONCE_LEN + 2 + ciphertext.len() + sealed.len());
    out.extend_from_slice(MAGIC);
    out.push(TYPE_REPLY);
    out.extend_from_slice(server_nonce);
    out.extend_from_slice(&(ciphertext.len() as u16).to_be_bytes());
    out.extend_from_slice(ciphertext);
    out.extend_from_slice(&sealed);
    Ok(out)
}

/// Open a reply against the token and the ephemeral secret the client kept.
pub fn open_reply(
    token: &Token,
    invite_id: &str,
    client_nonce: &[u8; NONCE_LEN],
    ephemeral_sk: &vallum_crypto::KemSecretKey,
    datagram: &[u8],
) -> Option<(String, String)> {
    if datagram.len() < 4 + 1 + NONCE_LEN + 2 || &datagram[..4] != MAGIC {
        return None;
    }
    if datagram[4] != TYPE_REPLY {
        return None;
    }
    let mut server_nonce = [0u8; NONCE_LEN];
    server_nonce.copy_from_slice(datagram.get(5..5 + NONCE_LEN)?);
    let mut offset = 5 + NONCE_LEN;
    let ct_len = u16::from_be_bytes(datagram.get(offset..offset + 2)?.try_into().ok()?) as usize;
    offset += 2;
    let ciphertext = datagram.get(offset..offset + ct_len)?;
    offset += ct_len;
    let sealed = datagram.get(offset..)?;
    let legs = suite().kem_decaps(ephemeral_sk, ciphertext).ok()?;
    let shared = combine_legs(&legs);
    let key = reply_key(token, &shared, client_nonce, &server_nonce).ok()?;
    let mut ad = Vec::with_capacity(ID_LEN + NONCE_LEN);
    ad.extend_from_slice(&crate::keys::hex_decode(invite_id).ok()?);
    ad.extend_from_slice(client_nonce);
    let open = suite().aead_open(&key, &server_nonce, &ad, sealed).ok()?;
    let text = String::from_utf8(open).ok()?;
    let (status, body) = text.split_once('\n')?;
    Some((status.to_owned(), body.to_owned()))
}

// ---------------------------------------------------------------------------
// Server side: `peer invite` writes, `enroll-serve` serves.

/// Mint an invite and write it where `enroll-serve` will find it.
pub fn issue_invite(
    interface: &str,
    name: &str,
    ttl_secs: u64,
    expect_public_line: Option<String>,
) -> Result<(Token, String, PathBuf), Error> {
    if !valid_name(name) {
        return Err(Error::Usage(format!(
            "`{name}` is not a usable peer name (letters, digits, - _ .)"
        )));
    }
    let token = Token::generate();
    let id = crate::keys::hex_encode(&crate::entropy::seed()[..ID_LEN]);
    let invite = Invite {
        version: INVITE_VERSION,
        id: id.clone(),
        name: name.to_owned(),
        token_hex: crate::keys::hex_encode(token.bytes()),
        expires: unix_now() + ttl_secs,
        expect_public_line,
        public_line: None,
        config: None,
    };
    let dir = run_dir();
    std::fs::create_dir_all(&dir).map_err(|source| Error::IoPath {
        action: "create the invite directory",
        path: dir.clone(),
        source,
    })?;
    let path = invite_path(interface, &id);
    write_private(
        &path,
        serde_json::to_vec_pretty(&invite)
            .map_err(|error| Error::Usage(format!("invite: {error}")))?
            .as_slice(),
    )?;
    Ok((token, id, path))
}

fn load_invite(interface: &str, id: &str) -> Option<Invite> {
    if !valid_id(id) {
        return None;
    }
    let bytes = std::fs::read(invite_path(interface, id)).ok()?;
    serde_json::from_slice(&bytes).ok()
}

fn store_invite(interface: &str, invite: &Invite) -> Result<(), Error> {
    let path = invite_path(interface, &invite.id);
    write_private(
        &path,
        serde_json::to_vec_pretty(invite)
            .map_err(|error| Error::Usage(format!("invite: {error}")))?
            .as_slice(),
    )
}

/// Remove every live invite for a peer name (after `peer remove`).
pub fn revoke_invite(interface: &str, name: &str) {
    let dir = run_dir();
    let prefix = format!("enroll-{interface}-");
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return;
    };
    for entry in entries.flatten() {
        let file_name = entry.file_name();
        let Some(file_name) = file_name.to_str() else {
            continue;
        };
        if !file_name.starts_with(&prefix) || !file_name.ends_with(".json") {
            continue;
        }
        let Ok(bytes) = std::fs::read(entry.path()) else {
            continue;
        };
        if let Ok(invite) = serde_json::from_slice::<Invite>(&bytes) {
            if invite.name == name {
                let _ = std::fs::remove_file(entry.path());
            }
        }
    }
}

/// Per-source-IP admission: the cookie already stops spoofing, but a real
/// source should not get unlimited work either.
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

/// The responder: bind `enroll.port` (default `listen + 1`) and answer sealed
/// requests. Off unless `[enroll] enabled = true`.
///
/// This is a separate process rather than a daemon socket because the daemon
/// runs with `ProtectSystem=strict` and dropped capabilities — it cannot and
/// should not write `/etc/vallum`.
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

    let socket = UdpSocket::bind(("0.0.0.0", port)).map_err(|source| Error::IoPath {
        action: "bind the enrolment port",
        path: PathBuf::from(format!("0.0.0.0:{port}")),
        source,
    })?;
    // A timeout so the cookie secret can rotate on schedule.
    socket
        .set_read_timeout(Some(Duration::from_secs(1)))
        .map_err(|error| Error::Usage(format!("socket: {error}")))?;
    say!("enrolment on :{port} (interface {interface})");

    let mut cookies = CookieSecret::new(&crate::entropy::seed());
    let mut rotated = Instant::now();
    let mut limit = RateLimit::new();
    let mut buf = vec![0u8; MAX_DATAGRAM];
    loop {
        if rotated.elapsed().as_secs() >= COOKIE_ROTATION_SECONDS {
            cookies.rotate(&crate::entropy::seed());
            rotated = Instant::now();
        }
        let Ok((size, source)) = socket.recv_from(&mut buf) else {
            continue; // timeout: rotate and listen again
        };
        if !limit.admit(source.ip()) {
            continue;
        }
        let Some(hello) = parse_hello(&buf[..size]) else {
            continue; // not for us, or malformed
        };
        // The cookie gate: before any invite lookup, any filesystem access, or
        // any KEM work. A spoofed source cannot receive it.
        let expected_cookie = cookies
            .cookie(&suite(), &source_key(source.ip()))
            .unwrap_or([0u8; COOKIE_SIZE]);
        match hello.cookie {
            Some(cookie) if constant_time_eq(&cookie, &expected_cookie) => {}
            _ => {
                let _ = socket.send_to(&encode_cookie(&expected_cookie), source);
                continue;
            }
        }
        let Some(invite) = load_invite(&interface, &hello.id) else {
            continue; // no such invite: silently
        };
        let Ok(token) = invite.token() else {
            continue;
        };
        if !verify_hello(&token, &hello) {
            continue; // wrong token or tampered: silently
        }

        // Post-auth: a refusal here can be sealed, so say why.
        let refusal = |status: &str, body: &str| -> Option<Vec<u8>> {
            let ciphertext = ephemeral_answer(&hello, &[]).ok()?;
            encode_reply(
                &token,
                &hello,
                &ciphertext.0,
                &ciphertext.1,
                &server_nonce(),
                status,
                body,
            )
            .ok()
        };

        if invite.expires < unix_now() {
            if let Some(datagram) = refusal(
                "err",
                "this invite has expired; ask the server for a new one",
            ) {
                let _ = socket.send_to(&datagram, source);
            }
            continue;
        }
        if let Some(expected) = &invite.expect_public_line {
            if !constant_time_eq(expected.as_bytes(), hello.public_line.as_bytes()) {
                if let Some(datagram) = refusal("err", "this invite is bound to a different key") {
                    let _ = socket.send_to(&datagram, source);
                }
                continue;
            }
        }
        if let (Some(old), Some(config)) = (&invite.public_line, &invite.config) {
            if !constant_time_eq(old.as_bytes(), hello.public_line.as_bytes()) {
                if let Some(datagram) =
                    refusal("err", "this invite was already used with a different key")
                {
                    let _ = socket.send_to(&datagram, source);
                }
                continue;
            }
            // A retransmit: re-seal the stored config under a fresh key.
            if let Some(datagram) = refusal("ok", config) {
                let _ = socket.send_to(&datagram, source);
            }
            continue;
        }

        // A real enrolment: one encapsulation, now that the sender has proven
        // it can receive at this address and holds the token.
        let Ok((ciphertext, shared)) = ephemeral_answer(&hello, &[]) else {
            continue;
        };
        match crate::commands::peer::enroll_report(&crate::commands::peer::EnrollArgs {
            name: invite.name.clone(),
            config: config_path.to_path_buf(),
            public_key: Some(hello.public_line.clone()),
            public_key_file: None,
            address: None,
            keepalive: None,
            no_apply: false,
            json: true,
        }) {
            Ok(report) => {
                let Ok(json) = serde_json::to_string(&report) else {
                    continue;
                };
                if let Ok(datagram) = encode_reply(
                    &token,
                    &hello,
                    &ciphertext,
                    &shared,
                    &server_nonce(),
                    "ok",
                    &json,
                ) {
                    let _ = socket.send_to(&datagram, source);
                }
                let mut spent = invite.clone();
                spent.public_line = Some(hello.public_line.clone());
                spent.config = Some(json);
                let _ = store_invite(&interface, &spent);
                eprintln!(
                    "vallum: enrolled `{}` for {} (token enrolment)",
                    invite.name,
                    source.ip()
                );
            }
            Err(error) => {
                if let Ok(datagram) = encode_reply(
                    &token,
                    &hello,
                    &ciphertext,
                    &shared,
                    &server_nonce(),
                    "err",
                    &format!("the server refused: {error}"),
                ) {
                    let _ = socket.send_to(&datagram, source);
                }
            }
        }
    }
}

/// What identifies a sender for cookie purposes: the address bytes, which two
/// senders can never share.
fn source_key(ip: IpAddr) -> Vec<u8> {
    match ip {
        IpAddr::V4(v4) => v4.octets().to_vec(),
        IpAddr::V6(v6) => v6.octets().to_vec(),
    }
}

fn server_nonce() -> [u8; NONCE_LEN] {
    let seed = crate::entropy::seed();
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&seed[..NONCE_LEN]);
    nonce
}

/// Encapsulate to the client's ephemeral key, returning `(ciphertext, shared)`.
fn ephemeral_answer(hello: &Hello, _unused: &[u8]) -> Result<(Vec<u8>, Vec<u8>), Error> {
    let suite = suite();
    let pk = KemPublicKey::new(hello.ephemeral_pk.clone());
    let encapsulation = suite
        .kem_encaps(&pk, &crate::entropy::seed())
        .map_err(|error| Error::Usage(format!("enroll encaps: {error}")))?;
    Ok((
        encapsulation.ciphertext.as_bytes().to_vec(),
        combine_legs(&encapsulation.shared_secrets),
    ))
}

// ---------------------------------------------------------------------------
// Client side: two round trips, then the answer.

/// Ask `server` (a `host:port` string) to enrol `name` with `public_line`.
///
/// Returns the JSON report the server produced, or an error explaining why not.
pub fn join(
    server: &str,
    token: &Token,
    invite_id: &str,
    name: &str,
    public_line: &str,
) -> Result<String, Error> {
    if !valid_id(invite_id) {
        return Err(Error::Usage(
            "--invite-id must be the 32 hex characters `vallum peer invite` printed".to_owned(),
        ));
    }
    let invite_id = invite_id.to_owned();
    let socket = UdpSocket::bind("0.0.0.0:0").map_err(|source| Error::IoPath {
        action: "bind",
        path: PathBuf::from("0.0.0.0:0"),
        source,
    })?;
    socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .map_err(|error| Error::Usage(format!("socket: {error}")))?;

    let client_nonce = server_nonce();
    let (ephemeral_pk, ephemeral_sk) = suite()
        .kem_keygen(&crate::entropy::seed(), KemRole::Ephemeral)
        .map_err(|error| Error::Usage(format!("enroll keygen: {error}")))?;

    let mut buf = vec![0u8; MAX_DATAGRAM];
    let mut cookie: Option<[u8; COOKIE_SIZE]> = None;
    let mut last_error = None;
    for _attempt in 0..4 {
        let hello = encode_hello(
            &invite_id,
            &client_nonce,
            ephemeral_pk.as_bytes(),
            public_line,
            cookie.as_ref(),
            token,
        )?;
        if socket.send_to(&hello, server).is_err() {
            last_error = Some("could not reach the server".to_owned());
            continue;
        }
        loop {
            match socket.recv_from(&mut buf) {
                Ok((size, _)) => {
                    if let Some(fresh) = parse_cookie(&buf[..size]) {
                        cookie = Some(fresh);
                        break; // resend with the cookie
                    }
                    if let Some((status, body)) = open_reply(
                        token,
                        &invite_id,
                        &client_nonce,
                        &ephemeral_sk,
                        &buf[..size],
                    ) {
                        return if status == "ok" {
                            Ok(body)
                        } else {
                            Err(Error::Usage(format!("the server refused: {body}")))
                        };
                    }
                    // Not ours: keep waiting.
                }
                Err(_) => {
                    last_error = Some("timed out".to_owned());
                    break;
                }
            }
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

    fn nonce(byte: u8) -> [u8; NONCE_LEN] {
        [byte; NONCE_LEN]
    }

    fn invite() -> (Invite, Token) {
        let token = Token::generate();
        let id = crate::keys::hex_encode(&crate::entropy::seed()[..ID_LEN]);
        (
            Invite {
                version: INVITE_VERSION,
                id,
                name: "laptop".to_owned(),
                token_hex: crate::keys::hex_encode(token.bytes()),
                expires: unix_now() + 600,
                expect_public_line: None,
                public_line: None,
                config: None,
            },
            token,
        )
    }

    #[test]
    fn a_hello_round_trips_and_opens_for_the_right_token() {
        let (invite, token) = invite();
        let wrong = Token::generate();
        let (pk, _sk) = suite()
            .kem_keygen(&crate::entropy::seed(), KemRole::Ephemeral)
            .unwrap();
        let datagram = encode_hello(
            &invite.id,
            &nonce(1),
            pk.as_bytes(),
            "vallum1:0003:aa",
            None,
            &token,
        )
        .unwrap();
        let hello = parse_hello(&datagram).unwrap();
        assert_eq!(hello.id, invite.id);
        assert!(verify_hello(&token, &hello));
        assert!(!verify_hello(&wrong, &hello));
    }

    #[test]
    fn the_peer_name_never_appears_on_the_wire() {
        // Finding #5: the invite id replaces the name in every direction.
        let (invite, token) = invite();
        let (pk, _sk) = suite()
            .kem_keygen(&crate::entropy::seed(), KemRole::Ephemeral)
            .unwrap();
        let datagram = encode_hello(
            &invite.id,
            &nonce(2),
            pk.as_bytes(),
            "vallum1:0003:aa",
            None,
            &token,
        )
        .unwrap();
        assert!(
            !datagram
                .windows(invite.name.len())
                .any(|window| window == invite.name.as_bytes()),
            "the peer name is on the wire"
        );
    }

    #[test]
    fn a_seal_copied_to_another_invite_id_fails() {
        let (invite, token) = invite();
        let (pk, sk) = suite()
            .kem_keygen(&crate::entropy::seed(), KemRole::Ephemeral)
            .unwrap();
        let hello =
            encode_hello(&invite.id, &nonce(3), pk.as_bytes(), "line", None, &token).unwrap();
        let parsed = parse_hello(&hello).unwrap();
        let (ct, shared) = ephemeral_answer(&parsed, &[]).unwrap();
        let reply = encode_reply(&token, &parsed, &ct, &shared, &nonce(4), "ok", "{}").unwrap();

        // The same reply under a different invite id must not open: the id is
        // bound into the AEAD's associated data.
        let other = crate::keys::hex_encode(&crate::entropy::seed()[..ID_LEN]);
        assert!(open_reply(&token, &other, &nonce(3), &sk, &reply).is_none());
        assert!(open_reply(&token, &invite.id, &nonce(3), &sk, &reply).is_some());
    }

    #[test]
    fn a_reply_does_not_open_without_the_ephemeral_secret() {
        // Finding #6: the reply key needs the ephemeral shared secret, so a
        // later token compromise alone opens nothing.
        let (invite, token) = invite();
        let (pk, sk) = suite()
            .kem_keygen(&crate::entropy::seed(), KemRole::Ephemeral)
            .unwrap();
        let hello =
            encode_hello(&invite.id, &nonce(5), pk.as_bytes(), "line", None, &token).unwrap();
        let parsed = parse_hello(&hello).unwrap();
        let (ct, shared) = ephemeral_answer(&parsed, &[]).unwrap();
        let reply = encode_reply(&token, &parsed, &ct, &shared, &nonce(6), "ok", "secret").unwrap();
        assert!(open_reply(&token, &invite.id, &nonce(5), &sk, &reply).is_some());

        // Someone with the token but a *different* ephemeral key gets nothing.
        let (_pk2, sk2) = suite()
            .kem_keygen(&crate::entropy::seed(), KemRole::Ephemeral)
            .unwrap();
        assert!(open_reply(&token, &invite.id, &nonce(5), &sk2, &reply).is_none());
    }

    #[test]
    fn a_cookie_round_trips_and_is_bound_to_the_sender() {
        let secret = CookieSecret::new(&crate::entropy::seed());
        let cookie = secret
            .cookie(&suite(), &source_key("192.0.2.1".parse().unwrap()))
            .unwrap();
        let datagram = encode_cookie(&cookie);
        assert_eq!(parse_cookie(&datagram), Some(cookie));
        // A different address gets a different cookie.
        let other = secret
            .cookie(&suite(), &source_key("192.0.2.2".parse().unwrap()))
            .unwrap();
        assert_ne!(cookie, other);
    }

    #[test]
    fn malformed_datagrams_are_dropped_not_parsed() {
        assert!(parse_hello(b"").is_none());
        assert!(parse_hello(b"VEN2").is_none());
        // A VEN1 (v1) datagram is not accepted: it must be upgraded instead.
        assert!(parse_hello(b"VEN1\x01\x00").is_none());
        let mut bad = b"VEN2".to_vec();
        bad.extend_from_slice(&[0xff; 100]);
        assert!(parse_hello(&bad).is_none());
    }

    #[test]
    fn an_invite_id_must_be_hex_and_never_a_path() {
        assert!(valid_id(&crate::keys::hex_encode(&[0u8; ID_LEN])));
        assert!(!valid_id("../../etc/passwd"));
        assert!(!valid_id("abc"));
    }

    #[test]
    fn a_token_survives_display_and_parse() {
        let token = Token::generate();
        assert_eq!(Token::parse(&token.display()).unwrap(), token);
        assert!(Token::parse("not a token").is_err());
    }

    #[test]
    fn a_name_with_path_characters_is_rejected() {
        assert!(issue_invite("vallum0", "../etc", 60, None).is_err());
        assert!(!valid_name("a/b"));
        assert!(!valid_name(""));
        assert!(valid_name("laptop-1.home"));
    }
}
