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

use crate::error::Error;
use crate::keys::write_private;
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
///
/// Counted only for sources that have passed the cookie gate. A datagram
/// that carries no valid cookie is not from the address it claims to be
/// from, so charging it to that address let a flood of spoofed sources lock
/// out the real client behind them: eight junk datagrams a second were
/// enough.
const RATE_PER_SECOND: u32 = 8;
/// Datagrams this server will answer per second, whoever they are from.
///
/// This one is global, because the source address of a UDP datagram is the
/// sender's claim and not a fact: a per-source budget cannot be trusted to
/// bound the work. The total work still has to be bounded, and the cookie
/// gate - a constant-time MAC check - is what decides which datagrams are
/// worth the rest of the work.
const RATE_REPLIES_PER_SECOND: u32 = 512;
/// Distinct source IPs tracked inside one window.
///
/// Only authenticated sources are tracked, so this bounds the map's growth
/// without giving an attacker a way to fill it. Past the cap the window's
/// table is cleared rather than a new source refused: refusing turned a
/// full table into a lockout, because the legitimate client was refused for
/// not being in a table the attacker had filled.
const RATE_LIMIT_SOURCES: usize = 4096;
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
// The join ticket: one pasteable string instead of four flags.
//
// WireGuard hands over an endpoint and a public key; a post-quantum public
// line is ~4.7 KB of hex, so the operator pastes an *invite* instead. The
// invite is still four values (address, id, token, fingerprint), and four CLI
// flags is a ceremony — so `peer invite` packs them into one string and
// `vallum join` takes it in one argument:

// ```text
// vallum1-join:<host>:<port>/<name>/<invite-id>/<token>/<fingerprint>
// ```

// The name is a hint for the client's own config file; the server enrols
// under whatever name the invite was minted with. The fingerprint pins the
// answer to the server the invite was minted on.
pub const TICKET_PREFIX: &str = "vallum1-join:";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JoinTicket {
    /// The responder's `host:port` — the server's enrolment port.
    pub server: String,
    /// The name the invite was minted for; the client's config file uses it.
    pub name: String,
    pub invite_id: String,
    pub token: Token,
    /// `keys::fingerprint` of the server's public line.
    pub fingerprint: String,
}

impl JoinTicket {
    pub fn encode(&self) -> String {
        format!(
            "{TICKET_PREFIX}{}/{}/{}/{}/{}",
            self.server,
            self.name,
            self.invite_id,
            self.token.display(),
            self.fingerprint
        )
    }

    pub fn parse(text: &str) -> Result<Self, Error> {
        let body = text
            .trim()
            .strip_prefix(TICKET_PREFIX)
            .ok_or_else(|| Error::Usage("a join ticket starts with `vallum1-join:`".to_owned()))?;
        let parts: Vec<&str> = body.split('/').collect();
        if parts.len() != 5 {
            return Err(Error::Usage(
                "a join ticket is vallum1-join:<host>:<port>/<name>/<id>/<token>/<fingerprint>"
                    .to_owned(),
            ));
        }
        let (server, name, invite_id, token, fingerprint) =
            (parts[0], parts[1], parts[2], parts[3], parts[4]);
        let port_ok = server
            .rsplit_once(':')
            .and_then(|(host, port)| (!host.is_empty()).then(|| port.parse::<u16>().is_ok()))
            .unwrap_or(false);
        if !port_ok {
            return Err(Error::Usage(format!(
                "`{server}` is not a host:port the responder listens on"
            )));
        }
        if !valid_name(name) {
            return Err(Error::Usage(format!(
                "`{name}` is not a usable peer name (letters, digits, - _ .)"
            )));
        }
        if !valid_id(invite_id) {
            return Err(Error::Usage(
                "the invite id is 32 hex characters".to_owned(),
            ));
        }
        let token = Token::parse(token)?;
        if fingerprint.len() < 8
            || fingerprint.len() % 2 != 0
            || !fingerprint.chars().all(|c| c.is_ascii_hexdigit())
        {
            return Err(Error::Usage(
                "the fingerprint is the hex `vallum peer invite` printed".to_owned(),
            ));
        }
        Ok(Self {
            server: server.to_owned(),
            name: name.to_owned(),
            invite_id: invite_id.to_owned(),
            token,
            fingerprint: fingerprint.to_owned(),
        })
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
    /// The operator's options, carried in the invite: a ticket otherwise hands
    /// the device a peer record built from the invite alone, and neither a
    /// preshared key nor a shaping preset could ever reach it. Both default to
    /// absent so invites minted before this change still parse.
    #[serde(default)]
    pub psk: bool,
    #[serde(default)]
    pub shaping: Option<String>,
}

impl Invite {
    fn token(&self) -> Result<Token, Error> {
        Token::parse(&self.token_hex)
    }
}

/// Where invites live. Runtime state, not config: they die with the machine,
/// which is the right behaviour for a 15-minute credential.
fn run_dir() -> PathBuf {
    crate::host::paths::runtime_dir()
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
    // Unknown flag bits are a rejection, not something to ignore: this parser
    // and any other must agree byte for byte about what a HELLO is, or the two
    // can be made to disagree about the same datagram. The fuzzer found this
    // one by re-encoding a parsed HELLO and comparing.
    if flags & !FLAG_COOKIE != 0 {
        return None;
    }
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

/// Split a reply's framing without touching crypto.
///
/// Returns `(server_nonce, ciphertext, sealed)`. Public so the fuzzer can hold
/// the framing to "never panic, and the three slices tile the datagram" without
/// a KEM decapsulation per input.
pub fn reply_framing(datagram: &[u8]) -> Option<([u8; NONCE_LEN], &[u8], &[u8])> {
    if datagram.len() < 4 + 1 + NONCE_LEN + 2 || &datagram[..4] != MAGIC {
        return None;
    }
    if datagram[4] != TYPE_REPLY {
        return None;
    }
    let mut server_nonce = [0u8; NONCE_LEN];
    server_nonce.copy_from_slice(datagram.get(5..5 + NONCE_LEN)?);
    let offset = 5 + NONCE_LEN;
    let ct_len = u16::from_be_bytes(datagram.get(offset..offset + 2)?.try_into().ok()?) as usize;
    let start = offset + 2;
    let ciphertext = datagram.get(start..start + ct_len)?;
    let sealed = datagram.get(start + ct_len..)?;
    Some((server_nonce, ciphertext, sealed))
}

/// Open a reply against the token and the ephemeral secret the client kept.
pub fn open_reply(
    token: &Token,
    invite_id: &str,
    client_nonce: &[u8; NONCE_LEN],
    ephemeral_sk: &vallum_crypto::KemSecretKey,
    datagram: &[u8],
) -> Option<(String, String)> {
    let (server_nonce, ciphertext, sealed) = reply_framing(datagram)?;
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
    psk: bool,
    shaping: Option<String>,
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
        psk,
        shaping,
    };
    let dir = run_dir();
    std::fs::create_dir_all(&dir).map_err(|source| Error::IoPath {
        action: "create the invite directory",
        path: dir.clone(),
        source,
    })?;
    // Prune expired invites as new ones are minted so `/run/vallum` does not
    // accumulate stale credentials.
    let _ = list_invites(interface);
    let path = invite_path(interface, &id);
    write_private(
        &path,
        serde_json::to_vec_pretty(&invite)
            .map_err(|error| Error::Usage(format!("invite: {error}")))?
            .as_slice(),
    )?;
    Ok((token, id, path))
}

/// Where a new peer should dial this node, as `host:port`.
///
/// The config is the operator's statement about reachability, so it wins: the
/// `[enroll] port` answers enrolment and the `[interface] public_endpoint`
/// names the address peers can reach. Without a config the best available guess
/// is the interface's listen port plus one, and `<server>` marks a host nobody
/// has declared.
#[must_use]
pub fn join_target(config: Option<&crate::config::Config>, listen: Option<&str>) -> String {
    let port = config
        .and_then(|config| config.enroll.port)
        .unwrap_or_else(|| {
            listen
                .or_else(|| config.and_then(|config| config.interface.listen.as_deref()))
                .and_then(|listen| listen.rsplit_once(':'))
                .and_then(|(_, port)| port.parse::<u16>().ok())
                .unwrap_or(51820)
                .saturating_add(1)
        });
    let host = config
        .and_then(|config| config.interface.public_endpoint.clone())
        .and_then(|endpoint| {
            endpoint
                .rsplit_once(':')
                .map(|(host, _)| host.to_owned())
                .or(Some(endpoint))
        })
        .unwrap_or_else(|| "<server>".to_owned());
    format!("{host}:{port}")
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

/// List live invites for `interface`, pruning any whose TTL has already passed.
pub fn list_invites(interface: &str) -> Vec<Invite> {
    let dir = run_dir();
    let prefix = format!("enroll-{interface}-");
    let now = unix_now();
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return Vec::new();
    };
    let mut active = Vec::new();
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
            if invite.expires < now {
                let _ = std::fs::remove_file(entry.path());
            } else {
                active.push(invite);
            }
        }
    }
    active.sort_by(|a, b| a.name.cmp(&b.name));
    active
}

/// Remove every live invite for a peer name (after `peer remove`), returning
/// how many invite files were removed.
pub fn revoke_invite(interface: &str, name: &str) -> usize {
    let dir = run_dir();
    let prefix = format!("enroll-{interface}-");
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return 0;
    };
    let mut removed = 0;
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
            if invite.name == name && std::fs::remove_file(entry.path()).is_ok() {
                removed += 1;
            }
        }
    }
    removed
}

/// Admission control, in two parts, because the two questions are different.
///
/// The first is the *reply* budget: how many datagrams this server answers
/// per second, whoever they are from. It is global. The source address of a
/// UDP datagram is the sender's claim and not a fact, so a per-source budget
/// cannot be trusted to bound the work - but the total work still has to be
/// bounded, and it is bounded here.
///
/// The second is the *per-source* budget: how many requests one address may
/// make per second. It is applied AFTER the cookie gate, because the cookie
/// is an authenticated tag bound to the client's address: a request that
/// carries one really is from the address it claims to be from. Charging a
/// datagram to an address before that was proven charged it to a claim, and
/// a flood of claims could spend the budget of a real client.
struct RateLimit {
    window_start: Instant,
    counts: std::collections::HashMap<IpAddr, u32>,
    total: u32,
}

impl RateLimit {
    fn new() -> Self {
        Self {
            window_start: Instant::now(),
            counts: std::collections::HashMap::new(),
            total: 0,
        }
    }

    /// Start a new window if the last one has passed.
    fn roll(&mut self) {
        if self.window_start.elapsed() >= Duration::from_secs(1) {
            self.counts.clear();
            self.total = 0;
            self.window_start = Instant::now();
        }
    }

    /// Whether the server may answer another datagram at all.
    fn admit_reply(&mut self) -> bool {
        self.roll();
        self.total += 1;
        self.total <= RATE_REPLIES_PER_SECOND
    }

    /// Whether this authenticated source may make another request.
    fn admit_source(&mut self, source: IpAddr) -> bool {
        self.roll();
        // A full table must not turn every new address away. It used to, and
        // that is how a flood of spoofed sources locked out a legitimate
        // client: the table was full of claims, and the real client was
        // refused for not being one of them. The window is a second long, so
        // clearing the table costs one second of budgets.
        if !self.counts.contains_key(&source) && self.counts.len() >= RATE_LIMIT_SOURCES {
            self.counts.clear();
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
    // The same derivation `server enroll` uses, so a config that would mint
    // invites for an unbindable port (ephemeral listen, or a port below the
    // responder's capabilities) fails here rather than crash-looping.
    let port = crate::commands::server::enroll_port(&config)?;
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

    let state = std::sync::Arc::new(std::sync::Mutex::new(EnrollResponderState {
        config_path: config_path.to_path_buf(),
        interface: interface.clone(),
        cookies: CookieSecret::new(&crate::entropy::seed()),
        rotated: Instant::now(),
        limit: RateLimit::new(),
        legacy: None,
    }));

    if let Some(front_port) = enroll.front_port {
        let use_tls = enroll.front_tls.unwrap_or(true);
        let bind_ip = if use_tls { "0.0.0.0" } else { "127.0.0.1" };
        let front_addr: std::net::SocketAddr = format!("{bind_ip}:{front_port}")
            .parse()
            .map_err(|e| Error::Usage(format!("invalid front address: {e}")))?;
        let tls_cfg = if use_tls {
            let sni = crate::tls_quic::normalize_sni(enroll.front_sni.as_deref());
            let (server_cfg, _) = crate::tls_quic::build_tls_configs(&sni, &[b"http/1.1"])
                .map_err(|e| Error::Usage(format!("front TLS setup: {e}")))?;
            Some(server_cfg)
        } else {
            None
        };
        let listener = std::net::TcpListener::bind(front_addr).map_err(|source| Error::IoPath {
            action: "bind the enrolment fronting port",
            path: PathBuf::from(front_addr.to_string()),
            source,
        })?;
        say!(
            "enrolment API fronting on {front_addr} ({})",
            if use_tls { "https" } else { "http" }
        );
        spawn_front_listener(listener, tls_cfg, std::sync::Arc::clone(&state));
    }

    let mut buf = vec![0u8; MAX_DATAGRAM];
    loop {
        let Ok((size, source)) = socket.recv_from(&mut buf) else {
            if let Ok(mut guard) = state.lock() {
                guard.maybe_rotate();
            }
            continue; // timeout: rotate and listen again
        };
        let reply = state
            .lock()
            .ok()
            .and_then(|mut guard| guard.handle_datagram(source.ip(), &buf[..size]));
        if let Some(datagram) = reply {
            let _ = socket.send_to(&datagram, source);
        }
    }
}

struct EnrollResponderState {
    config_path: PathBuf,
    interface: String,
    cookies: CookieSecret,
    rotated: Instant,
    limit: RateLimit,
    legacy: Option<Instant>,
}

impl EnrollResponderState {
    fn maybe_rotate(&mut self) {
        if self.rotated.elapsed().as_secs() >= COOKIE_ROTATION_SECONDS {
            self.cookies.rotate(&crate::entropy::seed());
            self.rotated = Instant::now();
        }
    }

    fn handle_datagram(&mut self, source_ip: IpAddr, payload: &[u8]) -> Option<Vec<u8>> {
        self.maybe_rotate();
        // The global reply budget, before anything else: it bounds the work
        // this server does for anyone.
        if !self.limit.admit_reply() {
            return None;
        }
        let Some(hello) = parse_hello(payload) else {
            if payload.starts_with(b"VEN1") && legacy_notice(&mut self.legacy) {
                eprintln!(
                    "vallum: a v1 enrolment client ({source_ip}) tried to enrol; this server \
                     speaks v2 — upgrade that client (`vallum setup --join`)"
                );
            }
            return None;
        };
        let client_addr = source_key(source_ip);
        let cookie_ok = hello
            .cookie
            .as_ref()
            .and_then(|cookie| {
                self.cookies
                    .verify_cookie(&suite(), &client_addr, cookie)
                    .ok()
            })
            .unwrap_or(false);
        if !cookie_ok {
            return self
                .cookies
                .cookie(&suite(), &client_addr)
                .ok()
                .map(|fresh| encode_cookie(&fresh));
        }
        if !self.limit.admit_source(source_ip) {
            return None;
        }
        let invite = load_invite(&self.interface, &hello.id)?;
        let token = invite.token().ok()?;
        if !verify_hello(&token, &hello) {
            return None;
        }

        let (ciphertext, shared) = ephemeral_answer(&hello).ok()?;
        let seal = |status: &str, body: &str| -> Option<Vec<u8>> {
            encode_reply(
                &token,
                &hello,
                &ciphertext,
                &shared,
                &server_nonce(),
                status,
                body,
            )
            .ok()
        };
        match decide_invite(&invite, &hello, unix_now()) {
            InviteDecision::Refuse(reason) => return seal("err", reason),
            InviteDecision::Retransmit(config) => return seal("ok", config),
            InviteDecision::Proceed => {}
        }
        match crate::commands::peer::enroll_report(&crate::commands::peer::EnrollArgs {
            name: invite.name.clone(),
            config: self.config_path.clone(),
            public_key: Some(hello.public_line.clone()),
            public_key_file: None,
            address: None,
            keepalive: None,
            shaping: invite.shaping.clone(),
            psk: invite.psk,
            no_apply: false,
            json: true,
        }) {
            Ok(report) => {
                if !report.applied {
                    eprintln!(
                        "vallum: enrolled `{}` in {} but could NOT apply it to the running \
                         daemon — this device cannot connect until the daemon reloads the \
                         config (`vallum syncconf {}`)",
                        invite.name, report.config, report.config
                    );
                }
                let json = serde_json::to_string(&report).ok()?;
                let mut spent = invite.clone();
                spent.public_line = Some(hello.public_line.clone());
                spent.config = Some(json.clone());
                if store_invite(&self.interface, &spent).is_err() {
                    eprintln!(
                        "vallum: enrolled `{}` for {source_ip} but could not persist the spent invite; \
                         refusing the send so the client retries",
                        invite.name,
                    );
                    return None;
                }
                eprintln!(
                    "vallum: enrolled `{}` for {source_ip} (token enrolment)",
                    invite.name,
                );
                seal("ok", &json)
            }
            Err(error) => seal("err", &format!("the server refused: {error}")),
        }
    }
}

fn spawn_front_listener(
    listener: std::net::TcpListener,
    tls_cfg: Option<std::sync::Arc<rustls::ServerConfig>>,
    state: std::sync::Arc<std::sync::Mutex<EnrollResponderState>>,
) {
    let _ = std::thread::Builder::new()
        .name("vallum-enroll-front".to_owned())
        .spawn(move || {
            for incoming in listener.incoming() {
                let Ok(stream) = incoming else {
                    continue;
                };
                let peer_ip = stream
                    .peer_addr()
                    .map_or(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), |a| a.ip());
                let tls_cfg = tls_cfg.clone();
                let state = std::sync::Arc::clone(&state);
                let _ = std::thread::Builder::new()
                    .name("vallum-enroll-req".to_owned())
                    .spawn(move || {
                        handle_front_connection(stream, peer_ip, tls_cfg, &state);
                    });
            }
        });
}

fn handle_front_connection(
    stream: std::net::TcpStream,
    peer_ip: IpAddr,
    tls_cfg: Option<std::sync::Arc<rustls::ServerConfig>>,
    state: &std::sync::Arc<std::sync::Mutex<EnrollResponderState>>,
) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));
    let _ = stream.set_nodelay(true);

    if let Some(cfg) = tls_cfg {
        let Ok(conn) = rustls::ServerConnection::new(cfg) else {
            return;
        };
        let mut tls_stream = rustls::StreamOwned::new(conn, stream);
        serve_front_http(&mut tls_stream, peer_ip, state);
    } else {
        let mut plain = stream;
        serve_front_http(&mut plain, peer_ip, state);
    }
}

fn serve_front_http<S: std::io::Read + std::io::Write>(
    io: &mut S,
    peer_ip: IpAddr,
    state: &std::sync::Arc<std::sync::Mutex<EnrollResponderState>>,
) {
    let Ok((method, path, forwarded_ip, body)) = read_http_request(io) else {
        let _ = write_http_response(io, "400 Bad Request", &[]);
        return;
    };
    if method != "POST" || (path != "/_vallum/enroll" && path != "/v1/enroll") {
        let _ = write_http_response(io, "404 Not Found", &[]);
        return;
    }
    let client_ip = forwarded_ip.unwrap_or(peer_ip);
    let reply = state
        .lock()
        .ok()
        .and_then(|mut guard| guard.handle_datagram(client_ip, &body));
    match reply {
        Some(bytes) => {
            let _ = write_http_response(io, "200 OK", &bytes);
        }
        None => {
            let _ = write_http_response(io, "204 No Content", &[]);
        }
    }
}

fn read_http_request<R: std::io::Read>(
    reader: &mut R,
) -> Result<(String, String, Option<IpAddr>, Vec<u8>), ()> {
    let mut buf = Vec::with_capacity(2048);
    let mut chunk = [0u8; 1024];
    let header_end = loop {
        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break pos;
        }
        if buf.len() >= 16_384 {
            return Err(());
        }
        let n = reader.read(&mut chunk).map_err(|_| ())?;
        if n == 0 {
            return Err(());
        }
        buf.extend_from_slice(&chunk[..n]);
    };

    let head = std::str::from_utf8(&buf[..header_end]).map_err(|_| ())?;
    let mut lines = head.split("\r\n");
    let request_line = lines.next().ok_or(())?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next().ok_or(())?.to_owned();
    let raw_target = parts.next().ok_or(())?;
    let path = raw_target
        .split('?')
        .next()
        .unwrap_or(raw_target)
        .to_owned();

    let mut content_len: usize = 0;
    let mut forwarded_ip: Option<IpAddr> = None;
    for line in lines {
        if let Some((name, val)) = line.split_once(':') {
            let key = name.trim();
            let value = val.trim();
            if key.eq_ignore_ascii_case("content-length") {
                content_len = value.parse::<usize>().map_err(|_| ())?;
                if content_len > MAX_DATAGRAM {
                    return Err(());
                }
            } else if key.eq_ignore_ascii_case("x-forwarded-for") && forwarded_ip.is_none() {
                if let Some(first) = value.split(',').next() {
                    forwarded_ip = first.trim().parse::<IpAddr>().ok();
                }
            }
        }
    }

    let body_start = header_end + 4;
    let mut body = buf[body_start..].to_vec();
    while body.len() < content_len {
        let n = reader.read(&mut chunk).map_err(|_| ())?;
        if n == 0 {
            return Err(());
        }
        body.extend_from_slice(&chunk[..n]);
    }
    body.truncate(content_len);
    Ok((method, path, forwarded_ip, body))
}

fn write_http_response<W: std::io::Write>(
    writer: &mut W,
    status: &str,
    body: &[u8],
) -> std::io::Result<()> {
    let header = format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    writer.write_all(header.as_bytes())?;
    if !body.is_empty() {
        writer.write_all(body)?;
    }
    writer.flush()
}

/// Pure post-auth decision for a verified `HELLO` against a loaded `Invite`.
#[derive(Debug, PartialEq, Eq)]
enum InviteDecision<'a> {
    Proceed,
    Retransmit(&'a str),
    Refuse(&'static str),
}

fn decide_invite<'a>(invite: &'a Invite, hello: &Hello, now: u64) -> InviteDecision<'a> {
    if invite.expires < now {
        return InviteDecision::Refuse("this invite has expired; ask the server for a new one");
    }
    if let Some(expected) = &invite.expect_public_line {
        if !constant_time_eq(expected.as_bytes(), hello.public_line.as_bytes()) {
            return InviteDecision::Refuse("this invite is bound to a different key");
        }
    }
    if let (Some(old), Some(config)) = (&invite.public_line, &invite.config) {
        return if constant_time_eq(old.as_bytes(), hello.public_line.as_bytes()) {
            InviteDecision::Retransmit(config)
        } else {
            InviteDecision::Refuse("this invite was already used with a different key")
        };
    }
    InviteDecision::Proceed
}

/// Whether to log a legacy-client notice now: at most once a minute, so a
/// v1 client retrying does not fill the journal.
fn legacy_notice(last: &mut Option<Instant>) -> bool {
    match last {
        Some(when) if when.elapsed() < Duration::from_secs(60) => false,
        _ => {
            *last = Some(Instant::now());
            true
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
fn ephemeral_answer(hello: &Hello) -> Result<(Vec<u8>, Vec<u8>), Error> {
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
    // The old message pointed at one cause - a stale invite - when there are
    // three, and the one it pointed at is the least likely: the port is
    // filtered upstream of the host far more often than a token is stale.
    Err(Error::Usage(format!(
        "no answer from {server}: {}.\n\
         Three different things end here, and they need different fixes:\n\
         \n   1. the port is not reachable. The responder answers on the port in \
         `{server}`, which must be open in the cloud security group as well as \
         on the host, and only while enrolling. Check that first.\n\
         \n   2. the responder is not running. On the server: \
         sudo systemctl start vallum-enroll@<interface>\n\
         \n   3. the invite is stale, or it was made for another device. Mint a \
         new one: sudo vallum peer invite {name}",
        last_error.unwrap_or_else(|| "no response".to_owned()),
        name = name,
    )))
}

#[derive(Debug, PartialEq, Eq)]
struct FrontEndpoint {
    tls: bool,
    connect_host: String,
    port: u16,
    path: String,
}

fn parse_front_url(raw: &str) -> Result<FrontEndpoint, Error> {
    let trimmed = raw.trim();
    let (tls, rest) = if let Some(r) = trimmed.strip_prefix("https://") {
        (true, r)
    } else if let Some(r) = trimmed.strip_prefix("http://") {
        (false, r)
    } else {
        return Err(Error::Usage(
            "front URL must start with `https://` or `http://`".to_owned(),
        ));
    };
    let (authority, path) = match rest.find('/') {
        Some(idx) => (&rest[..idx], rest[idx..].to_owned()),
        None => (rest, "/_vallum/enroll".to_owned()),
    };
    if authority.is_empty() {
        return Err(Error::Usage("front URL is missing a host".to_owned()));
    }
    let default_port = if tls { 443 } else { 80 };
    let (connect_host, port) = if let Some(bracketed) = authority.strip_prefix('[') {
        let end = bracketed
            .find(']')
            .ok_or_else(|| Error::Usage("malformed IPv6 host in front URL".to_owned()))?;
        let host = bracketed[..end].to_owned();
        let after = &bracketed[end + 1..];
        let port = if let Some(p) = after.strip_prefix(':') {
            p.parse::<u16>()
                .map_err(|_| Error::Usage("invalid port in front URL".to_owned()))?
        } else if after.is_empty() {
            default_port
        } else {
            return Err(Error::Usage("invalid authority in front URL".to_owned()));
        };
        (host, port)
    } else if let Some((h, p)) = authority.rsplit_once(':') {
        let port = p
            .parse::<u16>()
            .map_err(|_| Error::Usage("invalid port in front URL".to_owned()))?;
        (h.to_owned(), port)
    } else {
        (authority.to_owned(), default_port)
    };
    if connect_host.is_empty() {
        return Err(Error::Usage("front URL host cannot be empty".to_owned()));
    }
    Ok(FrontEndpoint {
        tls,
        connect_host,
        port,
        path,
    })
}

fn front_round_trip(
    endpoint: &FrontEndpoint,
    host_header: &str,
    client_cfg: Option<&std::sync::Arc<rustls::ClientConfig>>,
    payload: &[u8],
) -> Result<Vec<u8>, Error> {
    use std::io::{Read, Write};
    use std::net::ToSocketAddrs;

    let addr = (endpoint.connect_host.as_str(), endpoint.port)
        .to_socket_addrs()
        .map_err(|e| Error::Usage(format!("resolve front host: {e}")))?
        .next()
        .ok_or_else(|| Error::Usage("front host resolved to no addresses".to_owned()))?;
    let stream = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(5))
        .map_err(|e| Error::Usage(format!("connect front endpoint {addr}: {e}")))?;
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));
    let _ = stream.set_nodelay(true);

    let req_head = format!(
        "POST {} HTTP/1.1\r\nHost: {host_header}\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        endpoint.path,
        payload.len()
    );

    let mut raw_resp = Vec::with_capacity(4096);
    if endpoint.tls {
        let cfg = client_cfg.ok_or_else(|| Error::Usage("missing TLS client config".to_owned()))?;
        let server_name = crate::tls_quic::server_name_for(&endpoint.connect_host)
            .map_err(|e| Error::Usage(format!("front SNI: {e}")))?;
        let conn = rustls::ClientConnection::new(std::sync::Arc::clone(cfg), server_name)
            .map_err(|e| Error::Usage(format!("front TLS init: {e}")))?;
        let mut tls_stream = rustls::StreamOwned::new(conn, stream);
        tls_stream
            .write_all(req_head.as_bytes())
            .and_then(|()| tls_stream.write_all(payload))
            .and_then(|()| tls_stream.flush())
            .map_err(|e| Error::Usage(format!("front TLS write: {e}")))?;
        let _ = tls_stream.read_to_end(&mut raw_resp);
    } else {
        let mut plain = stream;
        plain
            .write_all(req_head.as_bytes())
            .and_then(|()| plain.write_all(payload))
            .and_then(|()| plain.flush())
            .map_err(|e| Error::Usage(format!("front HTTP write: {e}")))?;
        let _ = plain.read_to_end(&mut raw_resp);
    }

    let Some(hdr_end) = raw_resp.windows(4).position(|w| w == b"\r\n\r\n") else {
        return Err(Error::Usage(
            "malformed HTTP response from front endpoint".to_owned(),
        ));
    };
    let head = std::str::from_utf8(&raw_resp[..hdr_end])
        .map_err(|_| Error::Usage("non-UTF-8 HTTP header from front endpoint".to_owned()))?;
    let status_line = head.lines().next().unwrap_or("");
    if status_line.contains(" 204 ") {
        return Ok(Vec::new());
    }
    if !status_line.contains(" 200 ") {
        return Err(Error::Usage(format!(
            "front endpoint returned `{status_line}`"
        )));
    }
    Ok(raw_resp[hdr_end + 4..].to_vec())
}

/// Enrol through an HTTPS/HTTP API fronting endpoint (`POST /_vallum/enroll`),
/// optionally overriding the HTTP `Host:` header for CDN domain fronting.
pub fn join_via_front(
    front_url: &str,
    front_host: Option<&str>,
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
    let endpoint = parse_front_url(front_url)?;
    let host_header = front_host
        .map(str::trim)
        .filter(|h| !h.is_empty())
        .unwrap_or(&endpoint.connect_host)
        .to_owned();
    let client_cfg = if endpoint.tls {
        let (_, cfg) = crate::tls_quic::build_tls_configs(&endpoint.connect_host, &[b"http/1.1"])
            .map_err(|e| Error::Usage(format!("front TLS setup: {e}")))?;
        Some(cfg)
    } else {
        None
    };

    let client_nonce = server_nonce();
    let (ephemeral_pk, ephemeral_sk) = suite()
        .kem_keygen(&crate::entropy::seed(), KemRole::Ephemeral)
        .map_err(|error| Error::Usage(format!("enroll keygen: {error}")))?;

    let mut cookie: Option<[u8; COOKIE_SIZE]> = None;
    for _attempt in 0..4 {
        let hello = encode_hello(
            invite_id,
            &client_nonce,
            ephemeral_pk.as_bytes(),
            public_line,
            cookie.as_ref(),
            token,
        )?;
        let resp = front_round_trip(&endpoint, &host_header, client_cfg.as_ref(), &hello)?;
        if let Some(fresh) = parse_cookie(&resp) {
            cookie = Some(fresh);
            continue;
        }
        if let Some((status, body)) =
            open_reply(token, invite_id, &client_nonce, &ephemeral_sk, &resp)
        {
            return if status == "ok" {
                Ok(body)
            } else {
                Err(Error::Usage(format!("the server refused: {body}")))
            };
        }
    }
    Err(Error::Usage(format!(
        "no valid enrolment reply from front endpoint {front_url} for `{name}`"
    )))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

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
                psk: false,
                shaping: None,
            },
            token,
        )
    }

    #[test]
    fn the_rate_limiter_bounds_tracked_sources_and_repeats() {
        let mut limit = RateLimit::new();
        // The cap, not the flood, is what a source spray hits first: each
        // unique address costs one map entry, so the map must stop growing at
        // the bound rather than at memory exhaustion.
        for last_octet in 0..=u8::MAX {
            for third in 0..=u8::MAX {
                let ip = IpAddr::V4(Ipv4Addr::new(10, 0, third, last_octet));
                let _ = limit.admit_source(ip);
            }
        }
        assert_eq!(limit.counts.len(), RATE_LIMIT_SOURCES);
        // A brand-new source is still admitted when the map is at the cap.
        // It used to be REFUSED, and that was the lockout: the map was full
        // of claims, and the legitimate client was turned away for not being
        // one of them.
        assert!(
            limit.admit_source(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))),
            "a full table must not refuse a new address"
        );
        // A source inside the window is still counted, and throttled at 8/s.
        let known = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0));
        for _ in 0..RATE_PER_SECOND {
            let _ = limit.admit_source(known);
        }
        assert!(!limit.admit_source(known));
    }

    /// The reply budget is global, because the source of a UDP datagram is a
    /// claim. It bounds the server's work for anyone.
    #[test]
    fn the_reply_budget_is_global() {
        let mut limit = RateLimit::new();
        for _ in 0..RATE_REPLIES_PER_SECOND {
            assert!(limit.admit_reply());
        }
        assert!(
            !limit.admit_reply(),
            "the server must stop answering datagrams it cannot afford to answer"
        );
    }

    /// The source budget is charged only after the cookie gate, so a flood of
    /// junk that never passes it cannot spend a real client's budget.
    #[test]
    fn a_junk_flood_cannot_spend_a_real_clients_budget() {
        let mut limit = RateLimit::new();
        let real = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 5));
        // Junk from a claim that never passes the cookie gate: it is answered
        // with a cookie, but it is never charged to the address it claims.
        for _ in 0..100 {
            limit.admit_reply();
        }
        // The real client's own budget is untouched by that flood.
        for _ in 0..RATE_PER_SECOND {
            assert!(
                limit.admit_source(real),
                "the junk must not have spent the real client's budget"
            );
        }
        assert!(
            !limit.admit_source(real),
            "and the real client is still bounded"
        );
    }

    #[test]
    fn a_join_ticket_round_trips_every_field() {
        let token = Token::generate();
        let ticket = JoinTicket {
            server: "vpn.example.com:51821".to_owned(),
            name: "laptop".to_owned(),
            invite_id: "0123456789abcdef0123456789abcdef".to_owned(),
            token,
            fingerprint: "a1b2c3d4e5f6".to_owned(),
        };
        let encoded = ticket.encode();
        assert!(encoded.starts_with(TICKET_PREFIX));
        // One line, one token: no whitespace, nothing a QR or a paste breaks.
        assert!(!encoded.chars().any(|c| c.is_whitespace()));
        assert_eq!(JoinTicket::parse(&encoded).unwrap(), ticket);
    }

    #[test]
    fn a_join_ticket_tolerates_ipv6_and_a_wrapped_paste() {
        let token = Token::generate();
        let text = format!(
            "  {TICKET_PREFIX}[fd00::1]:51821/phone.dead/{}/{}/001122334455  \n",
            "aa".repeat(16),
            token.display()
        );
        let ticket = JoinTicket::parse(&text).unwrap();
        assert_eq!(ticket.server, "[fd00::1]:51821");
        assert_eq!(ticket.name, "phone.dead");
        assert_eq!(ticket.token, token);
    }

    #[test]
    fn a_join_ticket_rejects_what_is_not_one() {
        for bad in [
            "host:51821/laptop/aa/bb/cc",
            "vallum1-join:host:51821/laptop/aa",
            "vallum1-join::51821/laptop/0123456789abcdef0123456789abcdef/aaaa-bbbb-cccc-dddd-eeee-ffff-0000-1111/aabbccdd",
            "vallum1-join:host:51821/bad name/0123456789abcdef0123456789abcdef/aaaa-bbbb-cccc-dddd-eeee-ffff-0000-1111/aabbccdd",
            "vallum1-join:host:notaport/laptop/0123456789abcdef0123456789abcdef/aaaa-bbbb-cccc-dddd-eeee-ffff-0000-1111/aabbccdd",
            "vallum1-join:host:51821/laptop/tooshort/aaaa-bbbb-cccc-dddd-eeee-ffff-0000-1111/aabbccdd",
            "vallum1-join:host:51821/laptop/0123456789abcdef0123456789abcdef/nothex!!/aabbccdd",
        ] {
            assert!(JoinTicket::parse(bad).is_err(), "{bad} parsed");
        }
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
        let (ct, shared) = ephemeral_answer(&parsed).unwrap();
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
        let (ct, shared) = ephemeral_answer(&parsed).unwrap();
        let reply = encode_reply(&token, &parsed, &ct, &shared, &nonce(6), "ok", "secret").unwrap();
        assert!(open_reply(&token, &invite.id, &nonce(5), &sk, &reply).is_some());

        // Someone with the token but a *different* ephemeral key gets nothing.
        let (_pk2, sk2) = suite()
            .kem_keygen(&crate::entropy::seed(), KemRole::Ephemeral)
            .unwrap();
        assert!(open_reply(&token, &invite.id, &nonce(5), &sk2, &reply).is_none());
    }

    #[test]
    fn decide_invite_handles_expiry_pinning_and_retransmits_purely() {
        let (mut inv, token) = invite();
        let (pk, _sk) = suite()
            .kem_keygen(&crate::entropy::seed(), KemRole::Ephemeral)
            .unwrap();
        let datagram = encode_hello(
            &inv.id,
            &nonce(7),
            pk.as_bytes(),
            "vallum1:0003:aa",
            None,
            &token,
        )
        .unwrap();
        let hello = parse_hello(&datagram).unwrap();

        // Fresh invite within TTL -> Proceed.
        assert_eq!(
            decide_invite(&inv, &hello, inv.expires),
            InviteDecision::Proceed
        );
        // Past expiry -> Refuse.
        assert_eq!(
            decide_invite(&inv, &hello, inv.expires + 1),
            InviteDecision::Refuse("this invite has expired; ask the server for a new one")
        );

        // Pinned to another line -> Refuse; pinned to this line -> Proceed.
        inv.expect_public_line = Some("vallum1:0003:bb".to_owned());
        assert_eq!(
            decide_invite(&inv, &hello, inv.expires),
            InviteDecision::Refuse("this invite is bound to a different key")
        );
        inv.expect_public_line = Some("vallum1:0003:aa".to_owned());
        assert_eq!(
            decide_invite(&inv, &hello, inv.expires),
            InviteDecision::Proceed
        );

        // Spent on the same line -> Retransmit; spent on another -> Refuse.
        inv.public_line = Some("vallum1:0003:aa".to_owned());
        inv.config = Some("[interface]".to_owned());
        assert_eq!(
            decide_invite(&inv, &hello, inv.expires),
            InviteDecision::Retransmit("[interface]")
        );
        inv.public_line = Some("vallum1:0003:cc".to_owned());
        assert_eq!(
            decide_invite(&inv, &hello, inv.expires),
            InviteDecision::Refuse("this invite was already used with a different key")
        );
    }

    #[test]
    fn a_cookie_survives_a_single_secret_rotation() {
        let mut secret = CookieSecret::new(&[1u8; 32]);
        let client = source_key("192.0.2.1".parse().unwrap());
        let before_rotate = secret.cookie(&suite(), &client).unwrap();
        assert!(secret
            .verify_cookie(&suite(), &client, &before_rotate)
            .unwrap());

        // One rotation keeps `previous`, so a cookie issued moments earlier is
        // still accepted; a second rotation retires it.
        secret.rotate(&[2u8; 32]);
        assert!(secret
            .verify_cookie(&suite(), &client, &before_rotate)
            .unwrap());
        secret.rotate(&[3u8; 32]);
        assert!(!secret
            .verify_cookie(&suite(), &client, &before_rotate)
            .unwrap());
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
    fn the_invite_carries_the_operators_options() {
        // The responder builds the peer record from the invite alone, so the
        // options must survive the serde round trip — and invites minted
        // before the fields existed must still parse, with the options off.
        let (invite, _) = invite();
        let mut with_options = invite.clone();
        with_options.psk = true;
        with_options.shaping = Some("balanced".to_owned());
        let parsed: Invite =
            serde_json::from_str(&serde_json::to_string(&with_options).unwrap()).unwrap();
        assert!(parsed.psk);
        assert_eq!(parsed.shaping.as_deref(), Some("balanced"));

        let old_format = serde_json::json!({
            "version": INVITE_VERSION,
            "id": invite.id,
            "name": invite.name,
            "token_hex": invite.token_hex,
            "expires": invite.expires,
        });
        let parsed: Invite = serde_json::from_value(old_format).unwrap();
        assert!(!parsed.psk);
        assert_eq!(parsed.shaping, None);
    }

    #[test]
    fn a_name_with_path_characters_is_rejected() {
        assert!(issue_invite("vallum0", "../etc", 60, None, false, None).is_err());
        assert!(!valid_name("a/b"));
        assert!(!valid_name(""));
        assert!(valid_name("laptop-1.home"));
    }

    #[test]
    fn join_target_uses_listen_port_plus_one_when_public_endpoint_port_differs() {
        let path =
            std::env::temp_dir().join(format!("vallum-join-target-{}.toml", std::process::id()));
        let load = |body: &str| {
            std::fs::write(&path, body).unwrap();
            crate::config::Config::load(&path).unwrap()
        };
        let config = load(
            "[interface]\nprivate_key = \"test.key\"\npublic_endpoint = \"vpn.example.com:51900\"\nlisten = \"0.0.0.0:52000\"\n",
        );
        assert_eq!(join_target(Some(&config), None), "vpn.example.com:52001");
        assert_eq!(
            join_target(Some(&config), Some("0.0.0.0:53000")),
            "vpn.example.com:53001"
        );
        let pinned = load(
            "[interface]\nprivate_key = \"test.key\"\npublic_endpoint = \"vpn.example.com:51900\"\nlisten = \"0.0.0.0:52000\"\n[enroll]\nport = 60000\n",
        );
        assert_eq!(
            join_target(Some(&pinned), Some("0.0.0.0:53000")),
            "vpn.example.com:60000"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn parse_front_url_handles_https_http_ports_and_paths() {
        assert_eq!(
            parse_front_url("https://cdn.example.com").unwrap(),
            FrontEndpoint {
                tls: true,
                connect_host: "cdn.example.com".to_owned(),
                port: 443,
                path: "/_vallum/enroll".to_owned(),
            }
        );
        assert_eq!(
            parse_front_url("http://127.0.0.1:8443/v1/enroll").unwrap(),
            FrontEndpoint {
                tls: false,
                connect_host: "127.0.0.1".to_owned(),
                port: 8443,
                path: "/v1/enroll".to_owned(),
            }
        );
        assert!(parse_front_url("ftp://bad.example.com").is_err());
    }

    #[test]
    fn front_enrolment_round_trips_over_tls_and_domain_fronting_host() {
        let sni = "localhost";
        let (server_cfg, _) =
            crate::tls_quic::build_tls_configs(sni, &[b"http/1.1"]).expect("tls configs");
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("local addr");

        let state = std::sync::Arc::new(std::sync::Mutex::new(EnrollResponderState {
            config_path: PathBuf::from("/nonexistent-vallum-test.toml"),
            interface: "vallum-front-test".to_owned(),
            cookies: CookieSecret::new(&[7u8; 32]),
            rotated: Instant::now(),
            limit: RateLimit::new(),
            legacy: None,
        }));
        spawn_front_listener(listener, Some(server_cfg), state);

        let token = Token::generate();
        let invite_id = "0123456789abcdef0123456789abcdef";
        let url = format!("https://127.0.0.1:{}/_vallum/enroll", addr.port());
        // No invite file exists for this synthetic id, so the responder cleanly
        // returns 204 after issuing & verifying the TLS-fronted cookie exchange.
        let err = join_via_front(
            &url,
            Some("origin.internal.example"),
            &token,
            invite_id,
            "laptop-front",
            "vallum1:testkey",
        )
        .expect_err("synthetic invite returns no reply after cookie exchange");
        assert!(err.to_string().contains("no valid enrolment reply"));
    }
}
