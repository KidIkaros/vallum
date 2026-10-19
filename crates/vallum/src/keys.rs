// SPDX-License-Identifier: Apache-2.0

//! Long-term keys on disk, and the text form an operator pastes.
//!
//! # The secret file
//!
//! One 32-byte master seed, and the suite it was expanded under:
//!
//! ```toml
//! version = 1
//! suite = 3
//! seed = "…64 hex characters…"
//! signing = false
//! ```
//!
//! The seed is the whole secret. Everything else — the KEM key pair, and the
//! signing key pair when `signing` is set — is derived from it by the suite, so a
//! key file is portable across implementations of the same suite and nothing
//! derived has to be stored or invalidated.
//!
//! **The file records the suite and the daemon refuses to run if the two
//! disagree.** A seed expanded under one suite is not a key under another, and
//! silently deriving a different key would turn a config typo into a mysteriously
//! unreachable peer.
//!
//! # The public line
//!
//! A peer's public identity is one line, so moving it between two hosts is one
//! paste and not a field-by-field ceremony:
//!
//! ```text
//! vallum1:0003:<kem public key, hex>:<signing public key, hex, or ->
//! ```
//!
//! `vallum1` is a format tag, so a future encoding is a different tag rather than
//! a guess. The suite is carried in the line *and* checked against the daemon's
//! own suite at load: a peer configured with the wrong suite is a config error,
//! not a handshake that fails at 3 a.m.
//!
//! ## The line is long, and that is allowed
//!
//! A tri-hybrid public key is about 4.7 KB of hex — several times a terminal
//! width — so `decode_public` ignores *all* whitespace inside a line. An operator
//! can therefore wrap it, in a TOML multi-line string or however their editor
//! does it, and it will still load:
//!
//! ```toml
//! public_key = """
//!   vallum1:0003:4f6e3c8d…
//!   …:-
//! """
//! ```
//!
//! Nothing is lost by being forgiving here: the payload of every field is hex, and
//! hex has no whitespace in it, so a space can only ever be a line break someone's
//! editor inserted.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use vallum_core::identity::{PeerIdentity, StaticIdentity};
use vallum_crypto::{CryptoSuite, KemPublicKey, SharedSecret, SignPublicKey};

use crate::error::Error;

/// The key-file format this build writes and understands.
pub const KEY_FILE_VERSION: u32 = 1;

/// The tag on a public-key line.
pub const PUBLIC_TAG: &str = "vallum1";

/// A suite's operator-facing name, for generated comments and log lines.
#[must_use]
pub fn describe_suite(suite_id: u16) -> &'static str {
    match suite_id {
        0x0001 => "x25519+sntrup761",
        0x0002 => "x25519+ml-kem-768",
        0x0003 => "x25519+sntrup761+ml-kem-768",
        _ => "unknown",
    }
}

/// The contents of a private-key file.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretFile {
    /// Format version. See [`KEY_FILE_VERSION`].
    pub version: u32,
    /// The suite id the seed is expanded under.
    pub suite: u16,
    /// The 32-byte master seed, hex-encoded.
    pub seed: String,
    /// Whether the identity also carries a hybrid signing key pair.
    #[serde(default)]
    pub signing: bool,
}

/// A private key that could not be read, parsed, or expanded.
fn key_error(what: impl Into<String>, why: impl Into<String>) -> Error {
    Error::Key {
        what: what.into(),
        why: why.into(),
    }
}

/// Hex-encode.
#[must_use]
pub fn hex_encode(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from(DIGITS[usize::from(byte >> 4)]));
        out.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    out
}

/// Hex-decode. Rejects odd lengths and any non-hex character.
///
/// # Errors
///
/// A human-readable reason, for the config error or the CLI.
pub fn hex_decode(text: &str) -> Result<Vec<u8>, String> {
    let text = text.trim();
    if !text.len().is_multiple_of(2) {
        return Err(format!("hex string has odd length {}", text.len()));
    }
    let mut out = Vec::with_capacity(text.len() / 2);
    let bytes = text.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        let hi = hex_digit(bytes[index])?;
        let lo = hex_digit(bytes[index + 1])?;
        out.push((hi << 4) | lo);
        index += 2;
    }
    Ok(out)
}

fn hex_digit(byte: u8) -> Result<u8, String> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        other => Err(format!("`{}` is not a hex digit", char::from(other))),
    }
}

/// Best-effort memory scrub the optimizer is unlikely to elide.
///
/// The same construction as `vallum-core`'s internal helper. It is best-effort
/// and this crate does not claim more: without a `zeroize` dependency a copy
/// anywhere in the allocator can survive, so the real defence is that the seed
/// lives in one file read once at startup.
pub(crate) fn scrub(buf: &mut [u8]) {
    for byte in buf.iter_mut() {
        *byte = 0;
    }
    std::hint::black_box(buf);
}

/// A freshly generated secret.
///
/// `seed` is what the caller drew from the operating system; this function never
/// invents one.
#[must_use]
pub fn new_secret(suite_id: u16, signing: bool, seed: [u8; 32]) -> SecretFile {
    SecretFile {
        version: KEY_FILE_VERSION,
        suite: suite_id,
        seed: hex_encode(&seed),
        signing,
    }
}

/// Read a private-key file.
///
/// # Errors
///
/// If it cannot be read or parsed, or if its format version is not
/// [`KEY_FILE_VERSION`].
pub fn load_secret(path: &Path) -> Result<SecretFile, Error> {
    let text = fs::read_to_string(path).map_err(|source| Error::IoPath {
        action: "read key file",
        path: path.to_path_buf(),
        source,
    })?;
    let file: SecretFile = toml::from_str(&text).map_err(|source| Error::Toml {
        path: path.to_path_buf(),
        source,
    })?;
    if file.version != KEY_FILE_VERSION {
        return Err(Error::Invalid {
            path: path.to_path_buf(),
            what: format!(
                "key file version {} is not {KEY_FILE_VERSION}",
                file.version
            ),
        });
    }
    Ok(file)
}

/// Parse a 32-byte PSK from 64 hex characters.
///
/// # Errors
///
/// A human-readable reason if the text is not exactly 32 bytes of hex.
pub fn parse_psk(text: &str) -> Result<SharedSecret, String> {
    let bytes = hex_decode(text.trim())?;
    let len = bytes.len();
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| format!("preshared key is {len} bytes, not 32"))?;
    Ok(SharedSecret::new(bytes))
}

/// Load a PSK from a file, enforcing the private-key permission policy.
///
/// Returns the key and, when the override allowed a loose mode, the warning the
/// caller should log.
///
/// # Errors
///
/// [`Error::KeyPermissions`] for a group/world-readable file without the
/// override, or an I/O/parse failure naming the path.
pub fn load_psk(
    path: &Path,
    allow_insecure: bool,
) -> Result<(SharedSecret, Option<String>), Error> {
    let warning = check_permissions(path, allow_insecure)?;
    let text = fs::read_to_string(path).map_err(|source| Error::IoPath {
        action: "read PSK file",
        path: path.to_path_buf(),
        source,
    })?;
    let psk = parse_psk(&text).map_err(|why| Error::Invalid {
        path: path.to_path_buf(),
        what: format!("PSK file: {why}"),
    })?;
    Ok((psk, warning))
}

/// Write a private-key file, for its owner's eyes only.
///
/// Created with mode `0600` *at open time* rather than `chmod` afterwards, so
/// there is no window in which the seed is readable by anyone else. An existing
/// file is never overwritten.
///
/// # Errors
///
/// If the file already exists, or cannot be created or written.
pub fn save_secret(path: &Path, file: &SecretFile) -> Result<(), Error> {
    let body = render_secret(file);
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut handle = options.open(path).map_err(|source| {
        let action = if source.kind() == std::io::ErrorKind::AlreadyExists {
            "refusing to overwrite key file"
        } else {
            "create key file"
        };
        Error::IoPath {
            action,
            path: path.to_path_buf(),
            source,
        }
    })?;
    handle
        .write_all(body.as_bytes())
        .map_err(|source| Error::IoPath {
            action: "write key file",
            path: path.to_path_buf(),
            source,
        })?;
    Ok(())
}

/// The exact bytes a key file holds, with the comments a key file wants.
#[must_use]
pub fn render_secret(file: &SecretFile) -> String {
    format!(
        "# Vallum private key. Keep this file readable only by the daemon's user.\n\
         # The seed is the whole secret: the key pair is derived from it, and it\n\
         # must never be copied anywhere you would not put the key itself.\n\
         version = {}\n\
         suite = {}   # 0x{:04x} {}\n\
         seed = \"{}\"\n\
         signing = {}\n",
        file.version,
        file.suite,
        file.suite,
        describe_suite(file.suite),
        file.seed,
        file.signing,
    )
}

/// Expand a secret file into a usable static identity.
///
/// # Errors
///
/// If the file's suite is not `suite`'s, if the seed is not 32 bytes of hex, or
/// if key generation fails.
pub fn identity(suite: &dyn CryptoSuite, file: &SecretFile) -> Result<StaticIdentity, Error> {
    if file.suite != suite.suite_id() {
        return Err(key_error(
            "private key suite does not match the daemon's",
            format!(
                "key file says {} (0x{:04x}, {}), daemon speaks 0x{:04x} ({})",
                file.suite,
                file.suite,
                describe_suite(file.suite),
                suite.suite_id(),
                describe_suite(suite.suite_id()),
            ),
        ));
    }
    let mut seed_bytes =
        hex_decode(&file.seed).map_err(|why| key_error("private key seed is not hex", why))?;
    let seed: [u8; 32] = seed_bytes.as_slice().try_into().map_err(|_| {
        key_error(
            "private key seed is the wrong length",
            format!("expected 32 bytes, found {}", seed_bytes.len()),
        )
    })?;
    scrub(&mut seed_bytes);

    let identity = if file.signing {
        StaticIdentity::generate_with_signing(suite, &seed)
    } else {
        StaticIdentity::generate(suite, &seed)
    }
    .map_err(|e| key_error("the suite refused to expand the private key", e.to_string()))?;
    Ok(identity)
}

/// Refuse a private key file that a group or the world can read.
///
/// P6.5 accepted this as F7 ("warn, do not refuse"). That disposition is
/// reversed here: a warning in a log is not a control, and the file is the one
/// thing whose exposure makes every other security property moot. The override
/// exists because there are deliberate cases (a sealed volume, a test fixture),
/// and when it is used the exposure is still returned so it can be logged.
///
/// # Errors
///
/// [`Error::KeyPermissions`] when the mode is loose and `allow_insecure` is
/// false.
pub fn check_permissions(path: &Path, allow_insecure: bool) -> Result<Option<String>, Error> {
    let Some(detail) = permission_warning(path) else {
        return Ok(None);
    };
    if allow_insecure {
        Ok(Some(detail))
    } else {
        Err(Error::KeyPermissions {
            path: path.to_path_buf(),
            detail,
        })
    }
}

/// Describe why a key file is readable by anyone but its owner, if it is.
///
/// Returns the warning rather than logging it, so the caller decides where it
/// goes and a test can assert on it.
#[must_use]
pub fn permission_warning(path: &Path) -> Option<String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(path).ok()?.permissions().mode();
        if mode & 0o077 != 0 {
            return Some(format!(
                "{} is mode {:04o}; anyone in its group or the world can read \
                 the private key (chmod 600)",
                path.display(),
                mode & 0o7777
            ));
        }
    }
    None
}

// ── the public line ──────────────────────────────────────────────────

/// Encode a peer's public identity as one pasteable line.
#[must_use]
pub fn encode_public(suite_id: u16, identity: &PeerIdentity) -> String {
    let kem = hex_encode(identity.kem().as_bytes());
    let signing = identity
        .signing()
        .map_or_else(|| "-".to_owned(), |pk| hex_encode(pk.as_bytes()));
    format!("{PUBLIC_TAG}:{suite_id:04x}:{kem}:{signing}")
}

/// A public line, and the suite it names.
pub type DecodedPublic = (u16, PeerIdentity);

/// Decode a public line.
///
/// Whitespace anywhere in the line is ignored, so a wrapped key still loads. See
/// the module docs.
///
/// # Errors
///
/// If the tag, the field count, the suite, or either key is wrong.
pub fn decode_public(text: &str) -> Result<DecodedPublic, Error> {
    // Every field is hex, and hex contains no whitespace, so removing it cannot
    // change the meaning of a well-formed line — it can only rescue one that was
    // wrapped by an editor.
    let compact: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    let text = compact.as_str();
    let fields: Vec<&str> = text.split(':').collect();
    if fields.len() != 4 {
        return Err(key_error(
            "public key line has the wrong number of fields",
            format!(
                "expected `{PUBLIC_TAG}:<suite>:<kem>:<signing|->`, found {} fields",
                fields.len()
            ),
        ));
    }
    if fields[0] != PUBLIC_TAG {
        return Err(key_error(
            "public key line has the wrong tag",
            format!("expected `{PUBLIC_TAG}`, found `{}`", fields[0]),
        ));
    }
    let suite = u16::from_str_radix(fields[1], 16)
        .map_err(|why| key_error("public key suite field is not hex", why.to_string()))?;
    let kem_bytes =
        hex_decode(fields[2]).map_err(|why| key_error("public key KEM field is not hex", why))?;
    if kem_bytes.is_empty() {
        return Err(key_error("public key KEM field is empty", "no key bytes"));
    }
    let identity = if fields[3] == "-" {
        PeerIdentity::kem_only(KemPublicKey::new(kem_bytes))
    } else {
        let signing_bytes = hex_decode(fields[3])
            .map_err(|why| key_error("public key signing field is not hex", why))?;
        if signing_bytes.is_empty() {
            return Err(key_error(
                "public key signing field is empty",
                "no key bytes",
            ));
        }
        PeerIdentity::with_signing(
            KemPublicKey::new(kem_bytes),
            SignPublicKey::new(signing_bytes),
        )
    };
    Ok((suite, identity))
}

/// Where the daemon expects a key file when the config names none.
#[must_use]
pub fn default_secret_path(interface: &str) -> PathBuf {
    PathBuf::from(format!("/etc/vallum/{interface}.key"))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used)]

    use super::*;

    #[test]
    fn hex_round_trips_and_rejects_junk() {
        assert_eq!(hex_encode(&[0x00, 0x0f, 0xff]), "000fff");
        assert_eq!(hex_decode("000fff").unwrap(), vec![0x00, 0x0f, 0xff]);
        assert!(hex_decode("abc").is_err());
        assert!(hex_decode("zz").is_err());
    }

    #[test]
    fn a_public_line_round_trips() {
        let identity = PeerIdentity::kem_only(KemPublicKey::new(vec![0xab; 1190]));
        let line = encode_public(0x0003, &identity);
        assert!(line.starts_with("vallum1:0003:abab"));
        assert!(line.ends_with(":-"));
        let (suite, decoded) = decode_public(&line).unwrap();
        assert_eq!(suite, 0x0003);
        assert_eq!(decoded, identity);
    }

    #[test]
    fn a_public_line_with_signing_round_trips() {
        let identity = PeerIdentity::with_signing(
            KemPublicKey::new(vec![0x01; 1216]),
            SignPublicKey::new(vec![0x02; 1793]),
        );
        let line = encode_public(0x0002, &identity);
        let (suite, decoded) = decode_public(&line).unwrap();
        assert_eq!(suite, 0x0002);
        assert_eq!(decoded, identity);
        assert!(decoded.signing().is_some());
    }

    #[test]
    fn a_wrapped_public_line_still_loads() {
        let identity = PeerIdentity::kem_only(KemPublicKey::new(vec![0xab; 1190]));
        let line = encode_public(0x0003, &identity);

        // The shape an editor leaves behind when it wraps a 4.7 KB line: breaks
        // in the middle of the hex, plus indentation.
        let (head, tail) = line.split_at(600);
        let wrapped = format!("  {head}\n  {tail}\n");

        let (suite, decoded) = decode_public(&wrapped).expect("a wrapped line must load");
        assert_eq!(suite, 0x0003);
        assert_eq!(decoded, identity);
    }

    #[test]
    fn a_malformed_public_line_is_refused() {
        for bad in [
            "",
            "vallum1:0003:abcd",
            "vallum0:0003:abcd:-",
            "vallum1:zzzz:abcd:-",
            "vallum1:0003:zz:-",
            "vallum1:0003::-",
            "vallum1:0003:abcd:-:extra",
        ] {
            assert!(decode_public(bad).is_err(), "accepted `{bad}`");
        }
    }

    #[test]
    fn rendering_a_secret_file_parses_back() {
        let file = new_secret(0x0003, true, [0x5a; 32]);
        let rendered = render_secret(&file);
        let parsed: SecretFile = toml::from_str(&rendered).unwrap();
        assert_eq!(parsed.version, file.version);
        assert_eq!(parsed.suite, file.suite);
        assert_eq!(parsed.seed, file.seed);
        assert!(parsed.signing);
    }
}
