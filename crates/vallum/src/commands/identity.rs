// SPDX-License-Identifier: Apache-2.0

//! `vallum identity`: issue, self-sign, verify, and inspect identity documents.
//!
//! A document binds a peer's KEM key and signing key to a label and a validity
//! window. `vallum-core` implements the whole certificate path — `issue`,
//! `self_sign`, `is_valid_at`, `encode`/`decode`, `to_peer` — and nothing
//! exposed it. This is the operator surface: a CA key is just another key file,
//! and a document is the hex of its TLV encoding.

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use clap::{Args, Subcommand};
use serde::Serialize;
use vallum_core::identity::{IdentityDocument, Validity};
use vallum_crypto::CryptoSuite;
use vallum_crypto_sdk::SdkSuite;

use crate::commands::keys::parse_suite;
use crate::{keys, say, Error};

#[derive(Debug, Args)]
pub struct IdentityArgs {
    #[command(subcommand)]
    pub command: IdentityCommand,
}

#[derive(Debug, Subcommand)]
pub enum IdentityCommand {
    /// Issue a document signed by a CA key.
    Issue(IssueArgs),
    /// Issue a document signed by the peer's own key.
    SelfSign(SelfSignArgs),
    /// Check a document's signature and window.
    Verify(VerifyArgs),
    /// Print a document's label, keys and window without verifying it.
    Show(ShowArgs),
}

#[derive(Debug, Args)]
pub struct IssueArgs {
    /// The CA key, which must carry a signing half (`keygen --signing`).
    #[arg(long, value_name = "FILE")]
    pub ca_key: PathBuf,

    /// The peer's public line, which must carry a signing key.
    #[arg(long, value_name = "LINE", conflicts_with = "peer_public_file")]
    pub peer_public: Option<String>,

    /// A file holding the peer's public line.
    #[arg(long, value_name = "FILE")]
    pub peer_public_file: Option<PathBuf>,

    /// A name for the document, for logs and `peer show`.
    #[arg(long, value_name = "NAME")]
    pub label: String,

    /// How long the document is valid, in days.
    #[arg(long, value_name = "DAYS", default_value_t = 90)]
    pub days: u64,

    /// The first second the document is valid. Defaults to now.
    #[arg(long, value_name = "UNIX")]
    pub not_before: Option<u64>,

    /// Write the document here (0600) instead of stdout.
    #[arg(long, value_name = "FILE")]
    pub output: Option<PathBuf>,

    /// Emit JSON instead of the document text.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct SelfSignArgs {
    /// The peer's own key, which must carry a signing half.
    #[arg(long, value_name = "FILE")]
    pub key: PathBuf,

    /// A name for the document.
    #[arg(long, value_name = "NAME")]
    pub label: String,

    /// How long the document is valid, in days.
    #[arg(long, value_name = "DAYS", default_value_t = 90)]
    pub days: u64,

    /// The first second the document is valid. Defaults to now.
    #[arg(long, value_name = "UNIX")]
    pub not_before: Option<u64>,

    /// Write the document here (0600) instead of stdout.
    #[arg(long, value_name = "FILE")]
    pub output: Option<PathBuf>,

    /// Emit JSON instead of the document text.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct VerifyArgs {
    /// A file holding the issuer's `vallum1:` public line — what `vallum
    /// keygen` prints. Verification never needs the CA's private key.
    #[arg(long, value_name = "FILE", conflicts_with = "issuer_public")]
    pub issuer: Option<PathBuf>,

    /// The issuer's public line, instead of a file.
    #[arg(long, value_name = "LINE")]
    pub issuer_public: Option<String>,

    /// The document to check.
    #[arg(long, value_name = "FILE")]
    pub document: PathBuf,

    /// The suite to verify a self-signed document with.
    #[arg(long, value_name = "ID", default_value = "3")]
    pub suite: String,

    /// Emit JSON instead of a report.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct ShowArgs {
    /// The document to inspect.
    #[arg(long, value_name = "FILE")]
    pub document: PathBuf,

    /// The suite the document was encoded under.
    #[arg(long, value_name = "ID", default_value = "3")]
    pub suite: String,

    /// Emit JSON instead of a report.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Serialize)]
struct Issued {
    document: String,
    label: String,
    not_before: u64,
    not_after: u64,
    days: u64,
    suite: String,
    fingerprint: String,
    self_signed: bool,
}

#[derive(Debug, Serialize)]
struct Verified {
    valid: bool,
    label: String,
    not_before: u64,
    not_after: u64,
    days_remaining: i64,
    self_signed: bool,
    issuer_signed: bool,
    fingerprint: String,
}

/// `vallum identity`.
///
/// # Errors
///
/// A key without a signing half, a public line without one, a document that does
/// not decode, or a signature that does not verify.
pub fn identity(args: &IdentityArgs) -> Result<(), Error> {
    match &args.command {
        IdentityCommand::Issue(args) => issue(args),
        IdentityCommand::SelfSign(args) => self_sign(args),
        IdentityCommand::Verify(args) => verify(args),
        IdentityCommand::Show(args) => show(args),
    }
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

fn window(not_before: Option<u64>, days: u64) -> Validity {
    let start = not_before.unwrap_or_else(now_unix);
    Validity::new(start, start.saturating_add(days.saturating_mul(86_400)))
}

fn suite_of(suite_id: u16) -> Result<SdkSuite, Error> {
    SdkSuite::from_id(suite_id).map_err(|error| Error::Suite(error.to_string()))
}

fn fingerprint(suite: &dyn CryptoSuite, document: &[u8]) -> String {
    let hash = suite.hash(b"vallum/identity/fingerprint/v1", document);
    keys::hex_encode(&hash[..6])
}

fn issue(args: &IssueArgs) -> Result<(), Error> {
    let ca = keys::load_secret(&args.ca_key)?;
    let suite = suite_of(ca.suite)?;
    let ca_identity = keys::identity(&suite, &ca)?;
    let Some(ca_signing) = ca_identity.signing() else {
        return Err(Error::Usage(format!(
            "{} is a KEM-only key; issue a CA key with `vallum keygen --signing`",
            args.ca_key.display()
        )));
    };

    let line = match (&args.peer_public, &args.peer_public_file) {
        (Some(line), None) => line.trim().to_owned(),
        (None, Some(path)) => std::fs::read_to_string(path)
            .map_err(|source| Error::IoPath {
                action: "read public line",
                path: path.clone(),
                source,
            })?
            .trim()
            .to_owned(),
        _ => {
            return Err(Error::Usage(
                "give exactly one of --peer-public LINE or --peer-public-file FILE".to_owned(),
            ))
        }
    };
    let (peer_suite, peer) = keys::decode_public(&line)?;
    if peer_suite != ca.suite {
        return Err(Error::Usage(format!(
            "the peer's public line is for suite 0x{peer_suite:04x}, but the CA key is \
             0x{:04x}; a document is signed under one suite",
            ca.suite
        )));
    }
    let Some(peer_signing) = peer.signing() else {
        return Err(Error::Usage(
            "the peer's public line has no signing key; generate it with \
             `vallum keygen --signing`"
                .to_owned(),
        ));
    };

    let validity = window(args.not_before, args.days);
    let document = IdentityDocument::issue(
        &suite,
        args.label.as_bytes(),
        peer.kem().clone(),
        peer_signing.clone(),
        validity,
        ca_signing.secret(),
    )
    .map_err(|error| Error::Identity(error.to_string()))?;
    emit(
        &suite,
        &document,
        &args.label,
        args.days,
        args.output.as_deref(),
        args.json,
        false,
    )
}

fn self_sign(args: &SelfSignArgs) -> Result<(), Error> {
    let secret = keys::load_secret(&args.key)?;
    let suite = suite_of(secret.suite)?;
    let identity = keys::identity(&suite, &secret)?;
    if identity.signing().is_none() {
        return Err(Error::Usage(format!(
            "{} is a KEM-only key; generate it with `vallum keygen --signing`",
            args.key.display()
        )));
    }
    let validity = window(args.not_before, args.days);
    let document = IdentityDocument::self_sign(&suite, &identity, args.label.as_bytes(), validity)
        .map_err(|error| Error::Identity(error.to_string()))?;
    emit(
        &suite,
        &document,
        &args.label,
        args.days,
        args.output.as_deref(),
        args.json,
        true,
    )
}

#[allow(clippy::too_many_arguments)]
fn emit(
    suite: &SdkSuite,
    document: &IdentityDocument,
    label: &str,
    days: u64,
    output: Option<&Path>,
    json: bool,
    self_signed: bool,
) -> Result<(), Error> {
    let bytes = document
        .encode(suite.suite_id())
        .map_err(|error| Error::Identity(error.to_string()))?;
    let text = keys::hex_encode(&bytes);
    let validity = document.validity();
    if let Some(path) = output {
        write_private(path, text.as_bytes())?;
    }
    if json {
        let issued = Issued {
            document: text,
            label: label.to_owned(),
            not_before: validity.not_before,
            not_after: validity.not_after,
            days,
            suite: format!("0x{:04x}", suite.suite_id()),
            fingerprint: fingerprint(suite, &bytes),
            self_signed,
        };
        say!(
            "{}",
            serde_json::to_string_pretty(&issued)
                .map_err(|error| Error::Usage(format!("json: {error}")))?
        );
        return Ok(());
    }
    if let Some(path) = output {
        say!("document {}", path.display());
        say!(
            "   label      {label}\n   window     {} .. {} ({days} days)\n   fingerprint {}",
            validity.not_before,
            validity.not_after,
            fingerprint(suite, &bytes)
        );
    } else {
        // stdout carries the document alone, so it can be redirected.
        say!("{text}");
    }
    Ok(())
}

/// The suite and signing key an issuer's `vallum1:` public line names.
fn issuer_from_line(line: &str) -> Result<(SdkSuite, vallum_crypto::SignPublicKey), Error> {
    let (suite_id, identity) = keys::decode_public(line)?;
    let suite = suite_of(suite_id)?;
    let Some(signing) = identity.signing() else {
        return Err(Error::Usage(
            "the issuer's public line is KEM-only; a CA needs `vallum keygen --signing`".to_owned(),
        ));
    };
    Ok((suite, signing.clone()))
}

fn verify(args: &VerifyArgs) -> Result<(), Error> {
    let (suite, issuer) = match (&args.issuer, &args.issuer_public) {
        (Some(path), None) => {
            let text = std::fs::read_to_string(path).map_err(|source| Error::IoPath {
                action: "read the issuer's public line",
                path: path.clone(),
                source,
            })?;
            let (suite, signing) = issuer_from_line(text.trim()).map_err(|error| {
                // A private key file is the natural mistake here: it is the
                // CA's other artifact, and its name suggests it is the answer.
                if text.trim_start().starts_with("version") || text.contains("seed") {
                    Error::Usage(format!(
                        "{} looks like a private key file; --issuer takes the CA's public line \
                         (`vallum keygen … > ca.pub`), which is all verification needs",
                        path.display()
                    ))
                } else {
                    error
                }
            })?;
            (suite, Some(signing))
        }
        (None, Some(line)) => {
            let (suite, signing) = issuer_from_line(line)?;
            (suite, Some(signing))
        }
        _ => {
            let suite = suite_of(parse_suite(&args.suite)?)?;
            (suite, None)
        }
    };

    let document = read_document(&args.document)?;
    let now = now_unix();
    let validity = document.validity();
    let self_signed = document.is_self_signed(&suite);
    let issuer_signed = issuer
        .as_ref()
        .is_some_and(|issuer| document.is_valid(&suite, issuer));
    let valid = match &issuer {
        Some(issuer) => document.is_valid_at(&suite, issuer, now),
        None => self_signed && validity.contains(now),
    };

    if args.json {
        let report = Verified {
            valid,
            label: String::from_utf8_lossy(document.label()).into_owned(),
            not_before: validity.not_before,
            not_after: validity.not_after,
            days_remaining: days_remaining(validity, now),
            self_signed,
            issuer_signed,
            fingerprint: fingerprint(&suite, &encode(&suite, &document)?),
        };
        say!(
            "{}",
            serde_json::to_string_pretty(&report)
                .map_err(|error| Error::Usage(format!("json: {error}")))?
        );
    } else {
        say!(
            "{}  {}",
            if valid { "VALID  " } else { "INVALID" },
            String::from_utf8_lossy(document.label())
        );
        say!(
            "   window      {} .. {} ({} days remaining)",
            validity.not_before,
            validity.not_after,
            days_remaining(validity, now)
        );
        say!(
            "   signature   {}",
            if issuer.is_some() {
                if issuer_signed {
                    "matches the issuer"
                } else {
                    "does not match the issuer"
                }
            } else if self_signed {
                "self-signed"
            } else {
                "not self-signed, and no issuer given"
            }
        );
    }
    if valid {
        Ok(())
    } else {
        Err(Error::Usage("the document is not valid".to_owned()))
    }
}

fn show(args: &ShowArgs) -> Result<(), Error> {
    let suite = suite_of(parse_suite(&args.suite)?)?;
    let document = read_document(&args.document)?;
    let validity = document.validity();
    let now = now_unix();
    let bytes = encode(&suite, &document)?;
    if args.json {
        let report = Verified {
            valid: validity.contains(now),
            label: String::from_utf8_lossy(document.label()).into_owned(),
            not_before: validity.not_before,
            not_after: validity.not_after,
            days_remaining: days_remaining(validity, now),
            self_signed: document.is_self_signed(&suite),
            issuer_signed: false,
            fingerprint: fingerprint(&suite, &bytes),
        };
        say!(
            "{}",
            serde_json::to_string_pretty(&report)
                .map_err(|error| Error::Usage(format!("json: {error}")))?
        );
        return Ok(());
    }
    say!("document {}", String::from_utf8_lossy(document.label()));
    say!("   suite       0x{:04x}", suite.suite_id());
    say!("   kem         {} bytes", document.kem().len());
    say!("   signing     {} bytes", document.signing().len());
    say!(
        "   window      {} .. {} ({} days remaining)",
        validity.not_before,
        validity.not_after,
        days_remaining(validity, now)
    );
    say!(
        "   signature   {}",
        if document.is_self_signed(&suite) {
            "self-signed"
        } else {
            "issued by another key (use `identity verify`)"
        }
    );
    say!("   fingerprint {}", fingerprint(&suite, &bytes));
    Ok(())
}

fn encode(suite: &SdkSuite, document: &IdentityDocument) -> Result<Vec<u8>, Error> {
    document
        .encode(suite.suite_id())
        .map_err(|error| Error::Identity(error.to_string()))
}

fn read_document(path: &Path) -> Result<IdentityDocument, Error> {
    let text = std::fs::read_to_string(path).map_err(|source| Error::IoPath {
        action: "read identity document",
        path: path.to_path_buf(),
        source,
    })?;
    let bytes = keys::hex_decode(text.trim()).map_err(Error::Usage)?;
    IdentityDocument::decode(&bytes)
        .map_err(|error| Error::Usage(format!("identity document: {error}")))
}

fn days_remaining(validity: Validity, now: u64) -> i64 {
    let remaining = i64::try_from(validity.not_after).unwrap_or(i64::MAX)
        - i64::try_from(now).unwrap_or(i64::MAX);
    // Round a partial day up, so a document issued for 30 days reads "30 days"
    // a second later rather than "29". An expired window stays negative.
    if remaining > 0 {
        (remaining + 86_399) / 86_400
    } else {
        remaining / 86_400
    }
}

use crate::keys::write_private;

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn a_window_starts_now_and_lasts_the_requested_days() {
        let validity = window(Some(1_000), 2);
        assert_eq!(validity.not_before, 1_000);
        assert_eq!(validity.not_after, 1_000 + 2 * 86_400);
    }

    #[test]
    fn days_remaining_goes_negative_after_expiry() {
        let validity = Validity::new(1_000, 1_000 + 86_400);
        assert_eq!(days_remaining(validity, 1_000), 1);
        assert_eq!(days_remaining(validity, 1_001), 1);
        assert_eq!(days_remaining(validity, 1_000 + 86_400), 0);
        assert_eq!(days_remaining(validity, 1_000 + 3 * 86_400), -2);
    }
}
