// SPDX-License-Identifier: Apache-2.0

//! `keygen`, `pubkey`, and `genpsk`.

use std::path::PathBuf;

use clap::Args;
use serde_json::{json, Value};
use vallum_crypto_sdk::SdkSuite;

use crate::entropy;
use crate::keys;
use crate::Error;

#[derive(Debug, Args)]
pub struct KeygenArgs {
    /// Where to write the private key. Refuses to overwrite an existing file.
    #[arg(long, short, alias = "key", value_name = "FILE")]
    output: PathBuf,

    /// The suite id, decimal or `0x`-prefixed hex. Defaults to the tri-hybrid.
    #[arg(long, default_value = "3", value_name = "ID")]
    suite: String,

    /// Also derive a hybrid signing key pair, turning on P3 identity.
    #[arg(long)]
    signing: bool,
    /// Emit JSON instead of the bare public line, so an agent can read the answer.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
pub struct PubkeyArgs {
    /// The private key to read.
    #[arg(long, short = 'k', alias = "key", value_name = "FILE")]
    private_key: PathBuf,
}

#[derive(Debug, Args)]
pub struct OpenTicketArgs {
    /// The device private key the ticket was sealed to.
    #[arg(long, short = 'k', alias = "key", value_name = "FILE")]
    private_key: PathBuf,

    /// The AAD the ticket was sealed with (`account_id || public_line`).
    #[arg(long, value_name = "AAD")]
    aad: String,

    /// The sealed-ticket JSON file (`kem_ct`/`nonce`/`ct`); reads stdin when omitted.
    #[arg(long, value_name = "FILE")]
    sealed: Option<PathBuf>,
}

/// Device-pull (ADR-0049): open a ticket sealed to this device's KEM key, printing
/// the plaintext join ticket for `vallum join`. The seal is verified against the
/// AAD, so a blob bound to another account/device does not open.
pub fn open_ticket(args: &OpenTicketArgs) -> Result<(), Error> {
    let secret = keys::load_secret(&args.private_key)?;
    let suite = SdkSuite::from_id(secret.suite)
        .map_err(|e| Error::Suite(format!("key suite 0x{:04x}: {e}", secret.suite)))?;
    let identity = keys::identity(&suite, &secret)?;
    let text = match &args.sealed {
        Some(path) => std::fs::read_to_string(path).map_err(|source| Error::IoPath {
            action: "read sealed ticket",
            path: path.clone(),
            source,
        })?,
        None => {
            use std::io::Read;
            let mut buf = String::new();
            std::io::stdin().read_to_string(&mut buf).map_err(Error::Io)?;
            buf
        }
    };
    let sealed = crate::seal::SealedTicket::from_json(&text).map_err(Error::Usage)?;
    let ticket = crate::seal::open_ticket(&suite, &sealed, identity.secret(), args.aad.as_bytes())
        .map_err(Error::Usage)?;
    let ticket = String::from_utf8(ticket)
        .map_err(|_| Error::Usage("sealed ticket did not open to a join ticket".to_owned()))?;
    println!("{}", ticket.trim());
    Ok(())
}

pub fn genpsk() -> Result<(), Error> {
    let mut psk = [0u8; 32];
    getrandom::fill(&mut psk)
        .map_err(|e| Error::Io(std::io::Error::other(format!("getrandom: {e}"))))?;
    println!("{}", keys::hex_encode(&psk));
    Ok(())
}

pub fn keygen(args: &KeygenArgs) -> Result<(), Error> {
    let suite_id = parse_suite(&args.suite)?;
    // Refuse to write a key for a suite this build cannot expand.
    let suite = SdkSuite::from_id(suite_id)
        .map_err(|e| Error::Suite(format!("suite `{}`: {e}", args.suite)))?;

    let file = keys::new_secret(suite_id, args.signing, entropy::seed());
    let identity = keys::identity(&suite, &file)?;
    keys::save_secret(&args.output, &file)?;
    let public = keys::encode_public(suite_id, &identity.to_peer());

    if args.json {
        emit(&json!({
            "action": "keygen",
            "output": args.output.display().to_string(),
            "suite": suite_id,
            "signing": args.signing,
            "public": public,
        }))?;
    } else {
        // The bare line is the interface: operators redirect it into a `.pub` file.
        println!("{public}");
    }
    if !args.json {
        // Under `--json` the object above already says all of this, and some
        // transports hand the agent stdout and stderr as one text — a note
        // here would stop the object parsing.
        eprintln!(
            "vallum: wrote {} ({}, {})",
            args.output.display(),
            keys::describe_suite(suite_id),
            if args.signing {
                "with signing"
            } else {
                "KEM-only"
            },
        );
    }
    Ok(())
}

/// Print one JSON object.
///
/// Failures are not JSON: they keep the exit-1/stdout-silent contract in
/// `docs/deployment/automation.md`, and a caller that wants the reason reads
/// stderr the same way it does for every other verb.
fn emit(report: &Value) -> Result<(), Error> {
    println!(
        "{}",
        serde_json::to_string_pretty(report)
            .map_err(|error| Error::Usage(format!("json: {error}")))?
    );
    Ok(())
}

/// `pubkey`.
pub fn pubkey(args: &PubkeyArgs, allow_insecure_key: bool) -> Result<(), Error> {
    // Reading the key at all is the exposure, so `pubkey` enforces the same rule
    // as `run`: the mode is checked before the file is read.
    if let Some(warning) = keys::check_permissions(&args.private_key, allow_insecure_key)? {
        eprintln!("vallum: warning: {warning} (allowed by --allow-insecure-key-permissions)");
    }
    let file = keys::load_secret(&args.private_key)?;
    let suite = SdkSuite::from_id(file.suite)
        .map_err(|e| Error::Suite(format!("key file names a suite this build cannot use: {e}")))?;
    let identity = keys::identity(&suite, &file)?;
    println!("{}", keys::encode_public(file.suite, &identity.to_peer()));
    Ok(())
}

/// Parse a suite id, accepting `3` and `0x0003`.
pub fn parse_suite(text: &str) -> Result<u16, Error> {
    let text = text.trim();
    let parsed = if let Some(hex) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        u16::from_str_radix(hex, 16)
    } else {
        text.parse::<u16>()
    };
    parsed.map_err(|e| {
        Error::Usage(format!(
            "suite `{text}` is not an id (decimal, or hex with a 0x prefix): {e}"
        ))
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use clap::Parser;

    use super::*;

    #[derive(Parser, Debug)]
    struct KeygenCli {
        #[command(flatten)]
        args: KeygenArgs,
    }

    #[derive(Parser, Debug)]
    struct PubkeyCli {
        #[command(flatten)]
        args: PubkeyArgs,
    }

    #[test]
    fn key_alias_is_accepted_for_keygen_output() {
        let cli = KeygenCli::try_parse_from(["keygen", "--key", "/path/to/key"]).unwrap();
        assert_eq!(cli.args.output, PathBuf::from("/path/to/key"));
    }

    #[test]
    fn key_alias_is_accepted_for_pubkey_private_key() {
        let cli = PubkeyCli::try_parse_from(["pubkey", "--key", "/path/to/key"]).unwrap();
        assert_eq!(cli.args.private_key, PathBuf::from("/path/to/key"));
    }
}
