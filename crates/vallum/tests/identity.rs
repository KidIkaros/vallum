// SPDX-License-Identifier: Apache-2.0

//! Identity documents, driven through the binary.
//!
//! The certificate path lives in `vallum-core`; these tests prove the operator
//! surface: a document is issued, enrolled, refused when expired or signed by
//! the wrong key, and accepted self-signed only when no issuer is configured.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::{Path, PathBuf};
use std::process::Command;

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_vallum"))
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("vallum-identity-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn run(command: &mut Command) -> (bool, String, String) {
    let output = command.output().unwrap();
    (
        output.status.success(),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

fn init(dir: &Path) -> PathBuf {
    let config = dir.join("vallum0.toml");
    let (ok, _, stderr) = run(bin()
        .args(["server", "init", "--config"])
        .arg(&config)
        .args(["--endpoint", "203.0.113.5", "--no-host", "--no-service"]));
    assert!(ok, "{stderr}");
    config
}

/// Generate a signing key and return (key path, public line).
fn signing_key(dir: &Path, name: &str) -> (PathBuf, String) {
    let key = dir.join(format!("{name}.key"));
    let (ok, stdout, stderr) =
        run(bin()
            .args(["keygen", "--output"])
            .arg(&key)
            .args(["--suite", "3", "--signing"]));
    assert!(ok, "{stderr}");
    (key, stdout.trim().to_owned())
}

/// Put the CA's signing key into the interface as `identity_issuer`.
fn trust(config: &Path, ca_public_line: &str) {
    let signing = ca_public_line.split(':').nth(3).unwrap();
    let text = std::fs::read_to_string(config).unwrap();
    let text = text.replace(
        "fwmark = 4660",
        &format!("fwmark = 4660\nidentity_issuer = \"{signing}\""),
    );
    std::fs::write(config, text).unwrap();
}

fn issue(dir: &Path, ca: &Path, peer_public: &Path, label: &str, days: &str) -> PathBuf {
    let document = dir.join(format!("{label}.identity"));
    let (ok, _, stderr) = run(bin()
        .args(["identity", "issue", "--ca-key"])
        .arg(ca)
        .arg("--peer-public-file")
        .arg(peer_public)
        .args(["--label", label, "--days", days, "--output"])
        .arg(&document));
    assert!(ok, "{stderr}");
    document
}

#[test]
fn a_ca_document_enrols_a_peer_and_its_window_is_visible() {
    let dir = scratch("ca");
    let config = init(&dir);
    let (ca_key, ca_public) = signing_key(&dir, "ca");
    trust(&config, &ca_public);
    let (_peer_key, peer_public) = signing_key(&dir, "laptop");
    let peer_public_file = dir.join("laptop.pub");
    std::fs::write(&peer_public_file, &peer_public).unwrap();

    let document = issue(&dir, &ca_key, &peer_public_file, "laptop", "30");

    let (ok, stdout, stderr) = run(bin()
        .args(["peer", "add", "laptop", "--config"])
        .arg(&config)
        .arg("--identity")
        .arg(&document)
        .arg("--no-apply"));
    assert!(ok, "{stdout}{stderr}");
    assert!(
        stdout.contains("identity    ") && !stdout.contains("identity    -"),
        "{stdout}"
    );

    // The config names the document, not a public key.
    let text = std::fs::read_to_string(&config).unwrap();
    assert!(text.contains("identity_file = \"clients/laptop.identity\""));
    assert!(!text.contains("public_key"));

    let (ok, stdout, _) = run(bin()
        .args(["peer", "list", "--config"])
        .arg(&config)
        .arg("--json"));
    assert!(ok);
    let rows: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let validity = rows[0]["validity"].as_str().unwrap();
    assert!(validity.ends_with('d'), "{validity}");

    // The daemon's own resolver accepts the document and the window.
    let (ok, stdout, stderr) = run(bin().args(["doctor", "--config"]).arg(&config));
    let report = format!("{stdout}{stderr}");
    assert!(report.contains("PASS  config"), "{report}");
    assert!(ok || report.contains("control"), "{report}");

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn an_expired_document_is_refused_at_enrolment() {
    let dir = scratch("expired");
    let config = init(&dir);
    let (ca_key, ca_public) = signing_key(&dir, "ca");
    trust(&config, &ca_public);
    let (_peer_key, peer_public) = signing_key(&dir, "laptop");
    let peer_public_file = dir.join("laptop.pub");
    std::fs::write(&peer_public_file, &peer_public).unwrap();

    let document = issue(&dir, &ca_key, &peer_public_file, "laptop", "0");
    let (ok, _, stderr) = run(bin()
        .args(["peer", "add", "laptop", "--config"])
        .arg(&config)
        .arg("--identity")
        .arg(&document)
        .arg("--no-apply"));
    assert!(!ok);
    assert!(stderr.contains("expired"), "{stderr}");

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_document_from_another_ca_is_refused() {
    let dir = scratch("wrong-ca");
    let config = init(&dir);
    let (other_ca, _other_public) = signing_key(&dir, "other-ca");
    let (trusted_ca, trusted_public) = signing_key(&dir, "trusted-ca");
    trust(&config, &trusted_public);
    let (_peer_key, peer_public) = signing_key(&dir, "laptop");
    let peer_public_file = dir.join("laptop.pub");
    std::fs::write(&peer_public_file, &peer_public).unwrap();

    // Issued by the wrong CA.
    let document = issue(&dir, &other_ca, &peer_public_file, "laptop", "30");
    let (ok, _, stderr) = run(bin()
        .args(["peer", "add", "laptop", "--config"])
        .arg(&config)
        .arg("--identity")
        .arg(&document)
        .arg("--no-apply"));
    assert!(!ok, "a document from an untrusted CA was accepted");
    assert!(stderr.contains("did not verify"), "{stderr}");

    // The trusted CA still works, so the refusal is about the issuer.
    let document = issue(&dir, &trusted_ca, &peer_public_file, "laptop", "30");
    let (ok, _, stderr) = run(bin()
        .args(["peer", "add", "laptop", "--config"])
        .arg(&config)
        .arg("--identity")
        .arg(&document)
        .arg("--no-apply"));
    assert!(ok, "{stderr}");

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_self_signed_document_is_accepted_only_without_an_issuer() {
    let dir = scratch("self-signed");
    let config = init(&dir);
    let (peer_key, _peer_public) = signing_key(&dir, "phone");
    let document = dir.join("phone.identity");
    let (ok, _, stderr) = run(bin()
        .args(["identity", "self-sign", "--key"])
        .arg(&peer_key)
        .args(["--label", "phone", "--days", "10", "--output"])
        .arg(&document));
    assert!(ok, "{stderr}");

    // No issuer configured: a self-signed document is a key binding with a window.
    let (ok, _, stderr) = run(bin()
        .args(["peer", "add", "phone", "--config"])
        .arg(&config)
        .arg("--identity")
        .arg(&document)
        .arg("--no-apply"));
    assert!(ok, "{stderr}");

    // With an issuer configured, a self-signed document is not authorisation.
    let dir2 = scratch("self-signed-ca");
    let config2 = init(&dir2);
    let (_ca, ca_public) = signing_key(&dir2, "ca");
    trust(&config2, &ca_public);
    let (ok, _, stderr) = run(bin()
        .args(["peer", "add", "phone", "--config"])
        .arg(&config2)
        .arg("--identity")
        .arg(&document)
        .arg("--no-apply"));
    assert!(!ok, "a self-signed document was accepted under a CA policy");
    assert!(stderr.contains("did not verify"), "{stderr}");

    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&dir2);
}

#[test]
fn verify_reports_validity_and_exits_nonzero_when_invalid() {
    let dir = scratch("verify");
    let (ca_key, _ca_public) = signing_key(&dir, "ca");
    let (_peer_key, peer_public) = signing_key(&dir, "laptop");
    let peer_public_file = dir.join("laptop.pub");
    std::fs::write(&peer_public_file, &peer_public).unwrap();
    let document = issue(&dir, &ca_key, &peer_public_file, "laptop", "30");

    let (ok, stdout, _) = run(bin()
        .args(["identity", "verify", "--issuer"])
        .arg(&ca_key)
        .arg("--document")
        .arg(&document));
    assert!(ok);
    assert!(stdout.contains("VALID"), "{stdout}");
    assert!(stdout.contains("matches the issuer"), "{stdout}");

    // Verified against the peer's own key, the CA's signature does not match.
    let (ok, stdout, _) = run(bin()
        .args(["identity", "verify", "--issuer-public", &peer_public])
        .arg("--document")
        .arg(&document));
    assert!(!ok);
    assert!(stdout.contains("INVALID"), "{stdout}");

    // `show` needs no issuer and reports the window.
    let (ok, stdout, _) = run(bin()
        .args(["identity", "show", "--document"])
        .arg(&document));
    assert!(ok);
    assert!(stdout.contains("issued by another key"), "{stdout}");

    let _ = std::fs::remove_dir_all(&dir);
}
