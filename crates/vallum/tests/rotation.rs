// SPDX-License-Identifier: Apache-2.0

//! Rotation through the binary: the old key keeps working until `finalize`.
//!
//! The handshake behaviour is tested in `pentest.rs`; these tests prove the
//! operator path — the file is edited so both keys are accepted, and finalize
//! retires the old one — and that the generated config still loads.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::{Path, PathBuf};
use std::process::Command;

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_vallum"))
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("vallum-rotation-{}-{name}", std::process::id()));
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

fn keygen(dir: &Path, name: &str) -> String {
    let key = dir.join(format!("{name}.key"));
    let (ok, stdout, stderr) = run(bin()
        .args(["keygen", "--output"])
        .arg(&key)
        .args(["--suite", "3"]));
    assert!(ok, "{stderr}");
    stdout.trim().to_owned()
}

#[test]
fn rotate_installs_the_new_key_and_keeps_the_old_one_until_finalize() {
    let dir = scratch("basic");
    let config = init(&dir);
    let old = keygen(&dir, "laptop");
    let new = keygen(&dir, "laptop2");

    let (ok, _, stderr) = run(bin()
        .args(["peer", "add", "laptop", "--config"])
        .arg(&config)
        .args([
            "--public-key",
            &old,
            "--endpoint",
            "203.0.113.5",
            "--no-apply",
        ]));
    assert!(ok, "{stderr}");

    let (ok, stdout, stderr) = run(bin()
        .args(["peer", "rotate", "laptop", "--config"])
        .arg(&config)
        .args(["--public-key", &new, "--no-apply"]));
    assert!(ok, "{stdout}{stderr}");
    assert!(stdout.contains("kept as previous"), "{stdout}");

    // The file accepts both keys: the new one is current, the old one is previous.
    let parsed = vallum_config::Config::load(&config).unwrap();
    assert_eq!(parsed.peers[0].public_key.as_deref(), Some(new.as_str()));
    assert_eq!(
        parsed.peers[0].previous_public_key.as_deref(),
        Some(old.as_str())
    );
    // And the daemon accepts the pair.
    let (ok, stdout, stderr) = run(bin().args(["doctor", "--config"]).arg(&config));
    let report = format!("{stdout}{stderr}");
    assert!(report.contains("PASS  config"), "{report}");
    assert!(report.contains("WARN  rotation"), "{report}");
    assert!(ok || report.contains("control"), "{report}");

    let (ok, stdout, _) = run(bin()
        .args(["peer", "list", "--config"])
        .arg(&config)
        .arg("--json"));
    assert!(ok);
    let rows: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(rows[0]["rotating"], true);

    // Finalize retires the old key, and the config still loads.
    let (ok, stdout, stderr) = run(bin()
        .args(["peer", "finalize", "laptop", "--config"])
        .arg(&config)
        .arg("--no-apply"));
    assert!(ok, "{stdout}{stderr}");
    assert!(stdout.contains("no longer accepted"), "{stdout}");
    let parsed = vallum_config::Config::load(&config).unwrap();
    assert!(parsed.peers[0].previous_public_key.is_none());
    assert_eq!(parsed.peers[0].public_key.as_deref(), Some(new.as_str()));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn rotate_with_a_bundle_generates_a_new_key_without_overwriting_the_old_one() {
    let dir = scratch("bundle");
    let config = init(&dir);
    let old = keygen(&dir, "phone");
    let (ok, _, stderr) = run(bin()
        .args(["peer", "add", "phone", "--config"])
        .arg(&config)
        .args([
            "--public-key",
            &old,
            "--endpoint",
            "203.0.113.5",
            "--no-apply",
        ]));
    assert!(ok, "{stderr}");

    let bundle = dir.join("phone-rotated.vallum-bundle");
    let (ok, stdout, stderr) = run(bin()
        .args(["peer", "rotate", "phone", "--config"])
        .arg(&config)
        .args(["--endpoint", "203.0.113.5", "--ship-key", "--bundle-out"])
        .arg(&bundle)
        .arg("--forget-key")
        .arg("--no-apply"));
    assert!(ok, "{stdout}{stderr}");
    assert!(bundle.exists());

    // The bundle imports as a working config with the client's key name.
    let imported = dir.join("imported");
    let (ok, _, stderr) = run(bin()
        .arg("import-bundle")
        .arg(&bundle)
        .args(["--output-dir"])
        .arg(&imported));
    assert!(ok, "{stderr}");
    vallum_config::Config::load(&imported.join("phone.toml")).unwrap();
    assert!(imported.join("phone.key").exists());

    // The previous key is still accepted.
    let parsed = vallum_config::Config::load(&config).unwrap();
    assert!(parsed.peers[0].previous_public_key.is_some());

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn rotating_a_peer_that_does_not_exist_is_an_error() {
    let dir = scratch("missing");
    let config = init(&dir);
    let new = keygen(&dir, "laptop");
    let (ok, _, stderr) = run(bin()
        .args(["peer", "rotate", "ghost", "--config"])
        .arg(&config)
        .args(["--public-key", &new, "--no-apply"]));
    assert!(!ok);
    assert!(stderr.contains("no peer named"), "{stderr}");

    let _ = std::fs::remove_dir_all(&dir);
}
