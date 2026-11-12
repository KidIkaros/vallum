// SPDX-License-Identifier: Apache-2.0

//! The automation contract in `docs/deployment/automation.md`.
//!
//! Exit 2 means "a precondition was not met and nothing was attempted"; exit 1
//! means "the command failed". Automation depends on the difference: 2 says fix
//! the environment and retry, 1 says surface stderr and do not retry blindly.
//!
//! Found by dogfooding the released binary: `show` and `showconf` exited 1 for a
//! missing control socket while `metrics` exited 2 for the same condition, and a
//! missing config file exited 1 from the control-plane verbs but 2 from the
//! `peer` verbs. `metrics` even disagreed with itself depending on which half of
//! the precondition failed.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::process::Command;

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_vallum"))
}

fn code(args: &[&str]) -> i32 {
    let output = bin().args(args).output().unwrap();
    output
        .status
        .code()
        .unwrap_or_else(|| panic!("{args:?} died on a signal"))
}

#[test]
fn a_missing_config_is_a_precondition_for_every_control_plane_verb() {
    let dir = std::env::temp_dir().join(format!("vallum-exit-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let missing = dir.join("nope.toml");
    let missing = missing.to_str().unwrap();

    for verb in [
        "show", "showconf", "metrics", "setconf", "addconf", "syncconf",
    ] {
        assert_eq!(
            code(&[verb, "--config", missing]),
            2,
            "`{verb}` with a missing config must be a precondition"
        );
    }
    for verb in ["peer", "identity"] {
        assert_eq!(
            code(&[verb, "list", "--config", missing]),
            2,
            "`{verb} list` with a missing config must be a precondition"
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn no_control_socket_is_a_precondition_not_a_failure() {
    // The three verbs that read the daemon must agree. `metrics` already did;
    // `show` and `showconf` did not.
    for verb in ["show", "showconf", "metrics"] {
        assert_eq!(
            code(&[verb]),
            2,
            "`{verb}` with no socket configured must be a precondition"
        );
    }
}

#[test]
fn doctor_reports_its_verdict_as_a_failure_not_a_precondition() {
    // Doctor runs its checks and the answer is "no". That is a failed command
    // (1), not an unmet precondition (2) — something *was* attempted.
    assert_eq!(code(&["doctor"]), 1);
}

#[test]
fn a_client_whose_daemon_is_not_running_fails_the_doctor() {
    // The verdict is the product's headline: "am I protected?". A client whose
    // daemon is not running is NOT protected - nothing is moving its traffic
    // into a tunnel, so every byte goes out in the clear. The doctor used to
    // call that a warning, and a warning does not fail the run, so the command
    // exited 0 - "everything is fine" - while the user was in the open.
    //
    // No daemon is needed to prove it: the report is about the state it finds.
    let dir = std::env::temp_dir().join(format!("vallum-exit-client-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    let key = dir.join("client.key");
    let (ok, stdout, stderr) = bin()
        .args(["keygen", "--output"])
        .arg(&key)
        .args(["--suite", "3"])
        .output()
        .map(|output| {
            (
                output.status.success(),
                String::from_utf8_lossy(&output.stdout).into_owned(),
                String::from_utf8_lossy(&output.stderr).into_owned(),
            )
        })
        .unwrap();
    assert!(ok, "keygen failed: {stderr}");
    let public = stdout.trim().to_owned();

    // A client: an ephemeral listen port, a peer with an endpoint to dial, and
    // a control socket that nothing is listening on.
    let config = dir.join("client.toml");
    std::fs::write(
        &config,
        format!(
            "[interface]\nname = \"client\"\nprivate_key = \"{}\"\nlisten = \"0.0.0.0:0\"\ncontrol = \"{}\"\n\n[[peer]]\nname = \"server\"\npublic_key = \"{public}\"\nendpoint = \"127.0.0.1:51820\"\nallowed_ips = [\"10.0.0.0/24\"]\n",
            key.display(),
            dir.join("client.sock").display()
        ),
    )
    .unwrap();

    let output = bin()
        .args(["doctor", "--config"])
        .arg(&config)
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    assert_eq!(
        output.status.code(),
        Some(1),
        "a client with no daemon must fail the doctor, not warn:\n{stdout}"
    );
    // And it must say WHY, in words a person can act on.
    assert!(
        stdout.contains("NOT protected"),
        "the report must say the client is not protected:\n{stdout}"
    );
}

#[test]
fn a_usage_error_from_the_parser_stays_two() {
    // clap's own contract, pinned so a future refactor cannot remap it.
    assert_eq!(code(&["doctor", "--nonsense"]), 2);
    assert_eq!(code(&["frobnicate"]), 2);
}
