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
fn a_usage_error_from_the_parser_stays_two() {
    // clap's own contract, pinned so a future refactor cannot remap it.
    assert_eq!(code(&["doctor", "--nonsense"]), 2);
    assert_eq!(code(&["frobnicate"]), 2);
}
