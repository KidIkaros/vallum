// SPDX-License-Identifier: Apache-2.0

//! `vallum keygen --json` — identity creation, for a reader that is not a person.
//!
//! The manual ships `vallum_keygen` to agents, and a UTCP call returns stdout as
//! a string. Without `--json` the only thing an agent can do with the answer is
//! scrape a public line out of prose — and prose around key material is where
//! copy mistakes are born. These tests pin the object, the two refusals that
//! must stay silent on stdout, and the human output the deployment docs rely on:
//! `keygen --output k.key > k.pub` is the idiom in `docs/deployment/*.md`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::PathBuf;
use std::process::{Command, Output};

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_vallum"))
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("vallum-keygen-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir.join("client.key")
}

fn run(args: &[&str]) -> Output {
    bin().args(args).output().unwrap()
}

fn json(output: &Output) -> serde_json::Value {
    assert!(
        output.status.success(),
        "expected success, got {:?}: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
    let text = String::from_utf8(output.stdout.clone()).unwrap();
    serde_json::from_str(&text)
        .unwrap_or_else(|error| panic!("not one JSON object: {error}\n{text}"))
}

#[test]
fn keygen_answers_in_json_when_asked() {
    let key = scratch("json");
    let report = json(&run(&[
        "keygen",
        "--output",
        key.to_str().unwrap(),
        "--json",
    ]));

    assert_eq!(report["action"], "keygen");
    assert_eq!(report["output"], key.to_str().unwrap());
    assert_eq!(report["suite"], 3, "the default is the tri-hybrid");
    assert_eq!(report["signing"], false);
    let public = report["public"].as_str().unwrap();
    assert!(
        public.starts_with("vallum1:0003:"),
        "the line names the suite it was made with: {public}"
    );
    assert!(public.ends_with(":-"), "KEM-only ends in `-`: {public}");
    assert!(key.exists(), "the object describes a file that was written");
}

#[test]
fn signing_turns_on_p3_identity() {
    let key = scratch("signing");
    let report = json(&run(&[
        "keygen",
        "--output",
        key.to_str().unwrap(),
        "--signing",
        "--json",
    ]));

    assert_eq!(report["signing"], true);
    let public = report["public"].as_str().unwrap();
    let last = public.rsplit(':').next().unwrap();
    assert_ne!(
        last, "-",
        "a signing key's last segment is a key, not `-`: {public}"
    );
    // And the file it describes round-trips through the read half of the pair.
    let shown = run(&["pubkey", "--private-key", key.to_str().unwrap()]);
    assert!(shown.status.success());
    assert_eq!(
        String::from_utf8(shown.stdout).unwrap().trim(),
        public,
        "`pubkey` reads back what `keygen --json` reported"
    );
}

#[test]
fn the_human_answer_is_still_a_public_line() {
    // `--json` is an addition. The deployment docs redirect the bare line into
    // a `.pub` file, so stdout without the flag must stay exactly one line.
    let key = scratch("human");
    let output = run(&["keygen", "--output", key.to_str().unwrap()]);
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout).unwrap();
    assert_eq!(text.lines().count(), 1, "{text:?}");
    assert!(text.starts_with("vallum1:"), "{text:?}");
    assert!(serde_json::from_str::<serde_json::Value>(&text).is_err());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("wrote"), "{stderr:?}");
}

#[test]
fn json_success_writes_nothing_to_stderr() {
    // Some transports hand the agent stdout and stderr as one text, and the
    // Python CLI transport does: the `wrote` note broke parsing of the very
    // object it described. Under `--json` the object already says all of it
    // (`output`, `suite`, `signing`), so success is silent everywhere but
    // stdout. The human note stays in the human mode, pinned above.
    let key = scratch("quiet");
    let output = run(&["keygen", "--output", key.to_str().unwrap(), "--json"]);
    assert!(output.status.success());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        stderr.is_empty(),
        "a success note would corrupt the answer: {stderr:?}"
    );
}

#[test]
fn refusing_to_overwrite_is_silent_on_stdout_even_with_json() {
    // A key file is never overwritten. The second run must not print a partial
    // object — `automation.md` gives a refused request exit `1`, stdout silent.
    let key = scratch("refuse");
    let first = run(&["keygen", "--output", key.to_str().unwrap(), "--json"]);
    assert!(first.status.success());

    let output = run(&["keygen", "--output", key.to_str().unwrap(), "--json"]);
    assert_eq!(output.status.code(), Some(1), "a refused request");
    assert!(
        output.stdout.is_empty(),
        "stdout stays silent on a refusal; stderr carries the reason"
    );
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("refusing to overwrite"), "{stderr:?}");
}

#[test]
fn a_bad_suite_is_a_failure_not_an_object() {
    let key = scratch("suite");
    let output = run(&[
        "keygen",
        "--output",
        key.to_str().unwrap(),
        "--suite",
        "banana",
        "--json",
    ]);
    assert_eq!(output.status.code(), Some(1));
    assert!(
        output.stdout.is_empty(),
        "a usage error must not print half an object"
    );
    assert!(
        !key.exists(),
        "nothing was attempted, so nothing was written"
    );
}
