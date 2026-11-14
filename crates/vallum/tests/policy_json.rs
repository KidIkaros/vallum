// SPDX-License-Identifier: Apache-2.0

//! `vallum policy --json` — the guard's answer, for a reader that is not a person.
//!
//! The manual ships `vallum_policy` to agents, and a UTCP call returns stdout as
//! a string. Without `--json` the only thing an agent can do with the answer is
//! echo a sentence back at its caller. These tests pin the object, the mapping
//! from host state to the word `egress`, and the one case that must stay a
//! refusal: a split tunnel asked for an explicit `on`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_vallum"))
}

fn scratch(name: &str, text: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("vallum-policy-{}-{name}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("vallum0.toml");
    std::fs::write(&path, text).unwrap();
    path
}

/// A full tunnel: the guard is wanted, and there is an endpoint to permit.
const FULL: &str = r#"
[interface]
name = "vallum-laptop"
private_key = "k.key"
addresses = ["10.7.0.2/32"]

[quick]
policy = "auto"

[[peer]]
name = "server"
public_key = "vallum1:0003:aa:-"
endpoint = "127.0.0.1:51820"
allowed_ips = ["0.0.0.0/0"]
"#;

/// The same peer as a split tunnel, with no `[quick] policy`: `auto` means off.
const SPLIT: &str = r#"
[interface]
name = "vallum-laptop"
private_key = "k.key"
addresses = ["10.7.0.2/32"]

[[peer]]
name = "server"
public_key = "vallum1:0003:aa:-"
endpoint = "127.0.0.1:51820"
allowed_ips = ["10.7.0.1/32"]
"#;

fn run(args: &[&str], config: &Path) -> Output {
    bin()
        .args(args)
        .args(["--config", config.to_str().unwrap()])
        .output()
        .unwrap()
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
fn status_says_what_the_config_asks_for_and_what_the_host_has() {
    let config = scratch("status", FULL);
    let report = json(&run(&["policy", "status", "--json"], &config));

    assert_eq!(report["action"], "status");
    assert_eq!(report["declared"], "auto");
    assert_eq!(
        report["policy"], "on",
        "`auto` on a full tunnel resolves to a guard"
    );
    assert_eq!(report["interface"], "vallum-laptop");
    assert_eq!(report["families"], serde_json::json!(["v4"]));
}

#[test]
fn egress_is_the_word_for_what_the_host_actually_has() {
    let config = scratch("egress", FULL);
    let report = json(&run(&["policy", "status", "--json"], &config));

    // `guard` is host truth: Installed / Absent / Unknown (no root, no nft).
    let expected = match report["guard"].as_str().unwrap() {
        "installed" => "blocked",
        "absent" => "unrestricted",
        "unknown" => "unknown",
        other => panic!("guard state is not one of the three: {other}"),
    };
    assert_eq!(
        report["egress"], expected,
        "`egress` must not claim more than `guard` knows"
    );

    // The fix line exists in exactly the case it can help: wanted, not there.
    let wants_a_guard = report["policy"] == "on";
    let missing = report["guard"] == "absent";
    assert_eq!(
        report.get("fix").is_some(),
        wants_a_guard && missing,
        "the hint belongs to `wants a guard and none is installed`, not to any other state"
    );
}

#[test]
fn a_dry_run_hands_back_the_ruleset_without_touching_the_host() {
    let config = scratch("dry", FULL);
    let report = json(&run(&["policy", "on", "--dry-run", "--json"], &config));

    assert_eq!(report["action"], "on");
    assert_eq!(report["dry_run"], true);
    let rules = report["ruleset"].as_str().unwrap();
    assert!(rules.contains("table inet vallum_policy"));
    assert!(
        rules.contains("oifname \"vallum-laptop\" accept"),
        "the ruleset must permit the tunnel it protects: {rules}"
    );
}

#[test]
fn the_human_report_is_still_a_report() {
    // `--json` is an addition. The operator's output must not have become JSON,
    // and the dry run must still print the ruleset it would install.
    let config = scratch("human", FULL);
    let output = run(&["policy", "status"], &config);
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.contains("interface  vallum-laptop"), "{text}");
    assert!(serde_json::from_str::<serde_json::Value>(&text).is_err());

    let dry = run(&["policy", "on", "--dry-run"], &config);
    assert!(dry.status.success());
    let text = String::from_utf8(dry.stdout).unwrap();
    assert!(text.contains("would install this ruleset"));
}

#[test]
fn a_split_tunnel_asked_for_on_is_a_refusal_even_with_json() {
    // A refusal that prints nothing and exits 0 is indistinguishable from a
    // guard that was installed. `--json` must not turn it into an empty object.
    let config = scratch("split", SPLIT);
    let output = run(&["policy", "on", "--json"], &config);

    assert_eq!(output.status.code(), Some(2), "a met-unmet precondition");
    assert!(
        output.stdout.is_empty(),
        "stdout stays silent on a refusal; stderr carries the reason"
    );
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("split tunnel"), "{stderr}");
}

#[test]
fn early_boot_lockdown_unit_and_dns_free_policy_on_succeed_before_network() {
    let unit_path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../packaging/vallum-guard@.service");
    let unit = std::fs::read_to_string(&unit_path)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", unit_path.display()));
    assert!(
        unit.contains("Before=network-pre.target"),
        "guard unit must order before network-pre.target"
    );
    assert!(
        unit.contains("Wants=network-pre.target"),
        "guard unit must pull in network-pre.target ordering"
    );
    assert!(
        unit.contains("ExecStart=/usr/bin/vallum policy on --config /etc/vallum/%i.toml"),
        "guard unit ExecStart must invoke `vallum policy on`"
    );
    assert!(
        !unit
            .lines()
            .any(|l| !l.trim_start().starts_with('#') && l.contains("PartOf=vallum@%i.service")),
        "guard unit must stay crash-persistent across daemon stops"
    );

    // At early boot (before network-pre.target), DNS is unavailable. With
    // `[quick] policy = "lockdown"`, `vallum policy on` must still succeed
    // and emit a fail-closed ruleset.
    let lockdown_unresolvable = r#"
[interface]
name = "vallum-laptop"
private_key = "k.key"
addresses = ["10.7.0.2/32"]

[quick]
policy = "lockdown"

[[peer]]
name = "server"
public_key = "vallum1:0003:aa:-"
endpoint = "early-boot-unresolvable.invalid:51820"
allowed_ips = ["0.0.0.0/0"]
"#;
    let config = scratch("early-boot-lockdown", lockdown_unresolvable);
    let report = json(&run(&["policy", "on", "--dry-run", "--json"], &config));
    assert_eq!(report["action"], "on");
    let rules = report["ruleset"].as_str().unwrap();
    assert!(
        rules.contains("drop"),
        "early-boot lockdown ruleset must fail closed: {rules}"
    );
}
