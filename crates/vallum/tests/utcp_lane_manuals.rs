//! The agent-lane and desk manuals are published surfaces too.
//!
//! `packaging/utcp/vallum.utcp.json` is the `vallum` binary's own manual; the
//! fox manual describes the `vallum-fox` CLI and the desk manual the HTTP
//! endpoints an operator exposes. The same discipline holds for all three: a
//! tool with no template is uncallable, a placeholder that is not a required
//! input is substituted as an empty string, and an input no placeholder reads
//! is decoration the caller thinks works.
//!
//! The fox manual gets one more check the binary's manual cannot have: every
//! subcommand it names must exist in the shipped script, because the script is
//! shell and its verbs are a case statement, not a clap tree.

#![allow(clippy::expect_used)]

use std::process::Command;

use serde_json::Value;

fn manual(name: &str) -> Value {
    let path = format!(
        "{}/../../packaging/utcp/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
    let text = std::fs::read_to_string(&path).expect("read the manual");
    serde_json::from_str(&text).expect("the manual must be valid JSON")
}

fn tools(manual: &Value) -> &Vec<Value> {
    manual["tools"].as_array().expect("`tools` is an array")
}

fn template(tool: &Value) -> &str {
    tool["tool_call_template"]["commands"][0]["command"]
        .as_str()
        .unwrap_or_default()
}

fn placeholders(command: &str) -> Vec<String> {
    let mut found = Vec::new();
    let mut rest = command;
    while let Some(start) = rest.find("UTCP_ARG_") {
        let after = &rest[start + "UTCP_ARG_".len()..];
        let Some(end) = after.find("_UTCP_END") else {
            break;
        };
        let name = &after[..end];
        if !found.iter().any(|seen| seen == name) {
            found.push(name.to_owned());
        }
        rest = &after[end + "_UTCP_END".len()..];
    }
    found
}

/// The checks every manual in this repository must pass.
fn assert_manual_discipline(manual: &Value, label: &str) {
    let mut uncallable = Vec::new();
    let mut optional_placeholders = Vec::new();
    let mut unread_inputs = Vec::new();
    for tool in tools(manual) {
        let name = tool["name"].as_str().unwrap_or("?");
        let command = template(tool);
        if command.is_empty() {
            uncallable.push(name.to_owned());
            continue;
        }
        let required = tool["inputs"]["required"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        for placeholder in placeholders(command) {
            if !tool["inputs"]["properties"].get(&placeholder).is_some() {
                uncallable.push(format!("{name}: `{placeholder}` is not an input"));
            } else if !required.iter().any(|r| r.as_str() == Some(&placeholder)) {
                optional_placeholders.push(format!(
                    "{name}: `{placeholder}` is optional, so it would be substituted as an empty string"
                ));
            }
        }
        if let Some(properties) = tool["inputs"]["properties"].as_object() {
            for property in properties.keys() {
                if !placeholders(command).iter().any(|p| p == property) {
                    unread_inputs.push(format!(
                        "{name}: `{property}` is an input no placeholder reads, so its value is discarded"
                    ));
                }
            }
        }
    }
    assert!(uncallable.is_empty(), "{label}: {uncallable:?}");
    assert!(
        optional_placeholders.is_empty(),
        "{label}: {}",
        optional_placeholders.join("\n")
    );
    assert!(
        unread_inputs.is_empty(),
        "{label}: {}",
        unread_inputs.join("\n")
    );
}

#[test]
fn the_fox_manual_is_disciplined() {
    assert_manual_discipline(&manual("vallum-fox.utcp.json"), "vallum-fox");
}

#[test]
fn the_desk_manual_is_disciplined() {
    assert_manual_discipline(&manual("vallum-desk.utcp.json"), "vallum-desk");
}

/// Every subcommand the fox manual names must exist in the shipped script.
///
/// The script's verbs are a `case` statement, so the honest check is against
/// that statement — not against a guess of what the script accepts.
#[test]
fn every_fox_subcommand_exists_in_the_script() {
    let script_path = format!("{}/../../agent/vallum-fox", env!("CARGO_MANIFEST_DIR"));
    let script = std::fs::read_to_string(&script_path).expect("read the fox script");
    let manual = manual("vallum-fox.utcp.json");
    let mut problems = Vec::new();
    for tool in tools(&manual) {
        let name = tool["name"].as_str().unwrap_or("?");
        let command = template(tool);
        assert_eq!(
            command.split_whitespace().next(),
            Some("vallum-fox"),
            "{name}: the fox manual describes the fox CLI, not something else"
        );
        let subcommand = command.split_whitespace().nth(1).unwrap_or("");
        // The dispatch is a case statement: `fetch) cmd_fetch "$@" ;;`
        let implemented = script
            .lines()
            .any(|line| line.trim_start().starts_with(&format!("{subcommand})")));
        if !implemented {
            problems.push(format!("{name}: `{subcommand}` is not a verb in agent/vallum-fox"));
        }
    }
    assert!(problems.is_empty(), "{}", problems.join("\n"));
}

/// The script must run: a manual that describes a broken CLI is worse than
/// none. `help` prints the usage without touching the network or the tunnel.
#[test]
fn the_fox_script_runs_and_prints_its_usage() {
    let script_path = format!("{}/../../agent/vallum-fox", env!("CARGO_MANIFEST_DIR"));
    let output = Command::new("bash")
        .arg(&script_path)
        .arg("help")
        .output()
        .expect("run the fox script");
    assert!(
        output.status.success(),
        "vallum-fox help failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("vallum-fox"), "usage text missing: {stdout}");
}
