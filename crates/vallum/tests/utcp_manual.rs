//! The UTCP manual is a published surface, not documentation.
//!
//! `packaging/utcp/vallum.utcp.json` is how an agent harness — and every client
//! that loads a UTCP manual — calls Vallum. A tool with no `tool_call_template`
//! is a tool the client cannot call at all, and a placeholder that is not a
//! required input is substituted as an empty string, which turns
//! `--suite UTCP_ARG_suite_UTCP_END` into `--suite --output …`. Both shipped
//! once: five of fifteen tools were uncallable, and `syncconf`'s only template
//! passed a `-c` the binary does not accept.
//!
//! These tests read the committed manual and hold it against the committed
//! binary, so the drift is caught where it is introduced rather than by the
//! first agent that tries.

#![allow(clippy::expect_used)]

use std::process::Command;

use serde_json::Value;

fn manual() -> Value {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../packaging/utcp/vallum.utcp.json"
    );
    let text = std::fs::read_to_string(path).expect("read the UTCP manual");
    serde_json::from_str(&text).expect("the UTCP manual must be valid JSON")
}

fn tools(manual: &Value) -> &Vec<Value> {
    manual["tools"].as_array().expect("`tools` is an array")
}

fn template(tool: &Value) -> &str {
    tool["tool_call_template"]["commands"][0]["command"]
        .as_str()
        .unwrap_or_default()
}

/// `UTCP_ARG_<name>_UTCP_END` placeholders, in order of appearance.
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

/// A value a placeholder can be substituted with, chosen by the input's own
/// schema — an enum has to get one of its own values, or clap rejects the call
/// for a reason that says nothing about the manual.
fn sample(tool: &Value, name: &str) -> String {
    let property = &tool["inputs"]["properties"][name];
    if let Some(first) = property["enum"][0].as_str() {
        return first.to_owned();
    }
    if name.contains("socket") {
        "/tmp/utcp-check.sock".to_owned()
    } else if name.contains("key") {
        "/tmp/utcp-check.key".to_owned()
    } else if name.contains("file") || name.contains("path") || name.contains("config") {
        "/tmp/utcp-check.toml".to_owned()
    } else {
        "1".to_owned()
    }
}

#[test]
fn every_tool_can_actually_be_called() {
    let manual = manual();
    let mut uncallable = Vec::new();
    for tool in tools(&manual) {
        if template(tool).is_empty() {
            uncallable.push(tool["name"].as_str().unwrap_or("?").to_owned());
        }
    }
    assert!(
        uncallable.is_empty(),
        "these tools have no tool_call_template, so a UTCP client cannot call them: {uncallable:?}"
    );
}

#[test]
fn every_placeholder_is_a_required_input() {
    let manual = manual();
    let mut problems = Vec::new();
    for tool in tools(&manual) {
        let name = tool["name"].as_str().unwrap_or("?");
        let required = tool["inputs"]["required"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        for placeholder in placeholders(template(tool)) {
            if !tool["inputs"]["properties"].get(&placeholder).is_some() {
                problems.push(format!("{name}: `{placeholder}` is not an input"));
            } else if !required.iter().any(|r| r.as_str() == Some(&placeholder)) {
                problems.push(format!(
                    "{name}: `{placeholder}` is optional, so it would be substituted as an empty string"
                ));
            }
        }
    }
    assert!(problems.is_empty(), "{}", problems.join("\n"));
}

#[test]
fn every_input_reaches_the_command() {
    // The mirror image of the test above: an input the template never
    // substitutes is decoration. `vallum_status` declared `json` while its
    // command already passed `--json` itself, so an agent could set it to false
    // and still get JSON back.
    let manual = manual();
    let mut problems = Vec::new();
    for tool in tools(&manual) {
        let name = tool["name"].as_str().unwrap_or("?");
        let used = placeholders(template(tool));
        if let Some(properties) = tool["inputs"]["properties"].as_object() {
            for property in properties.keys() {
                if !used.iter().any(|placeholder| placeholder == property) {
                    problems.push(format!(
                        "{name}: `{property}` is an input that no placeholder reads, so its value is discarded"
                    ));
                }
            }
        }
    }
    assert!(problems.is_empty(), "{}", problems.join("\n"));
}

#[test]
fn every_template_is_a_command_the_binary_accepts() {
    let manual = manual();
    let mut problems = Vec::new();
    for tool in tools(&manual) {
        let name = tool["name"].as_str().unwrap_or("?");
        let command = template(tool);
        if command.is_empty() {
            continue;
        }
        let mut argv = Vec::new();
        for word in command.split_whitespace() {
            match placeholders(word).first() {
                Some(placeholder) => {
                    let placeholder = placeholder.clone();
                    argv.push(word.replace(
                        &format!("UTCP_ARG_{placeholder}_UTCP_END"),
                        &sample(tool, &placeholder),
                    ));
                }
                None => argv.push(word.to_owned()),
            }
        }
        assert_eq!(argv.first().map(String::as_str), Some("vallum"), "{name}");
        // `--help` on the deepest subcommand validates the flags without acting
        // on anything, which is the only safe way to ask a root verb.
        let mut probe = vec![argv[0].clone()];
        probe.extend(argv[1..].iter().cloned());
        let output = Command::new(env!("CARGO_BIN_EXE_vallum"))
            .args(
                probe
                    .iter()
                    .skip(1)
                    .cloned()
                    .chain(std::iter::once("--help".to_owned())),
            )
            .output()
            .expect("run the binary");
        let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
        if !output.status.success() {
            problems.push(format!(
                "{name}: `{} --help` failed: {}",
                probe[1..].join(" "),
                stderr.trim()
            ));
            continue;
        }
        for flag in argv.iter().filter(|word| word.starts_with("--")) {
            if !stdout.contains(flag.as_str()) {
                problems.push(format!("{name}: `{flag}` is not accepted by the binary"));
            }
        }
    }
    assert!(problems.is_empty(), "{}", problems.join("\n"));
}
