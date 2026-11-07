// SPDX-License-Identifier: Apache-2.0

//! The presets in `docs/shaping.md` must be configs, not prose.
//!
//! A copy-paste block that has drifted from the schema is worse than no block: it
//! fails on the operator's machine, after they trusted it. Each preset in the
//! user page is marked with an HTML comment and parsed here — `deny_unknown_fields`
//! and the shape kind enum do the rest, so a renamed field or a removed shape
//! breaks this test rather than a deployment.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::fs;
use std::path::PathBuf;

use vallum_config::{Config, ShapingSpec};

/// The marker the docs put on the line before a preset block.
const MARKER: &str = "<!-- parse-check -->";

/// Every `toml` block the docs marked, in order.
fn presets() -> Vec<String> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../docs/shaping.md");
    let text = fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("read {}: {error}", path.display()));

    let mut blocks = Vec::new();
    let mut lines = text.lines();
    while let Some(line) = lines.next() {
        if line.trim() != MARKER {
            continue;
        }
        // The fence is the next non-blank line after the marker.
        let fence = lines
            .by_ref()
            .find(|line| !line.trim().is_empty())
            .expect("a preset marker must be followed by a fenced block");
        assert_eq!(fence.trim(), "```toml", "a preset marker must precede toml");

        let mut block = String::new();
        for line in lines.by_ref() {
            if line.trim() == "```" {
                break;
            }
            block.push_str(line);
            block.push('\n');
        }
        blocks.push(block);
    }
    blocks
}

#[test]
fn every_documented_preset_is_a_config_that_parses() {
    let presets = presets();
    // The marker could be deleted along with a preset and this test would then
    // pass on nothing at all.
    assert!(
        presets.len() >= 2,
        "expected the documented presets, found {}",
        presets.len()
    );

    for (index, text) in presets.iter().enumerate() {
        let config: Config = toml::from_str(text)
            .unwrap_or_else(|error| panic!("preset {index} does not parse: {error}\n{text}"));

        let peer = config
            .peers
            .first()
            .unwrap_or_else(|| panic!("preset {index} has no peer to shape"));
        assert!(
            !peer.shaping.is_empty(),
            "preset {index} is a preset of the shaping page and must shape something"
        );

        // Building the machines is the second half of the contract: the kinds
        // parsed, and every parameter is one the library accepts.
        let machines: Vec<_> = peer.shaping.iter().map(ShapingSpec::machine).collect();
        assert_eq!(machines.len(), peer.shaping.len());
        let shaper = vallum_core::Shaper::new(machines);
        assert!(
            shaper.wake_after().is_some(),
            "preset {index} installs nothing time-driven, so it hides less than it claims"
        );
    }
}
