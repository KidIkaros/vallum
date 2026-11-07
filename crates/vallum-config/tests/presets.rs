// SPDX-License-Identifier: Apache-2.0

//! The presets in `docs/shaping.md` must be configs, not prose.
//!
//! A copy-paste block that has drifted from the schema is worse than no block: it
//! fails on the operator's machine, after they trusted it. Each preset in the
//! user page is marked with an HTML comment naming the preset it documents, and
//! this test parses it into the real `Config`, builds its machines, and compares
//! the shapes with [`vallum_config::ShapingPreset`] — so a renamed field, a
//! removed shape, or a page that no longer matches `vallum peer add --shaping`
//! breaks the build rather than a deployment.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::fs;
use std::path::PathBuf;

use vallum_config::{Config, ShapingPreset, ShapingSpec};

/// The marker the docs put on the line before a preset block, with its name.
const MARKER: &str = "<!-- parse-check: ";

struct Preset {
    name: String,
    text: String,
}

/// Every `toml` block the docs marked, with the preset it claims to be.
fn presets() -> Vec<Preset> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../docs/shaping.md");
    let text = fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("read {}: {error}", path.display()));

    let mut blocks = Vec::new();
    let mut lines = text.lines();
    while let Some(line) = lines.next() {
        let trimmed = line.trim();
        let Some(rest) = trimmed.strip_prefix(MARKER) else {
            continue;
        };
        let name = rest
            .strip_suffix("-->")
            .expect("a parse-check marker ends with `-->`")
            .trim()
            .to_owned();
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
        blocks.push(Preset { name, text: block });
    }
    blocks
}

#[test]
fn every_documented_preset_is_the_named_preset_it_claims_to_be() {
    let presets = presets();
    // Every preset must be documented, and the marker must not have been
    // deleted along with a block this test would then never look at.
    assert_eq!(
        presets.len(),
        ShapingPreset::ALL.len(),
        "the page documents {} presets; the library has {}",
        presets.len(),
        ShapingPreset::ALL.len()
    );

    for documented in &presets {
        let preset = ShapingPreset::parse(&documented.name).unwrap_or_else(|| {
            panic!(
                "`{}` is not a preset; the library has {:?}",
                documented.name,
                ShapingPreset::ALL.map(ShapingPreset::name)
            )
        });

        let config: Config = toml::from_str(&documented.text).unwrap_or_else(|error| {
            panic!(
                "preset `{}` does not parse: {error}\n{}",
                preset.name(),
                documented.text
            )
        });

        let peer = config
            .peers
            .first()
            .unwrap_or_else(|| panic!("preset `{}` has no peer to shape", preset.name()));
        assert_eq!(
            peer.shaping,
            preset.specs(),
            "the page's `{}` block and the library's preset disagree",
            preset.name()
        );

        // Building the machines is the second half of the contract: the kinds
        // parsed, and every parameter is one the library accepts.
        let machines: Vec<_> = peer.shaping.iter().map(ShapingSpec::machine).collect();
        assert_eq!(machines.len(), peer.shaping.len());
        let shaper = vallum_core::Shaper::new(machines);
        assert!(
            shaper.wake_after().is_some(),
            "preset `{}` installs nothing time-driven, so it hides less than it claims",
            preset.name()
        );
    }
}
