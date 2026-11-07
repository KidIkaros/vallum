// SPDX-License-Identifier: Apache-2.0

//! Named shaping combinations, so an operator names one word instead of
//! assembling four blocks.
//!
//! The shapes are the library's; the *combinations* are a product decision —
//! which ones are worth recommending, and at what parameters. They live here
//! rather than in the daemon because both the CLI (generating a client config)
//! and `docs/shaping.md` name them, and the documentation test parses the page's
//! blocks into exactly these specs so the two cannot drift apart.

use crate::ShapingSpec;

/// A recommended combination from `docs/shaping.md`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShapingPreset {
    /// One size for every packet, and a packet every two seconds.
    ///
    /// Closes the length channel and the silence channel together. It costs a
    /// continuous rate — about 5.8 kbit/s per peer per direction — so it is the
    /// preset to choose when a tunnel is idle for hours and its silence is what
    /// stands out.
    Balanced,
    /// One size for every packet, and a bounded burst at the start.
    ///
    /// For a device that suspends and wakes: the revealing moment is the minute
    /// after it comes back, and the burst is about 43 kB once rather than a rate
    /// that runs all day.
    Opening,
}

impl ShapingPreset {
    /// Every preset, in the order the documentation lists them.
    pub const ALL: [Self; 2] = [Self::Balanced, Self::Opening];

    /// The name an operator types.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Balanced => "balanced",
            Self::Opening => "opening",
        }
    }

    /// The preset for a name, or `None` if there is no such preset.
    ///
    /// Deliberately not a prefix match and not case-folded: a typo should be an
    /// error naming the presets, not a guess that shapes a tunnel nobody meant.
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|preset| preset.name() == name)
    }

    /// The shapes this preset installs, in order.
    #[must_use]
    pub fn specs(self) -> Vec<ShapingSpec> {
        match self {
            Self::Balanced => vec![
                ShapingSpec::PadToSize { size: 1_400 },
                ShapingSpec::ConstantRateFloor {
                    interval_ms: 2_000,
                    jitter_ms: 500,
                    size: 1_400,
                },
            ],
            Self::Opening => vec![
                ShapingSpec::PadToSize { size: 1_400 },
                ShapingSpec::FrontPadding {
                    count: 30,
                    interval_ms: 200,
                    size: 1_400,
                },
            ],
        }
    }

    /// The `[[peer.shaping]]` blocks, ready to append after a `[[peer]]` table.
    ///
    /// Written out rather than serialized so the output reads like the page an
    /// operator was just looking at: comments included, field order theirs.
    #[must_use]
    pub fn to_toml(self) -> String {
        match self {
            Self::Balanced => {
                "\n# Every packet leaves at one size: the length channel carries nothing.\n\
                 [[peer.shaping]]\n\
                 kind = \"pad_to_size\"\n\
                 size = 1400\n\
                 \n\
                 # And an idle tunnel keeps speaking.\n\
                 [[peer.shaping]]\n\
                 kind = \"constant_rate_floor\"\n\
                 interval_ms = 2000\n\
                 jitter_ms = 500\n\
                 size = 1400\n"
                    .to_owned()
            }
            Self::Opening => "\n# One size for every packet.\n\
                 [[peer.shaping]]\n\
                 kind = \"pad_to_size\"\n\
                 size = 1400\n\
                 \n\
                 # 30 packets, each riding along with real traffic or after 200 ms of\n\
                 # silence, and then the burst is over for good.\n\
                 [[peer.shaping]]\n\
                 kind = \"front_padding\"\n\
                 count = 30\n\
                 interval_ms = 200\n\
                 size = 1400\n"
                .to_owned(),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::ShapingPreset;

    #[test]
    fn a_preset_name_round_trips_and_an_unknown_one_is_not_guessed() {
        for preset in ShapingPreset::ALL {
            assert_eq!(ShapingPreset::parse(preset.name()), Some(preset));
        }
        assert_eq!(ShapingPreset::parse("Balanced"), None);
        assert_eq!(ShapingPreset::parse("bal"), None);
        assert_eq!(ShapingPreset::parse(""), None);
    }

    #[test]
    fn the_rendered_blocks_parse_back_to_the_presets_own_specs() {
        for preset in ShapingPreset::ALL {
            let text = format!(
                "[interface]\nprivate_key = \"client.key\"\n\n[[peer]]\nname = \"server\"\npublic_key = \"vallum1:0003:00:-\"\n{}",
                preset.to_toml()
            );
            let config: crate::Config = toml::from_str(&text).expect("a generated config parses");
            let peer = config.peers.first().expect("one peer");
            assert_eq!(
                peer.shaping,
                preset.specs(),
                "{} renders blocks that are not its own specs",
                preset.name()
            );
        }
    }
}
