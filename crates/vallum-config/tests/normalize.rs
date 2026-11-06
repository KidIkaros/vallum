// SPDX-License-Identifier: Apache-2.0

//! `with_local_fwmark`: a full-tunnel client config gets the mark it needs
//! to route; everything else passes through untouched.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use vallum_config::{with_local_fwmark, Config};

const FULL: &str = "\
[interface]
name = \"vallum-laptop\"
private_key = \"laptop.key\"
addresses = [\"10.7.0.2/32\"]

[[peer]]
name = \"server\"
public_key = \"line\"
allowed_ips = [\"0.0.0.0/0\"]
";

#[test]
fn a_full_tunnel_without_a_mark_gets_one() {
    let out = with_local_fwmark(FULL);
    let config: Config = toml::from_str(&out).expect("the completed config parses");
    assert_eq!(config.interface.fwmark, Some(51820));
    // And it lands inside [interface], not a stray table.
    assert!(out.contains("[interface]\nfwmark = 51820"), "{out}");
}

#[test]
fn a_split_tunnel_is_left_alone() {
    let text = FULL.replace("0.0.0.0/0", "10.7.0.0/24");
    assert_eq!(with_local_fwmark(&text), text);
}

#[test]
fn an_existing_mark_is_kept() {
    let text = FULL.replace("[interface]\n", "[interface]\nfwmark = 42\n");
    assert_eq!(with_local_fwmark(&text), text);
}

#[test]
fn garbage_passes_through_for_the_caller_to_report() {
    let text = "not toml at all {{{";
    assert_eq!(with_local_fwmark(text), text);
}
