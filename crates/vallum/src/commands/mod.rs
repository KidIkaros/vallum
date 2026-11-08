// SPDX-License-Identifier: Apache-2.0

//! The `vallum` command implementations. `main.rs` only parses and dispatches.

pub mod bench;
pub mod client;
pub mod control;
pub mod doctor;
pub mod identity;
pub mod import;
pub mod keys;
pub mod metrics;
pub mod peer;
pub mod policy;
pub mod run;
pub mod sandbox;
pub mod server;
pub mod setup;
pub mod status;
#[cfg(feature = "tui")]
pub mod tui;
pub mod uninstall;
