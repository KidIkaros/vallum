// SPDX-License-Identifier: Apache-2.0

//! The `vallum` command implementations. `main.rs` only parses and dispatches.

pub mod bench;
pub mod control;
pub mod doctor;
pub mod import;
pub mod keys;
pub mod run;
#[cfg(feature = "tui")]
pub mod tui;
