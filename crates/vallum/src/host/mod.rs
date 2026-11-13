//! The host boundary: everything that knows *which operating system* this
//! machine runs lives under this module — and nowhere else.
//!
//! The engine crates (`vallum-core`, `vallum-tunnel`, `vallum-config`) are
//! portable: they describe keys, handshakes, packets and parsed config. This
//! crate turns that engine into a product on a host, and this module is where
//! the host answers questions only it can answer: what the service manager
//! says, where config and sockets live, what the operator's SSH config offers.
//!
//! Per-platform knowledge arrives the way `tun` already does it: a `#[cfg]`
//! implementation behind one interface, not a trait — the product compiles
//! for a single target at a time. Callers (TUI, GUI, CLI verbs) never run
//! `systemctl` or read `/etc` themselves; they ask this module and accept
//! `None` as "the host cannot say".

pub mod paths;
pub mod probes;
