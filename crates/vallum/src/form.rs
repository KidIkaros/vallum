// SPDX-License-Identifier: Apache-2.0

//! Parsing what a human types into a peer form.
//!
//! The TUI and the desktop console offer the same fields — endpoint, allowed
//! IPs, keepalive, preshared key — so they must accept exactly the same input
//! and reject it with the same words. These live here, outside the `tui`
//! feature, so the console links them instead of carrying a second copy that
//! would drift from this one the first time either changed.
//!
//! Every function treats an empty field as "not set" rather than as an error:
//! on an edit form, a blank endpoint means leave the endpoint alone.

use std::net::{SocketAddr, ToSocketAddrs};

use vallum_tunnel::Prefix;

use crate::keys;

/// An endpoint as `host:port`, resolved if it is a name.
///
/// A bare address with no port is refused: `192.0.2.1` parses as an `IpAddr`,
/// not a `SocketAddr`, and an endpoint without a port configures a peer that
/// can never be dialled.
///
/// # Errors
///
/// A human-readable reason if the text is neither empty nor a reachable
/// `host:port`.
pub fn parse_endpoint(text: &str) -> Result<Option<SocketAddr>, String> {
    let text = text.trim();
    if text.is_empty() {
        return Ok(None);
    }
    if let Ok(address) = text.parse() {
        return Ok(Some(address));
    }
    if !text.contains(':') || (text.starts_with('[') && !text.contains("]:")) {
        return Err(
            "endpoint must include a port (e.g. 198.51.100.1:51820 or vpn.example.com:51820)"
                .to_owned(),
        );
    }
    text.to_socket_addrs()
        .map_err(|error| format!("endpoint: {error} (check hostname and port)"))?
        .next()
        .map(Some)
        .ok_or_else(|| "endpoint resolved to nothing".to_owned())
}

/// A list of prefixes, separated by commas or spaces.
///
/// A bare address is accepted as a host route (`/32` or `/128`), because that
/// is what an operator means by `10.7.0.2` in an allowed-IPs field.
///
/// # Errors
///
/// The offending entry and why it is not a prefix.
pub fn parse_prefixes(text: &str) -> Result<Vec<Prefix>, String> {
    text.split([',', ' '])
        .filter(|part| !part.is_empty())
        .map(|part| {
            let normalized = if !part.contains('/') {
                if part.parse::<std::net::Ipv4Addr>().is_ok() {
                    format!("{part}/32")
                } else if part.parse::<std::net::Ipv6Addr>().is_ok() {
                    format!("{part}/128")
                } else {
                    part.to_owned()
                }
            } else {
                part.to_owned()
            };
            normalized
                .parse::<Prefix>()
                .map_err(|error| format!("{part}: {error}"))
        })
        .collect()
}

/// A persistent keepalive interval in seconds.
///
/// Zero means "off" and is reported as absent, which is how the UAPI spells a
/// disabled keepalive.
///
/// # Errors
///
/// If the text is not empty and not a number of seconds.
pub fn parse_keepalive(text: &str) -> Result<Option<u16>, String> {
    let value = text.trim();
    if value.is_empty() {
        return Ok(None);
    }
    let seconds: u16 = value
        .parse()
        .map_err(|_| "keepalive is not a number".to_owned())?;
    Ok((seconds > 0).then_some(seconds))
}

/// A preshared key, as 64 hex characters.
///
/// # Errors
///
/// If the text is not empty and not exactly 32 bytes of hex.
pub fn parse_psk(text: &str) -> Result<Option<[u8; 32]>, String> {
    let value = text.trim();
    if value.is_empty() {
        return Ok(None);
    }
    keys::parse_psk(value)
        .map(|psk| Some(*psk.as_bytes()))
        .map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    #[test]
    fn a_blank_endpoint_is_absent() {
        assert_eq!(parse_endpoint("").unwrap(), None);
        assert_eq!(parse_endpoint("   ").unwrap(), None);
    }

    #[test]
    fn an_endpoint_without_a_port_is_refused() {
        assert!(parse_endpoint("192.168.1.1").is_err());
        assert!(parse_endpoint("[2001:db8::1]").is_err());
    }

    #[test]
    fn a_host_route_is_what_a_bare_address_means() {
        let prefixes = parse_prefixes("10.7.0.2, 192.168.1.0/24 2001:db8::1").unwrap();
        let rendered: Vec<String> = prefixes.iter().map(ToString::to_string).collect();
        assert_eq!(
            rendered,
            vec!["10.7.0.2/32", "192.168.1.0/24", "2001:db8::1/128"]
        );
    }

    #[test]
    fn a_zero_keepalive_is_absent() {
        assert_eq!(parse_keepalive("0").unwrap(), None);
        assert_eq!(parse_keepalive("25").unwrap(), Some(25));
        assert!(parse_keepalive("soon").is_err());
    }

    #[test]
    fn a_preshared_key_must_be_32_bytes() {
        assert_eq!(parse_psk("").unwrap(), None);
        assert!(parse_psk("abcd").is_err());
        assert!(parse_psk(&"00".repeat(32)).unwrap().is_some());
    }
}
