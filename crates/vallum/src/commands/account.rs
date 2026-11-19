//! `vallum account` — the client reads its account from the desk (ADR-0046).
//!
//! The daemon stays account-ignorant (ADR-0044/0045): this verb asks the
//! desk directly, over HTTPS, with the bearer token already sealed in
//! `[account]`. The read is best-effort — a desk that cannot be reached
//! renders `unknown`, never a confident false state. The endpoint is shown
//! before the call, so the user can see where their token goes.

use crate::error::Error;

/// A desk origin: `https://host[:port]` (or loopback `http://` for a local
/// desk). No path — the account API lives at a fixed `POST /api/account`.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct DeskEndpoint {
    pub tls: bool,
    pub host: String,
    pub port: u16,
}

/// Parse the desk origin recorded at join (`[account] endpoint`).
///
/// The token is a bearer credential: it may only travel over TLS, or over
/// plain HTTP on loopback where no network sits between client and desk.
/// A non-loopback `http://` origin is refused, not silently downgraded.
pub(crate) fn parse_desk_endpoint(raw: &str) -> Result<DeskEndpoint, Error> {
    let trimmed = raw.trim();
    let (tls, rest) = if let Some(r) = trimmed.strip_prefix("https://") {
        (true, r)
    } else if let Some(r) = trimmed.strip_prefix("http://") {
        (false, r)
    } else {
        return Err(Error::Usage(
            "the desk endpoint must be an `https://host[:port]` origin".to_owned(),
        ));
    };
    if rest.contains(['/', '?', '#', '@']) {
        return Err(Error::Usage(
            "the desk endpoint is an origin — no path, query, or userinfo".to_owned(),
        ));
    }
    let default_port = if tls { 443 } else { 80 };
    let (host, port) = if let Some(bracketed) = rest.strip_prefix('[') {
        let end = bracketed
            .find(']')
            .ok_or_else(|| Error::Usage("malformed IPv6 host in the desk endpoint".to_owned()))?;
        let host = bracketed[..end].to_owned();
        let after = &bracketed[end + 1..];
        let port = if let Some(p) = after.strip_prefix(':') {
            p.parse::<u16>()
                .map_err(|_| Error::Usage("invalid port in the desk endpoint".to_owned()))?
        } else if after.is_empty() {
            default_port
        } else {
            return Err(Error::Usage(
                "invalid authority in the desk endpoint".to_owned(),
            ));
        };
        (host, port)
    } else if let Some((h, p)) = rest.rsplit_once(':') {
        let port = p
            .parse::<u16>()
            .map_err(|_| Error::Usage("invalid port in the desk endpoint".to_owned()))?;
        (h.to_owned(), port)
    } else {
        (rest.to_owned(), default_port)
    };
    if host.is_empty() {
        return Err(Error::Usage(
            "the desk endpoint is missing a host".to_owned(),
        ));
    }
    if !tls && !is_loopback_host(&host) {
        return Err(Error::Usage(
            "the desk endpoint must be https:// off loopback — the account token \
             never crosses a network in cleartext"
                .to_owned(),
        ));
    }
    Ok(DeskEndpoint { tls, host, port })
}

fn is_loopback_host(host: &str) -> bool {
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    host.parse::<std::net::IpAddr>()
        .is_ok_and(|ip| ip.is_loopback())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn desk_origins_parse_with_default_and_explicit_ports() {
        assert_eq!(
            parse_desk_endpoint("https://desk.example.com").unwrap(),
            DeskEndpoint {
                tls: true,
                host: "desk.example.com".to_owned(),
                port: 443,
            }
        );
        assert_eq!(
            parse_desk_endpoint("https://desk.example.com:8443").unwrap(),
            DeskEndpoint {
                tls: true,
                host: "desk.example.com".to_owned(),
                port: 8443,
            }
        );
        assert_eq!(
            parse_desk_endpoint("https://[::1]:8443").unwrap(),
            DeskEndpoint {
                tls: true,
                host: "::1".to_owned(),
                port: 8443,
            }
        );
    }

    #[test]
    fn plain_http_is_only_for_loopback_desks() {
        // A local desk (and the stub tests) speak plain HTTP on loopback,
        // where no network sits between client and desk.
        assert!(parse_desk_endpoint("http://127.0.0.1:8080").is_ok());
        assert!(parse_desk_endpoint("http://localhost:8080").is_ok());
        assert!(parse_desk_endpoint("http://[::1]:8080").is_ok());
        // Off loopback the token would cross a network in cleartext.
        let err = parse_desk_endpoint("http://desk.example.com").unwrap_err();
        assert!(err.to_string().contains("https://"), "{err}");
    }

    #[test]
    fn malformed_desk_origins_are_refused() {
        assert!(parse_desk_endpoint("ftp://desk.example.com").is_err());
        assert!(parse_desk_endpoint("desk.example.com").is_err());
        assert!(parse_desk_endpoint("https://").is_err());
        assert!(parse_desk_endpoint("https://desk.example.com/path").is_err());
        assert!(parse_desk_endpoint("https://desk.example.com:notaport").is_err());
        assert!(parse_desk_endpoint("https://user@desk.example.com").is_err());
    }
}