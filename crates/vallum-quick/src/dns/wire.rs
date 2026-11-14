// SPDX-License-Identifier: Apache-2.0

//! RFC 1035 DNS wire format: just enough to read a query's first question and
//! to synthesize `NODATA` and captive-portal answers. Pure bytes in, bytes out:
//! no sockets, no config, no clock.

use std::net::Ipv4Addr;

/// RFC 5737 TEST-NET-2 IP returned for spoofed captive-portal `A` queries when
/// the tunnel host is in `Blocked` / `Lockdown` state (Mullvad §8.4 pattern).
pub(crate) const CAPTIVE_PORTAL_SPOOF_IP: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 1);

/// DNS RR type `A` (IPv4 host address).
pub(crate) const DNS_TYPE_A: u16 = 1;

/// DNS RR type `AAAA` (IPv6 host address).
pub(crate) const DNS_TYPE_AAAA: u16 = 28;

pub(super) const DNS_CLASS_IN: u16 = 1;

/// Parsed first question of an RFC 1035 DNS wire query packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DnsQueryQuestion {
    pub(crate) tx_id: u16,
    pub(crate) flags: u16,
    pub(crate) qname: String,
    pub(crate) qtype: u16,
    pub(crate) qclass: u16,
    pub(crate) question_end: usize,
}

/// Parse an RFC 1035 standard DNS query header and its first question.
///
/// Rejects responses (`QR=1`), empty question sections (`QDCOUNT == 0`),
/// compressed labels inside the query question, or truncated packets.
#[must_use]
pub(crate) fn parse_dns_query(packet: &[u8]) -> Option<DnsQueryQuestion> {
    if packet.len() < 12 {
        return None;
    }
    let tx_id = u16::from_be_bytes([packet[0], packet[1]]);
    let flags = u16::from_be_bytes([packet[2], packet[3]]);
    if (flags & 0x8000) != 0 {
        return None;
    }
    let qdcount = u16::from_be_bytes([packet[4], packet[5]]);
    if qdcount == 0 {
        return None;
    }

    let mut pos = 12usize;
    let mut qname = String::new();
    loop {
        let len = usize::from(*packet.get(pos)?);
        pos += 1;
        if len == 0 {
            break;
        }
        if (len & 0xc0) != 0 || len > 63 {
            return None;
        }
        let label = packet.get(pos..pos + len)?;
        if !label.is_ascii() {
            return None;
        }
        let label_str = std::str::from_utf8(label).ok()?;
        if !qname.is_empty() {
            qname.push('.');
        }
        qname.push_str(label_str);
        if qname.len() > 253 {
            return None;
        }
        pos += len;
    }

    let qt_hi = *packet.get(pos)?;
    let qt_lo = *packet.get(pos + 1)?;
    let qc_hi = *packet.get(pos + 2)?;
    let qc_lo = *packet.get(pos + 3)?;
    let question_end = pos + 4;

    Some(DnsQueryQuestion {
        tx_id,
        flags,
        qname,
        qtype: u16::from_be_bytes([qt_hi, qt_lo]),
        qclass: u16::from_be_bytes([qc_hi, qc_lo]),
        question_end,
    })
}

pub(super) fn build_dns_response_header(tx_id: u16, req_flags: u16, ancount: u16) -> [u8; 12] {
    let rd = req_flags & 0x0100;
    let resp_flags = 0x8080 | rd;
    let mut hdr = [0u8; 12];
    hdr[0..2].copy_from_slice(&tx_id.to_be_bytes());
    hdr[2..4].copy_from_slice(&resp_flags.to_be_bytes());
    hdr[4..6].copy_from_slice(&1u16.to_be_bytes());
    hdr[6..8].copy_from_slice(&ancount.to_be_bytes());
    hdr
}

/// Synthesize a DNS `NOERROR` / `NODATA` (`ANCOUNT = 0`) reply preserving the
/// query ID, recursion-desired bit, and original question section.
#[must_use]
pub(crate) fn synthesize_nodata_response(query: &[u8]) -> Option<Vec<u8>> {
    let parsed = parse_dns_query(query)?;
    let mut resp = Vec::with_capacity(parsed.question_end);
    resp.extend_from_slice(&build_dns_response_header(parsed.tx_id, parsed.flags, 0));
    resp.extend_from_slice(query.get(12..parsed.question_end)?);
    Some(resp)
}

/// Synthesize a captive-portal spoof `A` response resolving to
/// [`CAPTIVE_PORTAL_SPOOF_IP`] (`198.51.100.1`, TTL 5 s). Non-`A` or non-`IN`
/// queries receive a clean `NODATA` reply.
#[must_use]
pub(crate) fn synthesize_captive_portal_a_response(query: &[u8]) -> Option<Vec<u8>> {
    let parsed = parse_dns_query(query)?;
    if parsed.qtype != DNS_TYPE_A || parsed.qclass != DNS_CLASS_IN {
        return synthesize_nodata_response(query);
    }

    let mut resp = Vec::with_capacity(parsed.question_end + 16);
    resp.extend_from_slice(&build_dns_response_header(parsed.tx_id, parsed.flags, 1));
    resp.extend_from_slice(query.get(12..parsed.question_end)?);
    // Compressed pointer to offset 12 (QNAME), TYPE A, CLASS IN, TTL 5s, RDLENGTH 4, 198.51.100.1
    resp.extend_from_slice(&[0xc0, 0x0c]);
    resp.extend_from_slice(&DNS_TYPE_A.to_be_bytes());
    resp.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());
    resp.extend_from_slice(&5u32.to_be_bytes());
    resp.extend_from_slice(&4u16.to_be_bytes());
    resp.extend_from_slice(&CAPTIVE_PORTAL_SPOOF_IP.octets());
    Some(resp)
}
