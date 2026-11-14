// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::expect_used, clippy::unwrap_used)]

use super::proxy::*;
use super::resolvers::*;
use super::wire::build_dns_response_header;
use super::wire::*;
use std::fs;
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use vallum_config::Config;

fn build_dns_query(tx_id: u16, name: &str, qtype: u16) -> Vec<u8> {
    let mut pkt = Vec::new();
    pkt.extend_from_slice(&tx_id.to_be_bytes());
    pkt.extend_from_slice(&0x0100u16.to_be_bytes()); // RD=1
    pkt.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT=1
    pkt.extend_from_slice(&[0u8; 6]);
    for label in name.split('.') {
        pkt.push(label.len() as u8);
        pkt.extend_from_slice(label.as_bytes());
    }
    pkt.push(0);
    pkt.extend_from_slice(&qtype.to_be_bytes());
    pkt.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());
    pkt
}

#[test]
fn dns_wire_parser_and_captive_portal_or_nodata_synthesizers_roundtrip() {
    let q_a = build_dns_query(0x1337, "connectivitycheck.gstatic.com", DNS_TYPE_A);
    let parsed = parse_dns_query(&q_a).expect("parse A query");
    assert_eq!(parsed.tx_id, 0x1337);
    assert_eq!(parsed.qname, "connectivitycheck.gstatic.com");
    assert_eq!(parsed.qtype, DNS_TYPE_A);
    assert_eq!(parsed.qclass, DNS_CLASS_IN);

    // Captive portal A response has ANCOUNT=1 and resolves to 198.51.100.1.
    let spoof_a = synthesize_captive_portal_a_response(&q_a).expect("captive A");
    assert_eq!(&spoof_a[0..2], &0x1337u16.to_be_bytes());
    assert_eq!(u16::from_be_bytes([spoof_a[6], spoof_a[7]]), 1);
    assert_eq!(&spoof_a[spoof_a.len() - 4..], &[198, 51, 100, 1]);

    // AAAA query gets clean NODATA (ANCOUNT=0, RCODE=0) from both synthesizers.
    let q_aaaa = build_dns_query(0x4242, "example.com", DNS_TYPE_AAAA);
    let nodata = synthesize_nodata_response(&q_aaaa).expect("nodata AAAA");
    assert_eq!(&nodata[0..2], &0x4242u16.to_be_bytes());
    assert_eq!(u16::from_be_bytes([nodata[6], nodata[7]]), 0);
    assert_eq!(nodata[3] & 0x0f, 0); // RCODE=0 (NOERROR)
    assert_eq!(
        synthesize_captive_portal_a_response(&q_aaaa).expect("captive AAAA"),
        nodata
    );

    // Malformed / response packet (QR=1) is rejected cleanly.
    assert!(parse_dns_query(&nodata).is_none());
    assert!(parse_dns_query(&[0u8; 5]).is_none());
}

#[test]
fn resolver_classifier_splits_rfc1918_lan_from_cgnat_magic_and_public_dns() {
    let servers = vec![
        "100.64.0.7".to_owned(),
        "192.168.1.1".to_owned(),
        "10.0.0.53".to_owned(),
        "172.16.4.2".to_owned(),
        "fd00::53".to_owned(),
        "1.1.1.1".to_owned(),
        "2606:4700:4700::1111".to_owned(),
    ];
    // When allow_lan is true, RFC1918/ULA go to LAN while CGNAT magic 100.64.0.7 + public stay in tunnel.
    let (tunnel, lan) = split_resolvers(&servers, true);
    assert_eq!(
        tunnel,
        vec![
            "100.64.0.7".parse::<IpAddr>().unwrap(),
            "1.1.1.1".parse::<IpAddr>().unwrap(),
            "2606:4700:4700::1111".parse::<IpAddr>().unwrap(),
        ]
    );
    assert_eq!(
        lan,
        vec![
            "192.168.1.1".parse::<IpAddr>().unwrap(),
            "10.0.0.53".parse::<IpAddr>().unwrap(),
            "172.16.4.2".parse::<IpAddr>().unwrap(),
            "fd00::53".parse::<IpAddr>().unwrap(),
        ]
    );

    // When allow_lan is false, every resolver stays in-tunnel.
    let (all_tunnel, no_lan) = split_resolvers(&servers, false);
    assert!(no_lan.is_empty());
    assert_eq!(all_tunnel.len(), servers.len());

    assert!(is_local_domain("printer.lan"));
    assert!(is_local_domain("nas.local."));
    assert!(is_local_domain("router.home.arpa"));
    assert!(!is_local_domain("mullvad.net"));

    let load_cfg = |tag: &str, body: &str| {
        let dir = std::env::temp_dir().join(format!(
            "vallum-quick-dns-classify-{}-{tag}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("mkdir");
        let path = dir.join("v.toml");
        fs::write(&path, body).expect("write toml");
        let cfg = Config::load(&path).expect("load cfg");
        let _ = fs::remove_dir_all(&dir);
        cfg
    };

    let v4_only_cfg = load_cfg(
        "v4",
        "[interface]\nname = \"v0\"\nprivate_key = \"k\"\naddresses = [\"10.7.0.2/24\"]\n\
         [[peer]]\nname = \"p\"\npublic_key = \"k\"\nallowed_ips = [\"0.0.0.0/0\"]\n",
    );
    assert!(tunnel_is_ipv4_only(&v4_only_cfg));

    let dual_cfg = load_cfg(
        "dual",
        "[interface]\nname = \"v0\"\nprivate_key = \"k\"\naddresses = [\"10.7.0.2/24\", \"fd00:7::2/64\"]\n\
         [[peer]]\nname = \"p\"\npublic_key = \"k\"\nallowed_ips = [\"0.0.0.0/0\", \"::/0\"]\n",
    );
    assert!(!tunnel_is_ipv4_only(&dual_cfg));
}

#[test]
fn loopback_dns_proxy_suppresses_aaaa_spoofs_captive_portal_and_routes_lan_domains() {
    fn spawn_mock_upstream(reply_last_byte: u8) -> (SocketAddr, Arc<AtomicUsize>) {
        let sock = UdpSocket::bind("127.0.0.1:0").expect("mock upstream");
        sock.set_read_timeout(Some(Duration::from_secs(2)))
            .expect("timeout");
        let addr = sock.local_addr().expect("addr");
        let count = Arc::new(AtomicUsize::new(0));
        let c2 = Arc::clone(&count);
        thread::spawn(move || {
            let mut buf = [0u8; 512];
            for _ in 0..4 {
                let Ok((n, cli)) = sock.recv_from(&mut buf) else {
                    break;
                };
                c2.fetch_add(1, Ordering::Relaxed);
                if let Some(parsed) = parse_dns_query(&buf[..n]) {
                    let mut resp = Vec::with_capacity(parsed.question_end + 16);
                    resp.extend_from_slice(&build_dns_response_header(
                        parsed.tx_id,
                        parsed.flags,
                        1,
                    ));
                    resp.extend_from_slice(&buf[12..parsed.question_end]);
                    resp.extend_from_slice(&[
                        0xc0,
                        0x0c,
                        0x00,
                        0x01,
                        0x00,
                        0x01,
                        0x00,
                        0x00,
                        0x00,
                        0x3c,
                        0x00,
                        0x04,
                        10,
                        20,
                        30,
                        reply_last_byte,
                    ]);
                    let _ = sock.send_to(&resp, cli);
                }
            }
        });
        (addr, count)
    }

    let (tunnel_up, tunnel_hits) = spawn_mock_upstream(11);
    let (lan_up, lan_hits) = spawn_mock_upstream(22);

    let proxy = LoopbackDnsProxy::bind(
        "127.0.0.1:0".parse().expect("loopback"),
        Upstreams {
            tunnel: vec![tunnel_up],
            lan: vec![lan_up],
        },
        ProxyPolicy {
            suppress_aaaa: true,
            captive_spoof: false,
        },
    )
    .expect("bind proxy");

    let client = UdpSocket::bind("127.0.0.1:0").expect("client");
    client
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("timeout");

    // 1. AAAA query suppressed locally (NODATA, zero upstream hits).
    let q_aaaa = build_dns_query(0x1001, "example.com", DNS_TYPE_AAAA);
    client
        .send_to(&q_aaaa, proxy.local_addr())
        .expect("send aaaa");
    let mut rbuf = [0u8; 512];
    let (n, _) = client.recv_from(&mut rbuf).expect("recv aaaa");
    assert_eq!(&rbuf[0..2], &0x1001u16.to_be_bytes());
    assert_eq!(u16::from_be_bytes([rbuf[6], rbuf[7]]), 0);
    assert!(n >= q_aaaa.len());
    assert_eq!(tunnel_hits.load(Ordering::Relaxed), 0);

    // 2. Public A query goes to tunnel upstream -> 10.20.30.11.
    let q_pub = build_dns_query(0x1002, "example.com", DNS_TYPE_A);
    client
        .send_to(&q_pub, proxy.local_addr())
        .expect("send pub");
    let (n, _) = client.recv_from(&mut rbuf).expect("recv pub");
    assert_eq!(&rbuf[n - 4..n], &[10, 20, 30, 11]);
    assert_eq!(tunnel_hits.load(Ordering::Relaxed), 1);

    // 3. `.lan` A query goes to LAN upstream -> 10.20.30.22.
    let q_lan = build_dns_query(0x1003, "printer.lan", DNS_TYPE_A);
    client
        .send_to(&q_lan, proxy.local_addr())
        .expect("send lan");
    let (n, _) = client.recv_from(&mut rbuf).expect("recv lan");
    assert_eq!(&rbuf[n - 4..n], &[10, 20, 30, 22]);
    assert_eq!(lan_hits.load(Ordering::Relaxed), 1);

    // 4. Enabling captive_spoof intercepts A locally -> 198.51.100.1 without hitting upstream.
    proxy.set_captive_spoof(true);
    let q_cap = build_dns_query(0x1004, "captive.apple.com", DNS_TYPE_A);
    client
        .send_to(&q_cap, proxy.local_addr())
        .expect("send cap");
    let (n, _) = client.recv_from(&mut rbuf).expect("recv cap");
    assert_eq!(&rbuf[n - 4..n], &[198, 51, 100, 1]);
    assert_eq!(tunnel_hits.load(Ordering::Relaxed), 1);
}
