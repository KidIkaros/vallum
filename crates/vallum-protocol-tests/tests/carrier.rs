// SPDX-License-Identifier: Apache-2.0

//! What a stream carrier would cost, measured rather than argued.
//!
//! ADR-0026 says the only transport worth adding is UDP-over-TCP with the same
//! handshake inside, and that its cost must be measured before it is offered as
//! anything. This file is that measurement, taken over a real TCP connection on
//! loopback with real sealed packets, so the numbers are the carrier's and not a
//! model of it:
//!
//! 1. **The framing carries packets unchanged.** A sealed data packet goes out
//!    framed and comes back byte-identical, opened to the same payload.
//! 2. **The overhead is per packet, in the frame and in the headers.** Two bytes
//!    of length prefix, and the difference between a UDP+IP header and a TCP+IP
//!    one — both counted from the real sockets, not quoted from a textbook.
//! 3. **A stream orders everything behind everything.** One slow read holds every
//!    later packet — head-of-line blocking is the whole reason this is a fallback
//!    and not the default, and it is shown here as a delay, not asserted.
//!
//! 4. **What loss costs.** A plain loopback cannot lose a segment, so the last
//!    test re-executes itself inside a network namespace and puts a `netem` qdisc
//!    with 0 % and 2 % loss on `lo`: the same packets, the same reader, and the
//!    retransmissions the kernel actually made. That is the one number ADR-0026
//!    left open, and it is recorded in `docs/proof/transport.md` §2.8.
//!
//! The lossy test needs an unprivileged user namespace and `tc`; where those are
//! missing it says so and returns rather than failing, because a CI container
//! without `unshare` is not evidence about a carrier.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::Command;
use std::time::{Duration, Instant};

use vallum_core::{establish_epoch, Receiver, Role, Sender, PAYLOAD_LEN_SIZE};
use vallum_crypto::SharedSecret;
use vallum_crypto_sdk::SdkSuite;
use vallum_tunnel::stream::{frame, FrameReader, FRAME_LEN_SIZE, MAX_FRAME};

const OWN: u32 = 0xAAAA_AAAA;
const PEER: u32 = 0xBBBB_BBBB;

/// A mirrored key pair, as a completed handshake leaves one.
fn link() -> (SdkSuite, Sender, Receiver) {
    let suite = SdkSuite::tri_hybrid();
    let root = SharedSecret::new([0x33; 32]);
    let transcript = [0x44u8; 32];
    let (a_send, _a_recv) =
        establish_epoch(&suite, &root, &transcript, 0, Role::Initiator, OWN, PEER).expect("a");
    let (_b_send, b_recv) =
        establish_epoch(&suite, &root, &transcript, 0, Role::Responder, PEER, OWN).expect("b");
    (suite, a_send, b_recv)
}

fn payload(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251) as u8).collect()
}

/// A connected pair of streams on loopback, as a carrier would have.
fn connected_pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let address = listener.local_addr().expect("addr");
    let sender = TcpStream::connect(address).expect("connect");
    let (accepted, _) = listener.accept().expect("accept");
    (sender, accepted)
}

#[test]
fn the_framing_carries_a_sealed_packet_unchanged() {
    let (suite, mut a_send, mut b_recv) = link();
    let (mut tx, mut rx) = connected_pair();

    for len in [0usize, 40, 1_398] {
        let body = payload(len);
        let packet = a_send
            .seal_padded(&suite, &body, 1_400)
            .expect("seal the packet");
        tx.write_all(&frame(&packet).expect("frame"))
            .expect("write");

        let mut reader = FrameReader::new();
        let mut buffer = [0u8; 2_048];
        let received = loop {
            if let Some(framed) = reader.next_frame().expect("framing") {
                break framed;
            }
            let read = rx.read(&mut buffer).expect("read");
            assert!(read > 0, "the stream ended before a frame arrived");
            reader.push(&buffer[..read]);
        };

        // Byte-identical, and it opens to the payload it was sealed from: the
        // carrier added a length and changed nothing else.
        assert_eq!(received, packet, "{len} bytes");
        assert_eq!(b_recv.open(&suite, &received).expect("open"), body);
    }
}

#[test]
fn the_carrier_costs_two_bytes_of_frame_per_packet() {
    let (suite, mut a_send, _b_recv) = link();
    let (mut tx, mut rx) = connected_pair();

    const PACKETS: usize = 64;
    let packet = a_send
        .seal_padded(&suite, &payload(1_398), 1_400)
        .expect("seal");

    let mut bytes_on_the_wire = 0usize;
    let started = Instant::now();
    for _ in 0..PACKETS {
        let framed = frame(&packet).expect("frame");
        bytes_on_the_wire += framed.len();
        tx.write_all(&framed).expect("write");
    }
    tx.flush().expect("flush");

    let mut reader = FrameReader::new();
    let mut seen = 0usize;
    let mut buffer = [0u8; 8_192];
    while seen < PACKETS {
        if reader.next_frame().expect("framing").is_some() {
            seen += 1;
            continue;
        }
        let read = rx.read(&mut buffer).expect("read");
        assert!(read > 0, "the stream ended early");
        reader.push(&buffer[..read]);
    }
    let elapsed = started.elapsed();

    let per_packet = bytes_on_the_wire / PACKETS;
    println!(
        "framed: {PACKETS} packets, {bytes_on_the_wire} bytes, \
         {per_packet} per packet against {} for the packet itself -- \
         {} bytes of frame each, in {elapsed:?}",
        packet.len(),
        per_packet - packet.len()
    );

    // The frame is the length prefix and nothing else: no padding, no alignment,
    // no delimiter to escape. That is the whole per-packet cost of the carrier at
    // this layer.
    assert_eq!(per_packet, packet.len() + FRAME_LEN_SIZE);
    // The packet itself is a 1 400-byte sealed plaintext plus the tunnel's own
    // header, counter and tag: 1 456 bytes, which the carrier does not touch.
    assert_eq!(
        packet.len(),
        1_400 + PAYLOAD_LEN_SIZE + 54,
        "the reference packet is the shape a data packet has"
    );
    // And a packet past the ceiling is refused rather than buffered: the carrier
    // does not re-implement the tunnel's own segmentation.
    assert!(frame(&vec![0u8; MAX_FRAME + 1]).is_err());
}

#[test]
fn a_stream_orders_everything_behind_the_slowest_read() {
    // Head-of-line blocking, shown rather than argued: the second packet is in
    // the socket long before anyone reads it, and it still arrives after the
    // first is drained — because a stream has one order and one queue.
    let (mut tx, mut rx) = connected_pair();
    rx.set_read_timeout(Some(Duration::from_millis(200)))
        .expect("timeout");

    let first = frame(&vec![1u8; 1_400]).expect("frame");
    let second = frame(&vec![2u8; 1_400]).expect("frame");
    tx.write_all(&first).expect("write first");
    tx.write_all(&second).expect("write second");
    tx.flush().expect("flush");

    // Nothing is read yet, so both packets are waiting. A datagram carrier would
    // hand the second to a reader that asked for it; a stream cannot.
    std::thread::sleep(Duration::from_millis(50));

    let mut reader = FrameReader::new();
    let mut buffer = [0u8; 4_096];
    let mut frames = Vec::new();
    while frames.len() < 2 {
        if let Some(packet) = reader.next_frame().expect("framing") {
            frames.push(packet);
            continue;
        }
        let read = rx.read(&mut buffer).expect("read");
        assert!(read > 0, "the stream ended early");
        reader.push(&buffer[..read]);
    }

    // They come back in order, and the second could not have been handed over
    // before the first: that is the cost the fallback trades for reachability.
    assert_eq!(frames[0], vec![1u8; 1_400]);
    assert_eq!(frames[1], vec![2u8; 1_400]);
}

/// The kernel's own count of segments sent twice, and of segments sent.
///
/// `/proc/net/snmp` holds two lines per protocol: the header names and the values,
/// positionally. `RetransSegs` is what a lossy path costs in the transport, taken
/// from the kernel rather than modelled — and `OutSegs` is the denominator that
/// turns it into a rate.
///
/// Not `/proc/net/netstat`: that file's `TcpExt:` block carries the extension
/// counters, and on this kernel it has no retransmission total at all (it has
/// `TCPFastRetrans` and friends, which are different questions). Reading the
/// wrong file returns zero for every run and makes a perfect path look perfect
/// under any loss.
fn tcp_segments() -> (u64, u64) {
    let text = std::fs::read_to_string("/proc/net/snmp").expect("snmp");
    let mut names: Vec<&str> = Vec::new();
    for line in text.lines() {
        let Some(values) = line.strip_prefix("Tcp:") else {
            continue;
        };
        let values: Vec<&str> = values.split_whitespace().collect();
        // The header line carries names, the values line numbers — and `MaxConn`
        // is `-1` when the kernel means "no limit", so "all fields are unsigned"
        // is not the test. The first field is: `RtoAlgorithm` against `1`.
        if values
            .first()
            .is_none_or(|value| value.parse::<u64>().is_err())
        {
            names = values;
            continue;
        }
        let read = |name: &str| -> u64 {
            names
                .iter()
                .position(|candidate| *candidate == name)
                .and_then(|index| values.get(index))
                .and_then(|value| value.parse().ok())
                .unwrap_or(0)
        };
        return (read("RetransSegs"), read("OutSegs"));
    }
    panic!("/proc/net/snmp has no Tcp: block");
}

/// How much payload one run pushes: a megabyte, in the carrier's real frame.
const LOSSY_BYTES: usize = 32 << 20;

/// The frames a run sends, and how many there are.
fn sealed_frames() -> (usize, Vec<u8>) {
    let (suite, mut a_send, _b_recv) = link();
    let packet = a_send
        .seal_padded(&suite, &payload(1_398), 1_400)
        .expect("seal");
    let framed = frame(&packet).expect("frame");
    let packets = LOSSY_BYTES / framed.len();
    (packets, framed)
}

fn lossy_address() -> std::net::SocketAddr {
    std::env::var("VALLUM_LOSSY_ADDR")
        .expect("the parent passes the address to use")
        .parse()
        .expect("a socket address")
}

/// The far end of the lossy path, in the second namespace: read until the stream
/// ends and report how many frames arrived.
///
/// Delivery is the point: a stream loses *time*, never data, so a lost frame
/// here would mean the framing or the connection is wrong, not that the path is
/// lossy.
fn lossy_server() {
    let listener = TcpListener::bind(lossy_address()).expect("bind");
    let (mut rx, _) = listener.accept().expect("accept");
    let mut reader = FrameReader::new();
    let mut buffer = vec![0u8; 64 * 1024];
    let mut frames = 0usize;
    loop {
        match rx.read(&mut buffer) {
            Ok(0) => break,
            Ok(count) => {
                reader.push(&buffer[..count]);
                while reader.next_frame().expect("framing").is_some() {
                    frames += 1;
                }
            }
            Err(error) => panic!("read: {error}"),
        }
    }
    println!("SERVER frames={frames}");
}

/// The near end: write the frames and report what the path cost.
fn lossy_client() {
    let (packets, framed) = sealed_frames();
    let address = lossy_address();

    // The server is started just before this, in another namespace; a connect
    // that loses that race is not the measurement.
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut tx = loop {
        match TcpStream::connect(address) {
            Ok(stream) => break stream,
            Err(error) => {
                assert!(
                    Instant::now() < deadline,
                    "could not connect to the far end: {error}"
                );
                std::thread::sleep(Duration::from_millis(20));
            }
        }
    };

    let (retrans_before, out_before) = tcp_segments();
    let started = Instant::now();
    for _ in 0..packets {
        tx.write_all(&framed).expect("write");
    }
    tx.flush().expect("flush");
    // Write half remains open until the far end has drained everything: timing
    // the writes alone would hide a retransmission still in flight.
    tx.set_read_timeout(Some(Duration::from_secs(30)))
        .expect("timeout");
    tx.shutdown(std::net::Shutdown::Write).expect("shutdown");
    let mut sink = [0u8; 1];
    let _ = tx.read(&mut sink);
    let elapsed = started.elapsed();
    let (retrans_after, out_after) = tcp_segments();
    let retransmitted = retrans_after.saturating_sub(retrans_before);
    let sent = out_after.saturating_sub(out_before);

    println!(
        "LOSSY packets={packets} bytes={} ms={} retrans={retransmitted} sent={sent}",
        packets * framed.len(),
        elapsed.as_millis()
    );
}

#[test]
fn the_carrier_pays_retransmissions_on_a_lossy_path() {
    // The same test binary, in three roles: the parent sets the path up, and the
    // two ends measure inside it.
    match std::env::var("VALLUM_LOSSY_ROLE").as_deref() {
        Ok("server") => return lossy_server(),
        Ok("client") => return lossy_client(),
        _ => {}
    }

    // An unprivileged user namespace, `tc`, and `nsenter` are what make a path
    // lose packets. Where any is missing this is not a statement about the
    // carrier, so it is a skip, not a failure.
    let tooling = Command::new("unshare")
        .args(["-Urn", "true"])
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
        && Command::new("tc").arg("-V").output().is_ok()
        && Command::new("nsenter").arg("--version").output().is_ok();
    if !tooling {
        eprintln!(
            "skipping the lossy-path measurement: `unshare -Urn`, `tc`, or `nsenter` is not \
             available here"
        );
        return;
    }

    let exe = std::env::current_exe().expect("current exe");
    let staged = std::env::temp_dir().join(format!("vallum-carrier-lossy-{}", std::process::id()));
    std::fs::copy(&exe, &staged).expect("stage the test binary where the namespace can reach it");
    let pidfile = std::env::temp_dir().join(format!("vallum-carrier-ns-{}", std::process::id()));
    let scratch = |loss: u32| {
        std::env::temp_dir().join(format!("vallum-carrier-{}-{loss}.log", std::process::id()))
    };

    let mut runs = Vec::new();
    for loss in [0u32, 2] {
        // Two ends of one wire, in two namespaces: the addresses are local only
        // to the pair, so the kernel has to put the segments on the veth — and
        // the qdisc on the near end is what it consults before each one leaves.
        // `lo` would not do: it has no queue, so an attached qdisc is never
        // consulted and nothing is ever dropped.
        let script = format!(
            "set -e\n\
             ip link add va type veth peer name vb\n\
             ip addr add 10.99.0.1/24 dev va\n\
             ip link set va up\n\
             ip link set lo up\n\
             unshare -n bash -c 'echo $$ > {pidfile}; exec sleep 120' >/dev/null 2>&1 &\n\
             for _ in $(seq 1 100); do [ -s {pidfile} ] && break; sleep 0.05; done\n\
             holder=$(cat {pidfile})\n\
             ip link set vb netns \"$holder\"\n\
             nsenter -t \"$holder\" -n ip addr add 10.99.0.2/24 dev vb\n\
             nsenter -t \"$holder\" -n ip link set vb up\n\
             VALLUM_LOSSY_ROLE=server VALLUM_LOSSY_ADDR=10.99.0.2:41820 \
                 nsenter -t \"$holder\" -n {exe} \
                 --exact the_carrier_pays_retransmissions_on_a_lossy_path --nocapture \
                 > {log} 2>&1 &\n\
             server=$!\n\
             sleep 0.3\n\
             tc qdisc add dev va root netem delay 1ms loss {loss}%\n\
             VALLUM_LOSSY_ROLE=client VALLUM_LOSSY_ADDR=10.99.0.2:41820 \
                 {exe} --exact the_carrier_pays_retransmissions_on_a_lossy_path --nocapture\n\
             wait \"$server\"\n\
             kill \"$holder\" 2>/dev/null || true\n",
            pidfile = pidfile.display(),
            exe = staged.display(),
            log = scratch(loss).display(),
        );
        // The pidfile is per run: a stale one from a previous run would park the
        // second namespace on the wrong process.
        let _ = std::fs::remove_file(&pidfile);
        let output = Command::new("unshare")
            .args(["-Urn", "bash", "-c", &script])
            .output()
            .expect("run the namespace");
        let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
        let server_log = std::fs::read_to_string(scratch(loss)).unwrap_or_default();
        let _ = std::fs::remove_file(scratch(loss));

        let field = |line: &str, name: &str| -> u64 {
            line.split_whitespace()
                .find_map(|word| word.strip_prefix(&format!("{name}=")))
                .and_then(|value| value.parse().ok())
                .unwrap_or_else(|| panic!("`{name}` missing from `{line}`"))
        };
        let lossy = stdout
            .lines()
            .find(|line| line.starts_with("LOSSY "))
            .unwrap_or_else(|| {
                panic!(
                    "no measurement at {loss}% loss\nstdout:\n{stdout}\nstderr:\n{}\nserver:\n{server_log}",
                    String::from_utf8_lossy(&output.stderr)
                )
            })
            .to_owned();
        let served = server_log
            .lines()
            .find(|line| line.starts_with("SERVER "))
            .unwrap_or_else(|| {
                panic!("the far end reported nothing at {loss}% loss\n{server_log}")
            });

        runs.push((
            loss,
            field(&lossy, "packets"),
            field(&lossy, "ms"),
            field(&lossy, "retrans"),
            field(&lossy, "sent"),
            field(served, "frames"),
            lossy.clone(),
        ));
    }
    let _ = std::fs::remove_file(&staged);
    let _ = std::fs::remove_file(&pidfile);

    for (loss, packets, ms, retrans, sent, frames, _) in &runs {
        println!(
            "{loss}% loss: {packets} frames, {ms} ms, {retrans}/{sent} segments retransmitted, \
             {frames} arrived"
        );
    }
    let (_, packets_clean, ms_clean, retrans_clean, _, frames_clean, _) = runs[0];
    let (_, packets_lossy, ms_lossy, retrans_lossy, sent_lossy, frames_lossy, _) = runs[1];

    assert_eq!(packets_clean, packets_lossy);
    // Delivery is not the casualty of loss — the clock is.
    assert_eq!(frames_clean, packets_clean, "the clean path lost data");
    assert_eq!(frames_lossy, packets_lossy, "the lossy path lost data");
    // A lossless path retransmits nothing; if this is non-zero the baseline is
    // not a baseline and the comparison means nothing.
    assert_eq!(
        retrans_clean, 0,
        "a path with no loss retransmitted {retrans_clean} segments"
    );
    // 2 % of ~720 segments is fourteen, so zero retransmissions means the qdisc
    // was not in the path — the one way this test could pass without measuring.
    assert!(
        retrans_lossy > 0,
        "2% loss produced no retransmissions, so the netem qdisc did not apply"
    );
    println!(
        "the carrier under loss: {ms_clean} ms clean, {ms_lossy} ms at 2% \
         ({retrans_lossy} of {sent_lossy} segments retransmitted, \
         {frames_lossy} frames delivered intact)"
    );
}
