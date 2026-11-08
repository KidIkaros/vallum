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
//! 4. **What loss costs, and what a real round trip costs.** A plain loopback
//!    cannot lose a segment and cannot be slow, so the last test re-executes
//!    itself into two network namespaces joined by a veth pair and puts a `netem`
//!    qdisc on the client's end: 0 %, 2 % and 5 % loss at a 1 ms round trip, then
//!    a 40 ms round trip clean and at 2 % loss. The retransmission counts are the
//!    kernel's own. Those are the numbers ADR-0026 left open, and they are
//!    recorded in `docs/proof/transport.md` §2.8.
//!
//! The lossy test needs an unprivileged user namespace, `tc` and `nsenter`. Where
//! they are missing it says so and returns rather than failing, because a
//! container without `unshare` is not evidence about a carrier — except on the
//! gate runner, which sets `VALLUM_LOSSY_REQUIRED=1`: there a skip is a failure,
//! because the transport's cost quietly going unmeasured is exactly the failure
//! mode this test exists to prevent.

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

/// The kernel's count of segments dropped *after* they arrived, because the
/// receiving socket's queue was full: `RcvPruned` for the in-order queue,
/// `TCPRcvQDrop` for the backlog.
///
/// It is the difference between a lossy path and a slow reader. A clean path that
/// retransmits has one explanation — the far end could not keep up — and this
/// counter is what says so; without it, a harness that stalls and a qdisc that
/// drops look the same from the sending end.
fn receive_queue_drops() -> u64 {
    let text = std::fs::read_to_string("/proc/net/netstat").expect("netstat");
    let mut names: Vec<&str> = Vec::new();
    for line in text.lines() {
        let Some(values) = line.strip_prefix("TcpExt:") else {
            continue;
        };
        let values: Vec<&str> = values.split_whitespace().collect();
        // Same header-or-values discrimination as `/proc/net/snmp`: the header
        // names counters, the values are numbers.
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
        return read("RcvPruned") + read("TCPRcvQDrop");
    }
    // A driver without these counters is not a reason to fail a measurement.
    0
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
    println!("SERVER frames={frames} pruned={}", receive_queue_drops());
}

/// The near end: write the frames and report what the path cost.
fn lossy_client() {
    let (packets, framed) = sealed_frames();
    let address = lossy_address();

    // The server is started just before this, in another namespace; a connect
    // that loses that race is not the measurement.
    let deadline = Instant::now() + Duration::from_secs(5);
    // The handshake is the only round trip measured on its own, and it is the
    // one place the path's delay shows up without a queue or a congestion window
    // in the way: SYN there, SYN|ACK back. The parent uses it to check that the
    // delay it asked for is really in the path.
    let mut tx;
    let connect_ms;
    loop {
        let started = Instant::now();
        match TcpStream::connect(address) {
            Ok(stream) => {
                connect_ms = started.elapsed().as_millis();
                tx = stream;
                break;
            }
            Err(error) => {
                assert!(
                    Instant::now() < deadline,
                    "could not connect to the far end: {error}"
                );
                std::thread::sleep(Duration::from_millis(20));
            }
        }
    }

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
        "LOSSY packets={packets} bytes={} ms={} connect={connect_ms} retrans={retransmitted} \
         sent={sent}",
        packets * framed.len(),
        elapsed.as_millis()
    );
}

/// One path the carrier is measured on: an offered loss rate, and a one-way
/// delay. The qdisc sits on the client's egress only, so the round trip costs
/// twice the delay.
struct Path {
    label: &'static str,
    loss: u32,
    delay_ms: u32,
}

/// What one path cost.
struct Measurement {
    path: Path,
    packets: u64,
    ms: u64,
    connect_ms: u64,
    retrans: u64,
    sent: u64,
    frames: u64,
    /// Receive-queue drops on the far end: this host's reader falling behind,
    /// never the path's loss.
    pruned: u64,
}

/// The paths worth measuring, and why each one is here.
///
/// Clean and 2 % are the pair ADR-0026 asked for: what loss costs at all. 5 % is
/// where recovery starts to be most of what the stream does. The two delayed
/// paths answer what the 1 ms numbers cannot: a real round trip is not one
/// millisecond, and because a lost segment is repaid one round trip later, the
/// same loss on a 40 ms path is not the same cost. How much larger is the
/// question; it is measured here rather than assumed.
const PATHS: [Path; 5] = [
    Path {
        label: "1 ms, clean",
        loss: 0,
        delay_ms: 1,
    },
    Path {
        label: "1 ms, 2% loss",
        loss: 2,
        delay_ms: 1,
    },
    Path {
        label: "1 ms, 5% loss",
        loss: 5,
        delay_ms: 1,
    },
    Path {
        label: "40 ms RTT, clean",
        loss: 0,
        delay_ms: 20,
    },
    Path {
        label: "40 ms RTT, 2% loss",
        loss: 2,
        delay_ms: 20,
    },
];

/// How the measurement got the namespaces it puts the two ends in.
#[derive(Clone, Copy)]
enum Escalation {
    /// `unshare -Urn`: root inside a namespace of our own, without a password.
    Unprivileged,
    /// `sudo -n unshare -n`: a namespace of root's, on a host that restricts the
    /// unprivileged kind.
    Sudo,
}

/// Runs `program args` the way the measurement will run it, so a probe answers
/// the question actually asked: `tc` can be absent from a runner's `PATH` and
/// present in root's.
fn probed(escalation: Option<Escalation>, program: &str, args: &[&str]) -> bool {
    let mut command = match escalation {
        Some(Escalation::Sudo) => {
            let mut command = Command::new("sudo");
            command.arg("-n").arg(program);
            command
        }
        _ => Command::new(program),
    };
    command
        .args(args)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
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

    // A network namespace to put the two ends in, a qdisc that drops what
    // crosses the wire between them, and a way to enter the second namespace.
    // An unprivileged user namespace is the usual route; where the host restricts
    // those (Ubuntu 24.04's AppArmor default among them) the same script runs
    // under passwordless sudo, which is how the end-to-end gate already copes —
    // and the CI runner needs the budget, so a skip here is the cost of the
    // carrier going unmeasured with every check green.
    let escalation = if probed(None, "unshare", &["-Urn", "true"]) {
        Some(Escalation::Unprivileged)
    } else if probed(Some(Escalation::Sudo), "unshare", &["-n", "true"]) {
        Some(Escalation::Sudo)
    } else {
        None
    };
    // Each prerequisite is checked the way it will be used, so the message names
    // what is missing: "not available here" on its own sends someone looking at
    // the wrong package.
    let mut missing = Vec::new();
    if escalation.is_none() {
        missing.push(
            "`unshare -Urn` (unprivileged user namespaces) or `sudo -n unshare -n` (passwordless sudo)",
        );
    }
    if let Some(escalation) = escalation {
        if !probed(Some(escalation), "tc", &["-V"]) {
            missing.push("`tc`");
        }
        if !probed(Some(escalation), "nsenter", &["--version"]) {
            missing.push("`nsenter`");
        }
    }
    if !missing.is_empty() {
        let verb = if missing.len() == 1 { "is" } else { "are" };
        let line = format!(
            "skipping the lossy-path measurement: {} {verb} not available here",
            missing.join(", ")
        );
        // A gate runner sets this, because there the measurement is the point. A
        // silent skip would leave the carrier's cost unmeasured with every check
        // green, and nobody reads a green suite looking for the absence.
        if std::env::var("VALLUM_LOSSY_REQUIRED").is_ok_and(|required| required == "1") {
            panic!("{line}, and VALLUM_LOSSY_REQUIRED=1");
        }
        eprintln!("{line}");
        return;
    }
    let escalation = escalation.expect("prerequisites checked above");

    let exe = std::env::current_exe().expect("current exe");
    let staged = std::env::temp_dir().join(format!("vallum-carrier-lossy-{}", std::process::id()));
    std::fs::copy(&exe, &staged).expect("stage the test binary where the namespace can reach it");
    let pid_file = |path: &Path| {
        std::env::temp_dir().join(format!(
            "vallum-carrier-ns-{}-{}-{}",
            std::process::id(),
            path.loss,
            path.delay_ms
        ))
    };
    let pidfile = pid_file(&PATHS[0]); // first path, until the loop sets its own
                                       // One log per path, named by what the path offers: a failure then points at
                                       // the run that failed instead of at the first one.
    let scratch = |path: &Path| {
        std::env::temp_dir().join(format!(
            "vallum-carrier-{}-{}-{}.log",
            std::process::id(),
            path.loss,
            path.delay_ms
        ))
    };

    let mut runs: Vec<Measurement> = Vec::new();
    for path in PATHS {
        let (loss, delay) = (path.loss, path.delay_ms);
        // The pidfile is per path: a stale one would park the second namespace on
        // the wrong process, and under sudo the parent cannot clear it.
        let pidfile = pid_file(&path);
        let _ = std::fs::remove_file(&pidfile);
        // Two ends of one wire, in two namespaces: the addresses are local only
        // to the pair, so the kernel has to put the segments on the veth — and
        // the qdisc on the near end is what it consults before each one leaves.
        // `lo` would not do: it has no queue, so an attached qdisc is never
        // consulted and nothing is ever dropped.
        //
        // `limit 100000` rather than netem's default of 1 000 packets: a burst
        // of a whole file overflows a queue that small, and those drops are not
        // the loss this path was asked to offer. With the queue out of the way,
        // a retransmission on a clean path is a timer artifact, not a full
        // buffer.
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
             tc qdisc add dev va root netem delay {delay}ms loss {loss}% limit 100000\n\
             VALLUM_LOSSY_ROLE=client VALLUM_LOSSY_ADDR=10.99.0.2:41820 \
                 {exe} --exact the_carrier_pays_retransmissions_on_a_lossy_path --nocapture\n\
             wait \"$server\"\n\
             kill \"$holder\" 2>/dev/null || true\n\
             cat {log}\n\
             rm -f {log}\n",
            pidfile = pidfile.display(),
            exe = staged.display(),
            log = scratch(&path).display(),
        );
        let output = match escalation {
            Escalation::Sudo => {
                let mut command = Command::new("sudo");
                command.arg("-n").arg("unshare").args(["-n", "bash", "-c"]);
                command.arg(&script).output().expect("run the namespace")
            }
            Escalation::Unprivileged => Command::new("unshare")
                .args(["-Urn", "bash", "-c"])
                .arg(&script)
                .output()
                .expect("run the namespace"),
        };
        // The script echoes the far end's report into stdout and removes its own
        // files, because as root it owns them and the parent could not.
        let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
        let _ = std::fs::remove_file(scratch(&path));

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
                    "no measurement at {loss}% loss\nstdout:\n{stdout}\nstderr:\n{}",
                    String::from_utf8_lossy(&output.stderr)
                )
            })
            .to_owned();
        let served = stdout
            .lines()
            .find(|line| line.starts_with("SERVER "))
            .unwrap_or_else(|| {
                panic!(
                    "the far end reported nothing at {loss}% loss\nstdout:\n{stdout}\nstderr:\n{}",
                    String::from_utf8_lossy(&output.stderr)
                )
            });

        runs.push(Measurement {
            path,
            packets: field(&lossy, "packets"),
            ms: field(&lossy, "ms"),
            connect_ms: field(&lossy, "connect"),
            retrans: field(&lossy, "retrans"),
            sent: field(&lossy, "sent"),
            frames: field(served, "frames"),
            pruned: field(served, "pruned"),
        });
    }
    let _ = std::fs::remove_file(&staged);
    let _ = std::fs::remove_file(&pidfile);
    // As root, the staged binary outlives the parent's reach: everything the
    // script itself made is gone, and this one file is the exception.
    if let Escalation::Sudo = escalation {
        let _ = Command::new("sudo")
            .args(["-n", "rm", "-f"])
            .arg(&staged)
            .status();
    }

    println!(
        "{:>18} {:>8} {:>10} {:>8} {:>22} {:>8} {:>8}",
        "path", "connect", "time", "frames", "retransmitted", "arrived", "pruned"
    );
    for run in &runs {
        println!(
            "{:>18} {:>5} ms {:>7} ms {:>8} {:>10} / {:<11} {:>8} {:>8}",
            run.path.label,
            run.connect_ms,
            run.ms,
            run.packets,
            run.retrans,
            run.sent,
            run.frames,
            run.pruned
        );
    }

    // Delivery is not the casualty of loss — the clock is. A missing frame on any
    // path means the framing or the connection is wrong, not that the path was
    // lossy.
    let packets = runs[0].packets;
    for run in &runs {
        assert_eq!(run.packets, packets, "the frame count moved between paths");
        assert_eq!(
            run.frames, packets,
            "{} delivered {} of {packets} frames",
            run.path.label, run.frames
        );
    }

    // The qdisc has to have been in the path, or every number here is one
    // loopback measurement wearing five labels. A clean path retransmits nothing,
    // a lossy one retransmits, and a delayed one takes longer than the undelayed
    // one — each of those fails loudly if the traffic went around the qdisc.
    let base = &runs[0];
    for run in &runs {
        if run.path.loss == 0 {
            // Nothing should be retransmitted on a clean path, and where it is,
            // the receiving host has to have been the reason: this test reads a
            // frame at a time with a decryption in the loop, so on a delayed
            // path its own queue can fill while its reader is busy. That is a
            // property of the harness, not of the carrier — but it has to be
            // visible in the counters, or it is a qdisc dropping clean traffic
            // and every number below is wrong.
            if run.retrans > 0 {
                assert!(
                    run.pruned > 0,
                    "{} retransmitted {} of {} segments with no loss offered and no \
                     receive-queue drops on the far end",
                    run.path.label,
                    run.retrans,
                    run.sent
                );
                // Even explained, it has to stay a fraction of a percent: a
                // reader that cannot keep up with a clean path is not measuring
                // the carrier either.
                assert!(
                    run.retrans * 100 <= run.sent,
                    "{} retransmitted {} of {} segments with no loss offered",
                    run.path.label,
                    run.retrans,
                    run.sent
                );
            }
            continue;
        }
        assert!(
            run.retrans > 0,
            "{} produced no retransmissions, so the netem qdisc did not apply",
            run.path.label
        );
        let clean = runs
            .iter()
            .find(|other| other.path.loss == 0 && other.path.delay_ms == run.path.delay_ms)
            .expect("a clean path with the same delay");
        assert!(
            run.ms > clean.ms,
            "{} took {} ms against {} ms clean, so the offered loss did not apply",
            run.path.label,
            run.ms,
            clean.ms
        );
    }
    // The delay, checked on the handshake rather than on the transfer: a bulk
    // run's wall clock swings by hundreds of milliseconds on a busy machine, and
    // an assertion that noisy would either pass by accident or fail at random.
    // One SYN and one SYN|ACK are a round trip and nothing else.
    let delayed = runs
        .iter()
        .find(|run| run.path.loss == 0 && run.path.delay_ms != base.path.delay_ms)
        .expect("a clean path with a real round trip");
    assert!(
        delayed.connect_ms >= 30 && base.connect_ms < 30,
        "the handshake took {} ms on {} and {} ms on {}, so the {} ms one-way delay did not \
         apply",
        delayed.connect_ms,
        delayed.path.label,
        base.connect_ms,
        base.path.label,
        delayed.path.delay_ms
    );

    let at = |loss: u32, delay_ms: u32| {
        runs.iter()
            .find(|run| run.path.loss == loss && run.path.delay_ms == delay_ms)
            .expect("the path is in the table")
    };
    let five = at(5, base.path.delay_ms);
    let far = at(2, delayed.path.delay_ms);
    println!(
        "the carrier on {} paths, {packets} frames each: {} ms clean, {} ms at 5% loss (\
         {:.1}x), {} ms at 40 ms RTT and 2% loss ({:.1}x), every frame delivered",
        runs.len(),
        base.ms,
        five.ms,
        five.ms as f64 / base.ms as f64,
        far.ms,
        far.ms as f64 / base.ms as f64,
    );
}
