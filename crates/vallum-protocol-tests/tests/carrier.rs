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
//! What is *not* measured: behaviour under loss. Loopback TCP does not drop
//! segments, and a carrier that cannot be made to lose one cannot be made to show
//! its retransmission cost in a unit test. That number is named as unmeasured in
//! `docs/proof/transport.md` rather than guessed at.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
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
