// SPDX-License-Identifier: Apache-2.0

//! Datagram dispatch: classify a datagram and hand it to a handler.

use super::*;

impl Device {
    pub(super) fn on_datagram(
        &mut self,
        clock: Clock,
        source: SocketAddr,
        bytes: &[u8],
        rng: &mut dyn Randomness,
        out: &mut Vec<Action>,
    ) {
        let Ok(message) = Message::parse(bytes) else {
            return;
        };
        if message.header().suite_id != self.suite.suite_id() {
            return;
        }
        match message.message_type() {
            MessageType::InitHello => {
                self.on_init_hello(clock, source, &message, bytes, rng, out);
            }
            MessageType::RespHello => self.on_resp_hello(clock, source, bytes, out),
            MessageType::InitConf => self.on_init_conf(clock, source, bytes, out),
            MessageType::Data => self.on_data(clock, source, bytes, out),
            MessageType::CookieReply => self.on_cookie_reply(&message, out),
            // Identity documents travel out of band: P3 carries the signature
            // inline in the handshake, so a device has nothing to do with a
            // standalone document and must not guess what to do with one.
            MessageType::IdentityDoc => {}
        }
    }
}
