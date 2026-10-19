#![no_main]

//! The TLV parser and the segmentation envelope, on arbitrary bytes.
//!
//! Invariants: never panic, and a message that parses must round-trip. The
//! round-trip is the stronger one: `serialize_fields` writes the same header and
//! the same tag/length/value triples in the same order, so a parsed message
//! rebuilt field by field must reproduce its input byte for byte. A mismatch
//! means the parser accepts something the builder would not emit — exactly the
//! non-canonical encoding a second implementation could disagree with.

use libfuzzer_sys::fuzz_target;
use vallum_tunnel::segment;
use vallum_core::wire::{Message, MessageBuilder};

fuzz_target!(|data: &[u8]| {
    let _ = segment::parse(data);
    let _ = segment::is_fragment(data);

    let Ok(message) = Message::parse(data) else {
        return;
    };

    // These walk the field list; a malformed-but-accepted message must not make
    // any of them panic.
    let _ = message.mac1_input();
    let _ = message.mac2_input();
    let _ = message.resp_tag_input();
    let _ = message.field_count();

    let mut builder = MessageBuilder::new(message.header());
    for tag in message.tags() {
        let value = message
            .get(tag)
            .expect("a tag from the iterator has a value");
        if builder.field(tag, value).is_err() {
            return;
        }
    }
    let rebuilt = builder.finish().expect("a parsed message fits the cap");
    assert_eq!(
        rebuilt.as_slice(),
        data,
        "a parsed message did not round-trip"
    );
});
