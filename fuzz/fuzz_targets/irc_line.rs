//! Framing and message parsing from raw stream bytes.

#![no_main]

use libfuzzer_sys::fuzz_target;
use xdcc_core::proto::IrcMessage;
use xdcc_core_fuzz::{check_bound, frame_stream, measured};

fuzz_target!(|data: &[u8]| {
    // The whole input also goes straight to the parser, unframed.
    let (_, bytes) = measured(|| IrcMessage::parse(data).map(|message| message.tags().count()));
    check_bound(bytes);

    // The frames must not depend on where the stream was cut.
    let cut = data
        .first()
        .map_or(0, |&byte| usize::from(byte) * data.len() / 256);
    let (head, tail) = data.split_at(cut);
    assert_eq!(frame_stream(head, tail), frame_stream(data, &[]));
});
