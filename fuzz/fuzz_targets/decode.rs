//! Wire decoding on arbitrary bytes: the primitives and ATTRS must never
//! panic, read out of bounds or allocate based on hostile lengths.

#![no_main]

use ferrisftp::attrs::FileAttrs;
use ferrisftp::wire::{Reader, Writer};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Attributes, and their re-encoding must round-trip.
    let mut r = Reader::new(data);
    if let Ok(attrs) = FileAttrs::decode(&mut r) {
        let mut w = Writer::new(0);
        attrs.encode(&mut w);
        let packet = w.finish();
        let mut again = Reader::new(&packet[5..]);
        assert_eq!(FileAttrs::decode(&mut again).unwrap(), attrs);
        assert_eq!(again.remaining(), 0);
    }

    // A mixed sequence of primitives, steered by the input itself.
    let mut r = Reader::new(data);
    while let Ok(op) = r.u8() {
        let ok = match op % 4 {
            0 => r.u32().is_ok(),
            1 => r.u64().is_ok(),
            2 => r.string().is_ok(),
            _ => FileAttrs::decode(&mut r).is_ok(),
        };
        if !ok {
            break;
        }
    }
});
