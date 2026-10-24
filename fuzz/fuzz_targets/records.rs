#![no_main]

use declio::Decode;
use libfuzzer_sys::fuzz_target;
use pdb_sdk::codeview::symbols::SymbolRecord;
use pdb_sdk::codeview::types::{IdRecord, TypeRecord};

const MAX_INPUT_BYTES: usize = 64 * 1024;

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_BYTES {
        return;
    }

    // Each decoder sees the same bytes, including its own little-endian kind.
    // No stream length prefix or selector byte is consumed by this harness.
    let _ = TypeRecord::decode((), &mut &data[..]);
    let _ = IdRecord::decode((), &mut &data[..]);
    let _ = SymbolRecord::decode((), &mut &data[..]);
});
