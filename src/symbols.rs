//! Shared CodeView symbol records referenced by the DBI global/public indexes.

use std::io;

use derive_getters::Getters;

use crate::BufMsfStream;
use crate::codeview::PrefixedRecord;
use crate::codeview::symbols::SymbolRecord;
use crate::result::{Error, Result};

/// The shared symbol record stream identified by DBI's `sym_record_stream_index`.
///
/// This is distinct from the global and public hash-index streams. Records are
/// decoded into a vector in stream order; vector indices are not the byte
/// offsets stored in those indexes. Module-local symbols live in module streams.
#[derive(Debug, Getters)]
pub struct Symbols {
    records: Vec<SymbolRecord>,
}

impl Symbols {
    pub(crate) fn read<R: io::Read + io::Seek>(mut input: BufMsfStream<'_, R>) -> Result<Self> {
        let mut records: Vec<SymbolRecord> = vec![];
        let mut record_index = 0usize;
        loop {
            match PrefixedRecord::decode_or_terminator(&mut input) {
                Ok(Some(record)) => {
                    record_index += 1;
                    records.push(record.into_inner());
                }
                Ok(None) => break,
                Err(e) => {
                    return Err(Error::EncodingFailed(declio::Error::new(format!(
                        "global symbol stream: record #{record_index}: {e}"
                    ))));
                }
            }
        }
        Ok(Self { records })
    }
}
