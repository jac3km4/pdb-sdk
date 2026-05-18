use std::io;

use derive_getters::Getters;

use crate::BufMsfStream;
use crate::codeview::PrefixedRecord;
use crate::codeview::symbols::SymbolRecord;
use crate::result::{Error, Result};

/// Represents the Global Symbol Stream (often referred to as the "symbol record stream").
/// It contains a flat list of `SymbolRecord`s which encompass global symbols (e.g. Data, Procedure, Public).
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
