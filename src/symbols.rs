use std::io::{self, Read};

use derive_getters::Getters;

use crate::BufMsfStream;
use crate::codeview::PrefixedRecord;
use crate::codeview::symbols::SymbolRecord;
use crate::result::Result;

#[derive(Debug, Getters)]
pub struct Symbols {
    records: Vec<SymbolRecord>,
}

impl Symbols {
    pub(crate) fn read<R: io::Read + io::Seek>(mut input: BufMsfStream<'_, R>) -> Result<Self> {
        let mut records: Vec<SymbolRecord> = vec![];
        let len = input.get_ref().length();
        let mut sym_stream = input.by_ref().take(len.into());
        while sym_stream.limit() > 0 {
            records.push(PrefixedRecord::decode(&mut sym_stream)?.into_inner());
        }
        Ok(Self { records })
    }
}
