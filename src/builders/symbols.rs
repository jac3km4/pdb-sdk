use std::collections::BTreeMap;
use std::io;

use declio::{Encode, EncodedSize};

use super::StreamAllocator;
use crate::codeview::symbols::{Public, SymbolRecord};
use crate::codeview::{PrefixedRecord, RECORD_ALIGNMENT};
use crate::msf::DefaultMsfStreamWriter;
use crate::publics::Publics;
use crate::result::Result;
use crate::symbol_map::Globals;
use crate::utils::align_to;
use crate::{StreamIndex, SymbolOffset};

#[derive(Debug)]
pub struct PublicsBuilder<'a> {
    pub(super) symbols: &'a mut SymbolsBuilder,
}

impl<'a> PublicsBuilder<'a> {
    pub fn add(&mut self, public: Public) -> SymbolOffset {
        let offset = SymbolOffset(self.symbols.offset);
        let size = u16::default_encoded_size(()) * 2 + public.encoded_size(());
        self.symbols.offset += align_to(size, RECORD_ALIGNMENT) as u32;
        self.symbols.publics.insert(offset, public);
        offset
    }

    pub fn finish_publics(self) -> &'a mut SymbolsBuilder {
        self.symbols
    }
}

#[derive(Debug, Default)]
pub struct SymbolsBuilder {
    pub publics: BTreeMap<SymbolOffset, Public>,
    pub globals: BTreeMap<SymbolOffset, SymbolRecord>,
    pub offset: u32,
}

impl SymbolsBuilder {
    pub fn add(&mut self, symbol: SymbolRecord) -> SymbolOffset {
        let offset = SymbolOffset(self.offset);
        let size = u16::default_encoded_size(()) + symbol.encoded_size(());
        self.offset += align_to(size, RECORD_ALIGNMENT) as u32;
        self.globals.insert(offset, symbol);
        offset
    }

    pub(super) fn commit<S>(
        self,
        sink: &mut S,
        allocator: &mut StreamAllocator,
    ) -> Result<SymbolStreams>
    where
        S: io::Write + io::Seek,
    {
        // Always create globals stream (even if empty) - most tools expect it
        let globals = {
            let mut globals_stream = DefaultMsfStreamWriter::new(sink)?;
            Globals::from_symbols(&self.globals).write_with_header(&mut globals_stream)?;
            allocator.allocate(globals_stream.finish()?)
        };

        // Always create publics stream (even if empty) - most tools expect it
        let publics = {
            let mut publics_stream = DefaultMsfStreamWriter::new(sink)?;
            Publics::from_publics(&self.publics).write_with_header(&mut publics_stream)?;
            allocator.allocate(publics_stream.finish()?)
        };

        // Always create symbol stream (even if empty)
        let symbols = {
            let mut syms_stream = DefaultMsfStreamWriter::new(sink)?;
            for (_, sym) in self.publics {
                PrefixedRecord(SymbolRecord::Public32(sym)).encode((), &mut syms_stream)?;
            }
            for (_, sym) in self.globals {
                PrefixedRecord(sym).encode((), &mut syms_stream)?;
            }
            allocator.allocate(syms_stream.finish()?)
        };

        Ok(SymbolStreams {
            publics,
            globals,
            symbols,
        })
    }
}

pub(super) struct SymbolStreams {
    pub(super) publics: StreamIndex,
    pub(super) globals: StreamIndex,
    pub(super) symbols: StreamIndex,
}
