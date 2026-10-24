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

/// Adds public records to the shared symbol-record stream and public index.
///
/// Add all publics before globals: commit emits publics first, then globals,
/// without recalculating stored offsets.
#[derive(Debug)]
pub struct PublicsBuilder<'a> {
    pub(super) symbols: &'a mut SymbolsBuilder,
}

impl<'a> PublicsBuilder<'a> {
    /// Adds a public and returns its length-prefix byte offset in the shared stream.
    ///
    /// Offsets start at zero and advance by the 4-byte-aligned record size.
    pub fn add(&mut self, public: Public) -> SymbolOffset {
        let offset = SymbolOffset(self.symbols.offset);
        let size = u16::default_encoded_size(()) * 2 + public.encoded_size(());
        self.symbols.offset += align_to(size, RECORD_ALIGNMENT) as u32;
        self.symbols.publics.insert(offset, public);
        offset
    }

    /// Releases the public-symbol view and returns the builder for global records.
    /// This does not write any streams.
    pub fn finish_publics(self) -> &'a mut SymbolsBuilder {
        self.symbols
    }
}

/// Builds the shared symbol-record stream and separate public/global indexes.
///
/// Public records are emitted before globals, each in offset-key order. Direct
/// edits must keep keys and `offset` consistent with that serialized layout;
/// commit does not insert gaps or repair offsets. Even empty indexes are emitted.
#[derive(Debug, Default)]
pub struct SymbolsBuilder {
    /// Public records keyed by shared-stream byte offset.
    pub publics: BTreeMap<SymbolOffset, Public>,
    /// Global records keyed by shared-stream byte offset.
    pub globals: BTreeMap<SymbolOffset, SymbolRecord>,
    /// Next shared-stream byte offset; zero for an empty builder.
    pub offset: u32,
}

impl SymbolsBuilder {
    /// Adds a global record and returns its length-prefix offset in the shared stream.
    ///
    /// Add all publics first. The offset advances by the 4-byte-aligned record size;
    /// this does not add a module-local symbol or validate record references.
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
        // Emit the global index even when empty.
        let globals = {
            let mut globals_stream = DefaultMsfStreamWriter::new(sink)?;
            Globals::from_symbols(&self.globals).write_with_header(&mut globals_stream)?;
            allocator.allocate(globals_stream.finish()?)
        };

        // Emit the public index even when empty.
        let publics = {
            let mut publics_stream = DefaultMsfStreamWriter::new(sink)?;
            Publics::from_publics(&self.publics).write_with_header(&mut publics_stream)?;
            allocator.allocate(publics_stream.finish()?)
        };

        // Emit publics before globals, without using keys to position records.
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
