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
/// Publics and globals may be added in any order; returned offsets remain stable.
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
/// Records are emitted in combined offset-key order, preserving insertion order
/// and returned offsets when using `add`. Direct edits must keep keys contiguous
/// and `offset` equal to the total aligned size; commit rejects inconsistent
/// layouts rather than inserting gaps or repairing offsets. Empty indexes are emitted.
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
    /// Publics and globals may be interleaved. The offset advances by the
    /// 4-byte-aligned record size; this does not add a module-local symbol or
    /// validate record references.
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
        // Merge by the offsets assigned at insertion, not by symbol kind.
        let mut records = self.globals;
        if self
            .publics
            .keys()
            .any(|offset| records.contains_key(offset))
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "public and global records share a symbol offset",
            )
            .into());
        }
        let mut expected = 0u32;
        let mut sizes: Vec<_> = records
            .iter()
            .map(|(offset, symbol)| {
                (
                    *offset,
                    u16::default_encoded_size(()) + symbol.encoded_size(()),
                )
            })
            .chain(self.publics.iter().map(|(offset, public)| {
                (
                    *offset,
                    u16::default_encoded_size(()) * 2 + public.encoded_size(()),
                )
            }))
            .collect();
        sizes.sort_by_key(|(offset, _)| *offset);
        for (offset, size) in sizes {
            if offset.0 != expected {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "symbol offsets must describe contiguous aligned records",
                )
                .into());
            }
            if size > usize::from(u16::MAX) + 2
                || align_to(size, RECORD_ALIGNMENT) - 2 > usize::from(u16::MAX)
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "symbol record exceeds u16 length prefix",
                )
                .into());
            }
            let size = u32::try_from(align_to(size, RECORD_ALIGNMENT)).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "symbol record size exceeds u32",
                )
            })?;
            expected = expected.checked_add(size).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "symbol stream size exceeds u32",
                )
            })?;
        }
        if expected != self.offset {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "next symbol offset does not match the symbol stream size",
            )
            .into());
        }

        // Emit the global index even when empty.
        let globals = {
            let mut globals_stream = DefaultMsfStreamWriter::new(sink)?;
            Globals::from_symbols(&records).write_with_header(&mut globals_stream)?;
            allocator.allocate(globals_stream.finish()?)
        };

        // Emit the public index even when empty.
        let publics = {
            let mut publics_stream = DefaultMsfStreamWriter::new(sink)?;
            Publics::from_publics(&self.publics).write_with_header(&mut publics_stream)?;
            allocator.allocate(publics_stream.finish()?)
        };

        // PDB indexes refer to byte offsets; publics need not precede globals.
        for (offset, public) in self.publics {
            records.insert(offset, SymbolRecord::Public32(public));
        }
        let symbols = {
            let mut syms_stream = DefaultMsfStreamWriter::new(sink)?;
            for (_, sym) in records {
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

#[cfg(test)]
mod tests {
    use std::io::{Cursor, Read};

    use super::*;
    use crate::codeview::DataRegionOffset;
    use crate::codeview::symbols::{Data, PublicProperties};
    use crate::msf::{DEFAULT_BLOCK_SIZE, MsfStream};
    use crate::symbol_map::SymbolMap;

    fn public(name: &str, segment: u16, offset: u32) -> Public {
        Public {
            properties: PublicProperties::new(),
            offset: DataRegionOffset::new(offset, segment),
            name: name.into(),
        }
    }

    fn global(name: &str) -> SymbolRecord {
        SymbolRecord::GlobalData(Data {
            data_type: None,
            offset: DataRegionOffset::new(0, 1),
            name: name.into(),
        })
    }

    fn stream_bytes(
        sink: &mut Cursor<Vec<u8>>,
        allocator: &StreamAllocator,
        index: StreamIndex,
    ) -> Vec<u8> {
        let mut bytes = Vec::new();
        MsfStream::new(
            sink,
            &allocator.streams[index.0 as usize],
            DEFAULT_BLOCK_SIZE,
        )
        .read_to_end(&mut bytes)
        .unwrap();
        bytes
    }

    fn indexed_offsets(map: &SymbolMap) -> Vec<SymbolOffset> {
        let mut bytes = Vec::new();
        map.write_with_header(&mut bytes).unwrap();
        let size = u32::from_le_bytes(bytes[8..12].try_into().unwrap()) as usize;
        let mut offsets: Vec<_> = bytes[16..16 + size]
            .as_chunks::<8>()
            .0
            .iter()
            .map(|record| {
                let offset = u32::from_le_bytes(record[..4].try_into().unwrap());
                assert_ne!(offset, 0);
                SymbolOffset(offset - 1)
            })
            .collect();
        offsets.sort_unstable();
        offsets
    }

    #[test]
    fn interleaved_records_preserve_offsets_and_indexes() {
        let mut builder = SymbolsBuilder::default();
        let first = builder.add(global("global_first"));
        let second = PublicsBuilder {
            symbols: &mut builder,
        }
        .add(public("public_second", 2, 0));
        let third = builder.add(global("global_third"));
        let fourth = PublicsBuilder {
            symbols: &mut builder,
        }
        .add(public("public_fourth", 1, 100));
        let fifth = PublicsBuilder {
            symbols: &mut builder,
        }
        .add(public("public_fifth", 1, 10));
        let sixth = builder.add(global("global_sixth"));
        let total = builder.offset;
        let mut sink = Cursor::new(vec![0; 3 * DEFAULT_BLOCK_SIZE as usize]);
        sink.set_position(3 * u64::from(DEFAULT_BLOCK_SIZE));
        let mut allocator = StreamAllocator::default();
        let streams = builder.commit(&mut sink, &mut allocator).unwrap();
        let bytes = stream_bytes(&mut sink, &allocator, streams.symbols);
        assert_eq!(bytes.len(), total as usize);
        let mut cursor = Cursor::new(&bytes);
        for (offset, name) in [
            (first, "global_first"),
            (second, "public_second"),
            (third, "global_third"),
            (fourth, "public_fourth"),
            (fifth, "public_fifth"),
            (sixth, "global_sixth"),
        ] {
            assert_eq!(cursor.position(), u64::from(offset.0));
            let (record, consumed) =
                PrefixedRecord::<SymbolRecord>::decode_with_size(&mut cursor).unwrap();
            assert_eq!(record.0.name(), Some(name));
            assert_eq!(cursor.position(), u64::from(offset.0) + consumed);
        }
        assert_eq!(cursor.position(), u64::from(total));
        let globals = stream_bytes(&mut sink, &allocator, streams.globals);
        let globals = Globals::read_with_header(&globals[..]).unwrap();
        assert_eq!(indexed_offsets(&globals), [first, third, sixth]);
        let publics = stream_bytes(&mut sink, &allocator, streams.publics);
        let publics = Publics::read_with_header(&publics[..]).unwrap();
        assert_eq!(indexed_offsets(publics.map()), [second, fourth, fifth]);
        assert_eq!(publics.address_map(), &[fifth, fourth, second]);
        for offset in publics.address_map() {
            cursor.set_position(u64::from(offset.0));
            let (record, _) =
                PrefixedRecord::<SymbolRecord>::decode_with_size(&mut cursor).unwrap();
            assert!(record.0.name().unwrap().starts_with("public_"));
        }
    }

    #[test]
    fn inconsistent_manual_maps_are_rejected_before_writing() {
        for case in 0..4 {
            let mut builder = SymbolsBuilder::default();
            builder.add(SymbolRecord::Public32(public("global", 1, 0)));
            match case {
                0 => {
                    builder
                        .publics
                        .insert(SymbolOffset(0), public("duplicate", 1, 0));
                }
                1 => {
                    let symbol = builder.globals.remove(&SymbolOffset(0)).unwrap();
                    builder.globals.insert(SymbolOffset(4), symbol);
                }
                2 => {
                    builder.offset += 4;
                }
                _ => {
                    builder.globals.insert(
                        SymbolOffset(builder.offset - 4),
                        SymbolRecord::Public32(public("overlap", 1, 0)),
                    );
                }
            }
            let mut sink = Cursor::new(Vec::new());
            assert!(
                builder
                    .commit(&mut sink, &mut StreamAllocator::default())
                    .is_err()
            );
            assert!(sink.into_inner().is_empty());
        }
    }
}
