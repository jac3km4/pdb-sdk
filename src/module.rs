//! Per-module symbols and CodeView C13 debug subsections.
//!
//! DBI supplies each module stream's index and region sizes. C11 line data and
//! global references remain raw bytes; only some C13 payloads are decoded.

use std::io::{self, Read, Write};

use declio::ctx::{Endian, Len};
use declio::util::Bytes;
use declio::{Decode, Encode, EncodedSize, magic_bytes};
use derive_getters::Getters;
use modular_bitfield::prelude::*;

use crate::codeview::symbols::SymbolRecord;
use crate::codeview::{DataRegionOffset, PrefixedRecord};
use crate::msf::MsfStreamWriter;
use crate::result::Result;
use crate::{codecs, constants, impl_bitfield_codecs, impl_bitfield_specifier_codecs};

magic_bytes! {
    #[derive(Debug)]
    DebugSectionSignature(&0x4u32.to_le_bytes());
}

/// Debug information for one compiland, such as an object file or linker module.
///
/// Contains decoded symbol records and C13 subsection entries, plus raw C11 and
/// global-reference bytes. C13 entries retain raw payloads until explicitly
/// decoded; this is not an address-to-source lookup interface.
#[derive(Debug, Getters)]
pub struct Module {
    symbols: Vec<SymbolRecord>,
    c11_bytes: Vec<u8>,
    c13_records: Vec<DebugSubsectionEntry>,
    global_ref_bytes: Vec<u8>,
}

impl Module {
    /// Creates a module from symbols and C13 entries, with no C11 or global references.
    pub fn new(symbols: Vec<SymbolRecord>, debug_entries: Vec<DebugSubsectionEntry>) -> Self {
        Self {
            symbols,
            c11_bytes: vec![],
            c13_records: debug_entries,
            global_ref_bytes: vec![],
        }
    }

    pub(crate) fn read<R>(mut source: R, layout: &ModuleLayout) -> Result<Self>
    where
        R: io::Read,
    {
        let mut symbol_stream = source.by_ref().take(u64::from(layout.sym_bytes));
        DebugSectionSignature::decode((), &mut symbol_stream)?;

        let mut symbols = vec![];
        let mut record_index = 0usize;
        while symbol_stream.limit() > 0 {
            let consumed = u64::from(layout.sym_bytes) - symbol_stream.limit();
            let (record, _) = PrefixedRecord::decode_with_size(&mut symbol_stream).map_err(|e| {
                crate::result::Error::EncodingFailed(declio::Error::new(format!(
                    "module symbol stream: record #{record_index} at byte offset {consumed}: {e}"
                )))
            })?;
            record_index += 1;
            symbols.push(record.into_inner());
        }

        let c11_bytes = codecs::read_bytes(&mut source, u64::from(layout.c11_bytes))?;

        let mut c13_records = vec![];
        let mut c13_stream = source.by_ref().take(layout.c13_bytes.into());
        while c13_stream.limit() > 0 {
            c13_records.push(DebugSubsectionEntry::decode((), &mut c13_stream)?);
        }

        let global_ref_bytes = codecs::prefixed_bytes::decode((), &mut source)?;

        let res = Self {
            symbols,
            c11_bytes,
            c13_records,
            global_ref_bytes,
        };
        Ok(res)
    }

    pub(crate) fn write<S, const N: u32>(
        self,
        sink: &mut MsfStreamWriter<'_, S, N>,
    ) -> Result<ModuleLayout>
    where
        S: io::Write + io::Seek,
    {
        DebugSectionSignature.encode((), sink)?;
        for symbol in self.symbols {
            PrefixedRecord(symbol).encode((), sink)?;
        }
        let sym_bytes = sink.position();
        sink.write_all(&self.c11_bytes)?;
        let start = sink.position();
        for rec in self.c13_records {
            rec.encode((), sink)?;
        }

        let c13_bytes = sink.position() - start;
        Bytes::<u32>::from(&self.global_ref_bytes).encode(constants::ENDIANESS, sink)?;

        let layout = ModuleLayout {
            sym_bytes,
            c11_bytes: self.c11_bytes.len() as u32,
            c13_bytes,
        };
        Ok(layout)
    }
}

/// The layout of a Module Information Stream.
#[derive(Debug, Encode, Decode, EncodedSize)]
#[declio(ctx_is = "constants::ENDIANESS")]
pub struct ModuleLayout {
    /// Symbol-region byte size, including the 4-byte CodeView signature.
    sym_bytes: u32,
    /// Size of C11 line info.
    c11_bytes: u32,
    /// Size of C13 line info.
    c13_bytes: u32,
}

/// A C13 subsection kind and its length-prefixed, four-byte-aligned payload.
#[derive(Debug)]
pub struct DebugSubsectionEntry {
    /// Type of the debug subsection.
    pub record_type: DebugSubsectionRecordType,
    /// Raw payload, excluding the kind/length fields. Decoded PDB payloads
    /// include alignment bytes because LLVM includes them in `Header.Length`.
    pub data: Vec<u8>,
}

impl Encode for DebugSubsectionEntry {
    fn encode<W: Write>(&self, (): (), writer: &mut W) -> std::result::Result<(), declio::Error> {
        let padding = (4 - self.data.len() % 4) % 4;
        let length = self
            .data
            .len()
            .checked_add(padding)
            .and_then(|n| u32::try_from(n).ok())
            .ok_or_else(|| declio::Error::new("C13 subsection size exceeds u32"))?;
        self.record_type.encode((), writer)?;
        length.encode(constants::ENDIANESS, writer)?;
        writer.write_all(&self.data)?;
        writer.write_all(&[0; 3][..padding])?;
        Ok(())
    }
}

impl Decode for DebugSubsectionEntry {
    fn decode<R: Read>((): (), reader: &mut R) -> std::result::Result<Self, declio::Error> {
        let record_type = DebugSubsectionRecordType::decode((), reader)?;
        let length = u32::decode(constants::ENDIANESS, reader)?;
        let mut data = Vec::new();
        reader.take(u64::from(length)).read_to_end(&mut data)?;
        if data.len() as u64 != u64::from(length) {
            return Err(declio::Error::new("truncated C13 subsection"));
        }
        // PDB lengths already include padding. Also consume external padding
        // when reading a subsection whose header declares an unaligned length.
        let padding = ((4 - length % 4) % 4) as usize;
        reader.read_exact(&mut [0; 3][..padding])?;
        Ok(Self { record_type, data })
    }
}

impl EncodedSize for DebugSubsectionEntry {
    fn encoded_size(&self, (): ()) -> usize {
        8 + crate::utils::align_to(self.data.len(), 4)
    }
}

impl DebugSubsectionEntry {
    /// Interprets the payload according to its subsection kind.
    ///
    /// Lines and checksums have structured representations; inlinee lines expose
    /// a signature and raw entries, and other supported kinds retain raw bytes.
    pub fn decoded(&self) -> Result<DebugSubsectionRecord> {
        let ctx = self.record_type;
        Ok(DebugSubsectionRecord::decode(ctx, &mut &self.data[..])?)
    }
}

/// The type of a Debug Subsection Record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Specifier)]
#[bits = 32]
pub enum DebugSubsectionRecordType {
    /// CodeView Symbol Records.
    Symbols = 0xf1,
    /// CodeView Line Information.
    Lines = 0xf2,
    /// String Table.
    StringTable = 0xf3,
    /// File Checksums.
    FileChecksums = 0xf4,
    /// Frame Data.
    FrameData = 0xf5,
    /// Inlinee Lines.
    InlineeLines = 0xf6,
    /// Cross Scope Imports.
    CrossScopeImports = 0xf7,
    /// Cross Scope Exports.
    CrossScopeExports = 0xf8,
    /// IL Lines.
    ILLines = 0xf9,
    /// Func MD Token Map.
    FuncMDTokenMap = 0xfa,
    /// Type MD Token Map.
    TypeMDTokenMap = 0xfb,
    /// Merged Assembly Input.
    MergedAssemblyInput = 0xfc,
    /// Coff Symbol RVA.
    CoffSymbolRVA = 0xfd,
}

impl_bitfield_specifier_codecs!(DebugSubsectionRecordType);

/// Decoded C13 payload, with raw bytes for kinds not structurally interpreted.
#[derive(Debug, Encode, Decode, EncodedSize)]
#[declio(
    ctx = "record_type: DebugSubsectionRecordType",
    id_expr = "record_type"
)]
pub enum DebugSubsectionRecord {
    #[declio(id = "DebugSubsectionRecordType::Lines")]
    Lines {
        header: LineFragmentHeader,
        #[declio(with = "line_blocks", ctx = "(header.flags, constants::ENDIANESS)")]
        entries: Vec<LineColumnEntry>,
    },
    #[declio(id = "DebugSubsectionRecordType::FileChecksums")]
    FileChecksums {
        #[declio(with = "codecs::padded_rem_list")]
        entries: Vec<FileChecksumEntry>,
    },
    #[declio(id = "DebugSubsectionRecordType::InlineeLines")]
    InlineeLines {
        #[declio(ctx = "constants::ENDIANESS")]
        signature: u32,
        #[declio(with = "codecs::rem_bytes")]
        entries: Vec<u8>,
    },
    #[declio(id = "DebugSubsectionRecordType::Symbols")]
    Symbols(#[declio(with = "codecs::rem_bytes")] Vec<u8>),
    #[declio(id = "DebugSubsectionRecordType::StringTable")]
    StringTable(#[declio(with = "codecs::rem_bytes")] Vec<u8>),
    #[declio(id = "DebugSubsectionRecordType::FrameData")]
    FrameData(#[declio(with = "codecs::rem_bytes")] Vec<u8>),
    #[declio(id = "DebugSubsectionRecordType::CrossScopeImports")]
    CrossScopeImports(#[declio(with = "codecs::rem_bytes")] Vec<u8>),
    #[declio(id = "DebugSubsectionRecordType::CrossScopeExports")]
    CrossScopeExports(#[declio(with = "codecs::rem_bytes")] Vec<u8>),
    #[declio(id = "DebugSubsectionRecordType::ILLines")]
    ILLines(#[declio(with = "codecs::rem_bytes")] Vec<u8>),
    #[declio(id = "DebugSubsectionRecordType::FuncMDTokenMap")]
    FuncMDTokenMap(#[declio(with = "codecs::rem_bytes")] Vec<u8>),
    #[declio(id = "DebugSubsectionRecordType::TypeMDTokenMap")]
    TypeMDTokenMap(#[declio(with = "codecs::rem_bytes")] Vec<u8>),
    #[declio(id = "DebugSubsectionRecordType::MergedAssemblyInput")]
    MergedAssemblyInput(#[declio(with = "codecs::rem_bytes")] Vec<u8>),
    #[declio(id = "DebugSubsectionRecordType::CoffSymbolRVA")]
    CoffSymbolRVA(#[declio(with = "codecs::rem_bytes")] Vec<u8>),
}

/// The header for a line fragment.
#[derive(Debug, Encode, Decode, EncodedSize)]
#[declio(ctx_is = "constants::ENDIANESS")]
pub struct LineFragmentHeader {
    /// Relocation offset for the code segment.
    pub reloc: DataRegionOffset,
    /// Flags indicating presence of columns.
    pub flags: LineFlags,
    /// Size of the code.
    pub code_size: u32,
}

/// An entry containing line and column number information.
#[derive(Debug)]
pub struct LineColumnEntry {
    /// Byte offset of the source file's entry in the file-checksums subsection.
    pub name_index: u32,
    /// Number of line entries.
    pub num_lines: u32,
    /// Original serialized block size. Encoding recomputes this from the arrays.
    pub code_size: u32,
    /// Array of line number entries.
    pub line_numbers: Vec<LineNumberEntry>,
    /// Array of column number entries (if flags specify columns are present).
    pub columns: Vec<ColumnNumberEntry>,
}

impl Encode<(LineFlags, Endian)> for LineColumnEntry {
    fn encode<W: Write>(
        &self,
        (flags, endian): (LineFlags, Endian),
        writer: &mut W,
    ) -> std::result::Result<(), declio::Error> {
        if self.line_numbers.len() != self.num_lines as usize
            || (flags.has_columns() && self.columns.len() != self.line_numbers.len())
            || (!flags.has_columns() && !self.columns.is_empty())
        {
            return Err(declio::Error::new("line block counts do not match arrays"));
        }
        let size = u32::try_from(self.encoded_size((flags, endian)))
            .map_err(|_| declio::Error::new("line block exceeds u32 size"))?;
        self.name_index.encode(endian, writer)?;
        self.num_lines.encode(endian, writer)?;
        size.encode(endian, writer)?;
        for line in &self.line_numbers {
            line.encode((), writer)?;
        }
        if flags.has_columns() {
            for column in &self.columns {
                column.encode((), writer)?;
            }
        }
        Ok(())
    }
}

impl EncodedSize<(LineFlags, Endian)> for LineColumnEntry {
    fn encoded_size(&self, (flags, _): (LineFlags, Endian)) -> usize {
        12 + self.line_numbers.len() * 8
            + if flags.has_columns() {
                self.columns.len() * 4
            } else {
                0
            }
    }
}

impl Decode<(LineFlags, Endian)> for LineColumnEntry {
    fn decode<R: Read>(
        (flags, endian): (LineFlags, Endian),
        reader: &mut R,
    ) -> std::result::Result<Self, declio::Error> {
        let name_index = u32::decode(endian, reader)?;
        let num_lines = u32::decode(endian, reader)?;
        let code_size = u32::decode(endian, reader)?;
        let payload_size = code_size
            .checked_sub(12)
            .ok_or_else(|| declio::Error::new("line block size is smaller than its header"))?;
        let line_info_size = u64::from(num_lines) * if flags.has_columns() { 12 } else { 8 };
        if line_info_size > u64::from(payload_size) {
            return Err(declio::Error::new("line arrays exceed line block size"));
        }

        let mut block = reader.take(u64::from(payload_size));
        let mut line_numbers = Vec::new();
        for _ in 0..num_lines {
            line_numbers.push(LineNumberEntry::decode((), &mut block)?);
        }
        let mut columns = Vec::new();
        if flags.has_columns() {
            for _ in 0..num_lines {
                columns.push(ColumnNumberEntry::decode((), &mut block)?);
            }
        }
        // LLVM advances by BlockSize, not just by the decoded array sizes.
        let remaining = block.limit();
        if io::copy(&mut block, &mut io::sink())? != remaining {
            return Err(declio::Error::new("truncated line block"));
        }
        Ok(Self {
            name_index,
            num_lines,
            code_size,
            line_numbers,
            columns,
        })
    }
}

mod line_blocks {
    use super::*;

    pub fn decode<R: Read>(
        ctx: (LineFlags, Endian),
        reader: &mut R,
    ) -> std::result::Result<Vec<LineColumnEntry>, declio::Error> {
        let mut bytes = Vec::new();
        reader.read_to_end(&mut bytes)?;
        let mut remaining = bytes.as_slice();
        let mut entries = Vec::new();
        while !remaining.is_empty() {
            entries.push(LineColumnEntry::decode(ctx, &mut remaining)?);
        }
        Ok(entries)
    }

    pub fn encode<W: Write>(
        entries: &[LineColumnEntry],
        ctx: (LineFlags, Endian),
        writer: &mut W,
    ) -> std::result::Result<(), declio::Error> {
        for entry in entries {
            entry.encode(ctx, writer)?;
        }
        Ok(())
    }

    pub fn encoded_size(entries: &[LineColumnEntry], ctx: (LineFlags, Endian)) -> usize {
        entries.iter().map(|entry| entry.encoded_size(ctx)).sum()
    }
}

/// Flags for line number entries.
#[bitfield(bits = 16)]
#[derive(Debug, Clone, Copy)]
pub struct LineFlags {
    pub has_columns: bool,
    #[skip]
    padding: B15,
}

impl_bitfield_codecs!(LineFlags);

/// A line number entry.
#[derive(Debug, Encode, Decode, EncodedSize)]
#[declio(ctx_is = "constants::ENDIANESS")]
pub struct LineNumberEntry {
    /// Instruction byte offset relative to the line fragment's code start.
    pub offset: u32,
    /// Packed start line (bits 0..23), end-line delta (24..30), and statement bit (31).
    pub flags: u32,
}

/// A column number entry.
#[derive(Debug, Encode, Decode, EncodedSize)]
#[declio(ctx_is = "constants::ENDIANESS")]
pub struct ColumnNumberEntry {
    /// Starting column number.
    pub start_col: u16,
    /// Ending column number.
    pub end_col: u16,
}

/// An entry in the file checksums subsection.
#[derive(Debug, Encode, Decode, EncodedSize)]
#[declio(ctx_is = "constants::ENDIANESS")]
pub struct FileChecksumEntry {
    /// Byte offset of the file name in the associated CodeView string table.
    pub file_name_offset: u32,
    /// Size of the checksum.
    pub checksum_size: u8,
    /// The hashing algorithm used for the checksum.
    pub checksum_type: ChecksumType,
    #[declio(ctx = "Len(usize::from(*checksum_size))", via = "Bytes<'_>")]
    pub bytes: Vec<u8>,
}

/// The type of checksum used for a file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Specifier)]
#[bits = 8]
pub enum ChecksumType {
    /// No checksum.
    None,
    /// MD5 hash.
    Md5,
    /// SHA-1 hash.
    Sha1,
    /// SHA-256 hash.
    Sha256,
}

impl_bitfield_specifier_codecs!(ChecksumType);

#[cfg(test)]
mod tests {
    use std::io::{Cursor, Seek};

    use super::*;
    use crate::msf::{DEFAULT_BLOCK_SIZE, DefaultMsfStreamWriter, MsfStream};

    #[test]
    fn module_symbol_region_includes_signature_and_preserves_following_regions() {
        // Signature, S_END, C11, C13 inlinee lines, global references, sentinel.
        let bytes = [
            4, 0, 0, 0, 2, 0, 6, 0, 0xaa, 0xbb, 0xf6, 0, 0, 0, 4, 0, 0, 0, 1, 0, 0, 0, 3, 0, 0, 0,
            7, 8, 9, 0xcc,
        ];
        let layout = ModuleLayout {
            sym_bytes: 8,
            c11_bytes: 2,
            c13_bytes: 12,
        };
        let mut reader = Cursor::new(bytes);
        let module = Module::read(&mut reader, &layout).unwrap();
        assert!(matches!(
            module.symbols.as_slice(),
            [SymbolRecord::ScopeEnd]
        ));
        assert_eq!(module.c11_bytes, [0xaa, 0xbb]);
        assert_eq!(module.c13_records.len(), 1);
        assert_eq!(module.c13_records[0].data, [1, 0, 0, 0]);
        assert_eq!(module.global_ref_bytes, [7, 8, 9]);
        assert_eq!(reader.position(), 29);
        assert_eq!(u8::decode((), &mut reader).unwrap(), 0xcc);
    }

    #[test]
    fn module_symbols_cannot_read_past_declared_region() {
        let bytes = [4, 0, 0, 0, 2, 0, 6, 0, 0xaa, 0xbb, 0xcc, 0xdd];
        // A short signature, partial prefix or partial body must not borrow
        // bytes from C11/C13/global references to complete the symbol region.
        for sym_bytes in [0, 1, 2, 3, 5, 6, 7] {
            let mut reader = Cursor::new(bytes);
            let layout = ModuleLayout {
                sym_bytes,
                c11_bytes: 0,
                c13_bytes: 0,
            };
            assert!(Module::read(&mut reader, &layout).is_err(), "{sym_bytes}");
            assert_eq!(reader.position(), u64::from(sym_bytes));
            assert_eq!(
                u8::decode((), &mut reader).unwrap(),
                bytes[sym_bytes as usize]
            );
        }
    }

    #[test]
    fn module_symbols_reject_undersized_and_truncated_records() {
        for tail in [&[0][..], &[0, 0], &[1, 0], &[2, 0, 6]] {
            let mut bytes = vec![4, 0, 0, 0, 2, 0, 6, 0];
            bytes.extend_from_slice(tail);
            let end = bytes.len();
            bytes.extend_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd]);
            let mut reader = Cursor::new(bytes);
            let layout = ModuleLayout {
                sym_bytes: end as u32,
                c11_bytes: 0,
                c13_bytes: 0,
            };
            assert!(Module::read(&mut reader, &layout).is_err());
            assert_eq!(reader.position() as usize, end);
            assert_eq!(u8::decode((), &mut reader).unwrap(), 0xaa);
        }
        // Physical EOF before the declared end is not a successful short read.
        for end in 0..8 {
            let bytes = [4, 0, 0, 0, 2, 0, 6, 0];
            let mut reader = Cursor::new(&bytes[..end]);
            let layout = ModuleLayout {
                sym_bytes: 8,
                c11_bytes: 0,
                c13_bytes: 0,
            };
            assert!(Module::read(&mut reader, &layout).is_err());
            assert_eq!(reader.position() as usize, end);
        }
    }

    fn line_block_bytes(words: &[u32]) -> Vec<u8> {
        words.iter().flat_map(|word| word.to_le_bytes()).collect()
    }

    #[test]
    fn c13_line_blocks_advance_by_block_size_without_extra_alignment() {
        for has_columns in [false, true] {
            let flags = LineFlags::new().with_has_columns(has_columns);
            // Two line entries are followed by two column entries, not interleaved.
            let mut first = line_block_bytes(&[0x10, 2, 0, 3, 0x8000_002a, 7, 0x0100_002b]);
            if has_columns {
                first.extend_from_slice(&[1, 0, 5, 0, 2, 0, 9, 0]);
            }
            // LLVM permits extra bytes within BlockSize, even an unaligned size.
            first.extend_from_slice(&[0xaa, 0xbb, 0xcc]);
            let first_size = first.len() as u32;
            first[8..12].copy_from_slice(&first_size.to_le_bytes());
            let mut bytes = first;
            bytes.extend_from_slice(&line_block_bytes(&[
                0x20,
                1,
                if has_columns { 24 } else { 20 },
                11,
                99,
            ]));
            if has_columns {
                bytes.extend_from_slice(&[4, 0, 8, 0]);
            }
            let end = bytes.len();
            bytes.push(0xee);
            let mut reader = Cursor::new(&bytes);
            let first =
                LineColumnEntry::decode((flags, constants::ENDIANESS), &mut reader).unwrap();
            assert_eq!(reader.position(), u64::from(first_size));
            assert_eq!(
                (first.name_index, first.num_lines, first.code_size),
                (0x10, 2, first_size)
            );
            assert_eq!(first.line_numbers[0].offset, 3);
            assert_eq!(first.line_numbers[0].flags, 0x8000_002a);
            assert_eq!(first.line_numbers[1].offset, 7);
            assert_eq!(first.line_numbers[1].flags, 0x0100_002b);
            if has_columns {
                assert_eq!(
                    (first.columns[0].start_col, first.columns[0].end_col),
                    (1, 5)
                );
                assert_eq!(
                    (first.columns[1].start_col, first.columns[1].end_col),
                    (2, 9)
                );
            } else {
                assert!(first.columns.is_empty());
            }
            let next = LineColumnEntry::decode((flags, constants::ENDIANESS), &mut reader).unwrap();
            assert_eq!(next.name_index, 0x20);
            assert_eq!(next.line_numbers[0].offset, 11);
            assert_eq!(next.line_numbers[0].flags, 99);
            assert_eq!(reader.position() as usize, end);
            assert_eq!(u8::decode((), &mut reader).unwrap(), 0xee);

            let ctx = (flags, constants::ENDIANESS);
            let mut encoded = Vec::new();
            first.encode(ctx, &mut encoded).unwrap();
            next.encode(ctx, &mut encoded).unwrap();
            assert_eq!(
                encoded.len(),
                first.encoded_size(ctx) + next.encoded_size(ctx)
            );
            let mut roundtrip = Cursor::new(&encoded);
            let first_again = LineColumnEntry::decode(ctx, &mut roundtrip).unwrap();
            assert_eq!(first_again.code_size as usize, first.encoded_size(ctx));
            assert_eq!(first_again.line_numbers[1].offset, 7);
            assert_eq!(roundtrip.position() as usize, first.encoded_size(ctx));
            let next_again = LineColumnEntry::decode(ctx, &mut roundtrip).unwrap();
            assert_eq!(next_again.name_index, 0x20);
            assert_eq!(next_again.line_numbers[0].flags, 99);
            if has_columns {
                assert_eq!(next_again.columns[0].end_col, 8);
            }
            assert_eq!(roundtrip.position() as usize, encoded.len());

            // Exercise the subsection's list decoder as well as individual blocks.
            let mut payload =
                line_block_bytes(&[0, if has_columns { 0x0001_0001 } else { 1 }, 100]);
            payload.extend_from_slice(&bytes[..end]);
            let mut reader = Cursor::new(payload);
            let DebugSubsectionRecord::Lines { entries, .. } =
                DebugSubsectionRecord::decode(DebugSubsectionRecordType::Lines, &mut reader)
                    .unwrap()
            else {
                panic!("expected lines");
            };
            assert_eq!(entries.len(), 2);
            assert_eq!(entries[1].name_index, 0x20);
            assert_eq!(reader.position() as usize, 12 + end);
        }
    }

    #[test]
    fn c13_line_block_encoder_rejects_inconsistent_counts() {
        let mut entry = LineColumnEntry {
            name_index: 0,
            num_lines: 1,
            code_size: 0,
            line_numbers: vec![],
            columns: vec![],
        };
        let mut bytes = Vec::new();
        let flags = LineFlags::new();
        assert!(
            entry
                .encode((flags, constants::ENDIANESS), &mut bytes)
                .is_err()
        );
        entry.line_numbers.push(LineNumberEntry {
            offset: 0,
            flags: 1,
        });
        assert!(
            entry
                .encode(
                    (flags.with_has_columns(true), constants::ENDIANESS),
                    &mut bytes
                )
                .is_err()
        );
        assert!(bytes.is_empty());
    }

    #[test]
    fn c13_line_blocks_validate_sizes_before_reading_arrays() {
        for has_columns in [false, true] {
            let flags = LineFlags::new().with_has_columns(has_columns);
            for (num_lines, block_size) in [
                (0, 0),
                (0, 11),
                (1, 12),
                (1, 19),
                (u32::MAX, u32::MAX),
                (0x2000_0000, 12),
            ] {
                let mut bytes = line_block_bytes(&[0, num_lines, block_size]);
                bytes.extend_from_slice(&[0xaa; 32]);
                let mut reader = Cursor::new(bytes);
                assert!(
                    LineColumnEntry::decode((flags, constants::ENDIANESS), &mut reader).is_err()
                );
                assert_eq!(reader.position(), 12);
                assert_eq!(u8::decode((), &mut reader).unwrap(), 0xaa);
            }
        }
        // Enough room for lines alone is insufficient when columns are present.
        let mut reader = Cursor::new(line_block_bytes(&[0, 1, 20, 7, 42, 0x0005_0001]));
        assert!(
            LineColumnEntry::decode(
                (
                    LineFlags::new().with_has_columns(true),
                    constants::ENDIANESS
                ),
                &mut reader,
            )
            .is_err()
        );
        assert_eq!(reader.position(), 12);
    }

    #[test]
    fn c13_line_blocks_reject_truncated_headers_arrays_and_extra_bytes() {
        for has_columns in [false, true] {
            let flags = LineFlags::new().with_has_columns(has_columns);
            let mut bytes = line_block_bytes(&[0, 1, if has_columns { 28 } else { 24 }, 7, 42]);
            if has_columns {
                bytes.extend_from_slice(&[1, 0, 5, 0]);
            }
            bytes.extend_from_slice(&[0xaa; 4]);
            for end in 0..bytes.len() {
                let mut reader = Cursor::new(&bytes[..end]);
                assert!(
                    LineColumnEntry::decode((flags, constants::ENDIANESS), &mut reader).is_err()
                );
                assert_eq!(reader.position() as usize, end);
            }
            // An empty block is valid, and must not swallow the next block.
            let mut reader = Cursor::new(line_block_bytes(&[0x10, 0, 12, 0x20, 0, 12]));
            let entries = line_blocks::decode((flags, constants::ENDIANESS), &mut reader).unwrap();
            assert_eq!(entries.len(), 2);
            assert_eq!(entries[1].name_index, 0x20);
            assert_eq!(reader.position(), 24);
        }
    }

    #[test]
    fn c13_encoding_sizes_lengths_and_positions() {
        for len in [0, 1, 2, 3, 4, 5, 4095, 4096, 4097] {
            let entry = DebugSubsectionEntry {
                record_type: DebugSubsectionRecordType::StringTable,
                data: vec![b'x'; len],
            };
            let mut bytes = Vec::new();
            entry.encode((), &mut bytes).unwrap();
            assert_eq!(entry.encoded_size(()), bytes.len());
            assert_eq!(bytes.len(), 8 + crate::utils::align_to(len, 4));
            assert_eq!(
                u32::from_le_bytes(bytes[4..8].try_into().unwrap()) as usize,
                bytes.len() - 8
            );
            assert_eq!(&bytes[8..8 + len], entry.data);
            assert!(bytes[8 + len..].iter().all(|&b| b == 0));
            let end = bytes.len();
            bytes.extend_from_slice(&[0xf6, 0, 0, 0, 4, 0, 0, 0, 1, 0, 0, 0]);
            let mut reader = Cursor::new(bytes);
            let decoded = DebugSubsectionEntry::decode((), &mut reader).unwrap();
            assert_eq!(reader.position() as usize, end);
            assert_eq!(decoded.record_type, entry.record_type);
            assert_eq!(&decoded.data[..len], entry.data);
            let mut reencoded = Vec::new();
            decoded.encode((), &mut reencoded).unwrap();
            assert_eq!(reencoded, reader.get_ref()[..end]);
            let next = DebugSubsectionEntry::decode((), &mut reader).unwrap();
            assert_eq!(next.record_type, DebugSubsectionRecordType::InlineeLines);
            assert!(
                matches!(next.decoded().unwrap(), DebugSubsectionRecord::InlineeLines { signature: 1, entries } if entries.is_empty())
            );
            assert_eq!(reader.position() as usize, end + 12);
        }
    }

    #[test]
    fn c13_reads_llvm_pdb_lengths_without_double_padding() {
        // LLVM's PDB builder writes aligned Header.Length, including the NUL
        // and padding of the string table. The next header follows immediately.
        let bytes = [
            0xf3, 0, 0, 0, 4, 0, 0, 0, 0, b'a', 0, 0, 0xf6, 0, 0, 0, 4, 0, 0, 0, 1, 0, 0, 0,
        ];
        let mut reader = Cursor::new(bytes);
        let strings = DebugSubsectionEntry::decode((), &mut reader).unwrap();
        assert_eq!(strings.data, [0, b'a', 0, 0]);
        assert_eq!(reader.position(), 12);
        let inlinee = DebugSubsectionEntry::decode((), &mut reader).unwrap();
        assert_eq!(inlinee.data, [1, 0, 0, 0]);
        assert_eq!(reader.position(), 24);
        // Also accept an unaligned length with external alignment bytes.
        let mut reader = Cursor::new([0xf3, 0, 0, 0, 1, 0, 0, 0, b'x', 0, 0, 0]);
        assert_eq!(
            DebugSubsectionEntry::decode((), &mut reader).unwrap().data,
            [b'x']
        );
        assert_eq!(reader.position(), 12);
        for end in 0..12 {
            assert!(DebugSubsectionEntry::decode((), &mut &bytes[..end]).is_err());
        }
    }

    #[test]
    fn llvm_fixture_c13_checksums_and_line_values() {
        let mut pdb = crate::PdbFile::open(Cursor::new(
            include_bytes!("../tests/corpus/clang-lld-x64.pdb").as_slice(),
        ))
        .unwrap();
        let dbi = pdb.get_dbi().unwrap();
        let module = pdb.get_module(&dbi.modules()[0]).unwrap();
        let mut line_fragments = Vec::new();
        let mut checksums = 0;
        for entry in &module.c13_records {
            match entry.decoded().unwrap() {
                DebugSubsectionRecord::FileChecksums { entries } => {
                    assert_eq!(entries.len(), 1);
                    assert_eq!(entries[0].checksum_type, ChecksumType::Md5);
                    assert_eq!(
                        entries[0].bytes,
                        [
                            0x05, 0xae, 0x82, 0xea, 0xc7, 0x16, 0x20, 0x47, 0x59, 0x37, 0x84, 0xa2,
                            0xe1, 0x5f, 0xff, 0x74,
                        ]
                    );
                    checksums += 1;
                }
                DebugSubsectionRecord::Lines { header, entries } => {
                    assert_eq!(header.reloc.segment, 1);
                    let lines: Vec<_> = entries
                        .iter()
                        .flat_map(|e| &e.line_numbers)
                        .map(|line| (line.offset, line.flags & 0x00ff_ffff))
                        .collect();
                    line_fragments.push((header.reloc.offset, header.code_size, lines));
                }
                _ => {}
            }
        }
        assert_eq!(checksums, 1);
        assert_eq!(
            line_fragments,
            [
                (0, 0x36, vec![(0, 16), (0x0d, 17), (0x1d, 18)]),
                (0x40, 0x20, vec![(0, 21), (4, 22), (0x1b, 23)]),
            ]
        );
    }

    #[test]
    fn module_c13_layout_preserves_following_global_references() {
        let mut module = Module::new(
            vec![],
            vec![
                DebugSubsectionEntry {
                    record_type: DebugSubsectionRecordType::StringTable,
                    data: b"\0a\0".to_vec(),
                },
                DebugSubsectionEntry {
                    record_type: DebugSubsectionRecordType::InlineeLines,
                    data: 1u32.to_le_bytes().to_vec(),
                },
            ],
        );
        module.global_ref_bytes = vec![7, 8, 9];
        let mut sink = Cursor::new(Vec::new());
        let mut writer = DefaultMsfStreamWriter::new(&mut sink).unwrap();
        let layout = module.write(&mut writer).unwrap();
        assert_eq!(
            (layout.sym_bytes, layout.c11_bytes, layout.c13_bytes),
            (4, 0, 24)
        );
        assert_eq!(writer.position(), 35);
        let stream_layout = writer.finish().unwrap();
        let mut reader = MsfStream::new(&mut sink, &stream_layout, DEFAULT_BLOCK_SIZE);
        let decoded = Module::read(&mut reader, &layout).unwrap();
        assert_eq!(decoded.c13_records.len(), 2);
        assert_eq!(decoded.c13_records[0].data, b"\0a\0\0");
        assert_eq!(decoded.c13_records[1].data, 1u32.to_le_bytes());
        assert_eq!(decoded.global_ref_bytes, [7, 8, 9]);
        assert_eq!(reader.stream_position().unwrap(), 35);
    }
}
