use std::io::{self, Read, Write};

use declio::ctx::{Endian, Len};
use declio::util::Bytes;
use declio::{magic_bytes, Decode, Encode, EncodedSize};
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

/// The Module Information Stream.
/// Contains information about a single module (object file, import library, etc) that contributes to the binary. Includes line info and CodeView information for symbols.
#[derive(Debug, Getters)]
pub struct Module {
    symbols: Vec<SymbolRecord>,
    c11_bytes: Vec<u8>,
    c13_records: Vec<DebugSubsectionEntry>,
    global_ref_bytes: Vec<u8>,
}

impl Module {
    /// Creates a new Module.
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
        let mut sym_stream = source.by_ref().take(layout.sym_bytes.into());
        DebugSectionSignature::decode((), &mut sym_stream)?;

        let mut symbols = vec![];
        while sym_stream.limit() > 0 {
            symbols.push(PrefixedRecord::decode(&mut sym_stream)?.into_inner());
        }

        let c11_bytes =
            <Bytes<'_>>::decode(Len(layout.c11_bytes as usize), &mut source)?.into_vec();

        let mut c13_records = vec![];
        let mut c13_stream = source.by_ref().take(layout.c13_bytes.into());
        while c13_stream.limit() > 0 {
            c13_records.push(DebugSubsectionEntry::decode((), &mut c13_stream)?);
        }

        let global_ref_bytes =
            <Bytes<'_, u32>>::decode(constants::ENDIANESS, &mut source)?.into_vec();

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
    /// Size of symbols.
    sym_bytes: u32,
    /// Size of C11 line info.
    c11_bytes: u32,
    /// Size of C13 line info.
    c13_bytes: u32,
}

/// An entry in a Debug Subsection.
#[derive(Debug, Encode, Decode, EncodedSize)]
#[declio(ctx_is = "constants::ENDIANESS")]
pub struct DebugSubsectionEntry {
    /// Type of the debug subsection.
    pub record_type: DebugSubsectionRecordType,
    #[declio(via = "Bytes<'_, u32>")]
    pub data: Vec<u8>,
}

impl DebugSubsectionEntry {
    /// Decodes the Debug Subsection Entry into a DebugSubsectionRecord.
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

/// A Debug Subsection Record.
#[derive(Debug, Encode, Decode, EncodedSize)]
#[declio(
    ctx = "record_type: DebugSubsectionRecordType",
    id_expr = "record_type"
)]
pub enum DebugSubsectionRecord {
    #[declio(id = "DebugSubsectionRecordType::Lines")]
    Lines {
        header: LineFragmentHeader,
        #[declio(
            with = "codecs::padded_rem_list",
            ctx = "(header.flags, constants::ENDIANESS)"
        )]
        entries: Vec<LineColumnEntry>,
    },
    #[declio(id = "DebugSubsectionRecordType::FileChecksums")]
    FileChecksums {
        #[declio(with = "codecs::padded_rem_list")]
        entries: Vec<FileChecksumEntry>,
    },
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
#[derive(Debug, Encode, Decode, EncodedSize)]
#[declio(ctx = "flags: LineFlags, endian: Endian")]
pub struct LineColumnEntry {
    /// Index of the source file name in the string table.
    pub name_index: u32,
    /// Number of line entries.
    pub num_lines: u32,
    /// Size of the code segment.
    pub code_size: u32,
    /// Array of line number entries.
    #[declio(ctx = "Len(*num_lines as usize)")]
    pub line_numbers: Vec<LineNumberEntry>,
    /// Array of column number entries (if flags specify columns are present).
    #[declio(ctx = "Len(*num_lines as usize)", skip_if = "!flags.has_columns()")]
    pub columns: Vec<ColumnNumberEntry>,
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
    /// Offset of the instruction.
    pub offset: u32,
    /// Line number and statement flags.
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
    /// Offset of the file name in the string table.
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
