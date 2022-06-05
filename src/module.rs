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

#[derive(Debug, Getters)]
pub struct Module {
    symbols: Vec<SymbolRecord>,
    c11_bytes: Vec<u8>,
    c13_records: Vec<DebugSubsectionEntry>,
    global_ref_bytes: Vec<u8>,
}

impl Module {
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

        let c11_bytes = <Bytes>::decode(Len(layout.c11_bytes as usize), &mut source)?.into_vec();

        let mut c13_records = vec![];
        let mut c13_stream = source.by_ref().take(layout.c13_bytes.into());
        while c13_stream.limit() > 0 {
            c13_records.push(DebugSubsectionEntry::decode((), &mut c13_stream)?);
        }

        let global_ref_bytes = <Bytes<u32>>::decode(constants::ENDIANESS, &mut source)?.into_vec();

        let res = Self {
            symbols,
            c11_bytes,
            c13_records,
            global_ref_bytes,
        };
        Ok(res)
    }

    pub(crate) fn write<S, const N: u32>(self, sink: &mut MsfStreamWriter<S, N>) -> Result<ModuleLayout>
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

#[derive(Debug, Encode, Decode, EncodedSize)]
#[declio(ctx_is = "constants::ENDIANESS")]
pub struct ModuleLayout {
    sym_bytes: u32,
    c11_bytes: u32,
    c13_bytes: u32,
}

#[derive(Debug, Encode, Decode, EncodedSize)]
#[declio(ctx_is = "constants::ENDIANESS")]
pub struct DebugSubsectionEntry {
    pub record_type: DebugSubsectionRecordType,
    #[declio(via = "Bytes<u32>")]
    pub data: Vec<u8>,
}

impl DebugSubsectionEntry {
    pub fn decoded(&self) -> Result<DebugSubsectionRecord> {
        let ctx = self.record_type;
        Ok(DebugSubsectionRecord::decode(ctx, &mut &self.data[..])?)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, BitfieldSpecifier)]
#[bits = 32]
pub enum DebugSubsectionRecordType {
    Symbols = 0xf1,
    Lines = 0xf2,
    StringTable = 0xf3,
    FileChecksums = 0xf4,
    FrameData = 0xf5,
    InlineeLines = 0xf6,
    CrossScopeImports = 0xf7,
    CrossScopeExports = 0xf8,
    ILLines = 0xf9,
    FuncMDTokenMap = 0xfa,
    TypeMDTokenMap = 0xfb,
    MergedAssemblyInput = 0xfc,
    CoffSymbolRVA = 0xfd,
}

impl_bitfield_specifier_codecs!(DebugSubsectionRecordType);

#[derive(Debug, Encode, Decode, EncodedSize)]
#[declio(ctx = "record_type: DebugSubsectionRecordType", id_expr = "record_type")]
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

#[derive(Debug, Encode, Decode, EncodedSize)]
#[declio(ctx_is = "constants::ENDIANESS")]
pub struct LineFragmentHeader {
    pub reloc: DataRegionOffset,
    pub flags: LineFlags,
    pub code_size: u32,
}

#[derive(Debug, Encode, Decode, EncodedSize)]
#[declio(ctx = "flags: LineFlags, endian: Endian")]
pub struct LineColumnEntry {
    pub name_index: u32,
    pub num_lines: u32,
    pub code_size: u32,
    #[declio(ctx = "Len(*num_lines as usize)")]
    pub line_numbers: Vec<LineNumberEntry>,
    #[declio(ctx = "Len(*num_lines as usize)", skip_if = "!flags.has_columns()")]
    pub columns: Vec<ColumnNumberEntry>,
}

#[bitfield(bits = 16)]
#[derive(Debug, Clone, Copy)]
pub struct LineFlags {
    pub has_columns: bool,
    #[skip]
    padding: B15,
}

impl_bitfield_codecs!(LineFlags);

#[derive(Debug, Encode, Decode, EncodedSize)]
#[declio(ctx_is = "constants::ENDIANESS")]
pub struct LineNumberEntry {
    pub offset: u32,
    pub flags: u32,
}

#[derive(Debug, Encode, Decode, EncodedSize)]
#[declio(ctx_is = "constants::ENDIANESS")]
pub struct ColumnNumberEntry {
    pub start_col: u16,
    pub end_col: u16,
}

#[derive(Debug, Encode, Decode, EncodedSize)]
#[declio(ctx_is = "constants::ENDIANESS")]
pub struct FileChecksumEntry {
    pub file_name_offset: u32,
    pub checksum_size: u8,
    pub checksum_type: ChecksumType,
    #[declio(ctx = "Len(usize::from(*checksum_size))", via = "Bytes")]
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, BitfieldSpecifier)]
#[bits = 8]
pub enum ChecksumType {
    None,
    Md5,
    Sha1,
    Sha256,
}

impl_bitfield_specifier_codecs!(ChecksumType);
