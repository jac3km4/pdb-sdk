//! # PDB SDK
//!
//! This crate parses and manages Microsoft Program Database (PDB) files.
//!
//! ## Major Differences from LLVM
//!
//! While this crate draws heavily from the LLVM `DebugInfo/PDB` implementation, it takes several different design choices:
//!
//! - **Eager vs. Lazy Parsing:** LLVM often takes a lazy approach using continuous stream readers (e.g., lazily iterating `CVSymbolArray` or evaluating `GSIHashTable` buckets directly from disk). This crate generally prefers eager parsing into structured types in memory (e.g., loading symbols into `Vec`s) via the `declio` crate. This allows safer mutations and easier manipulation in Rust at the cost of higher initial parsing overhead.
//! - **Declarative Binary IO:** Rather than using manual pointer arithmetic and types like `support::ulittle32_t` with `BinaryStreamReader`, this codebase relies heavily on declarative binary serialization using the `declio` and `modular-bitfield` crates to handle byte arrays and bitfields.
//! - **Builder Pattern:** To construct PDB files, we use builders (`PdbBuilder`, `DbiBuilder`, etc.) which manage stream allocations under the hood, differing slightly from LLVM's `MSFBuilder` approach.

use std::num::NonZeroU32;
use std::{fmt, io, mem};

use dbi::{DbiModule, DbiStream, FpoStream, FrameDataStream, SectionHeaderStream};
use declio::ctx::Len;
use declio::{Decode, Encode, EncodedSize};
use info::PdbInfo;
use module::Module;
use msf::{MsfStream, MsfStreamLayout, StreamIndex, SuperBlock};
use publics::Publics;
use result::{Error, Result};
use strings::Strings;
use symbol_map::SymbolMap;
use symbols::Symbols;
use types::{IpiStream, TpiStream, TypeHash, TypeStream};

pub mod builders;
mod codecs;
pub mod codeview;
mod constants;
pub mod dbi;
mod hash;
pub mod info;
pub mod module;
mod msf;
mod publics;
pub mod result;
mod strings;
mod symbol_map;
pub mod symbols;
pub mod types;
pub mod utils;

/// An MSF (Multi-Stream Format) container file representing a PDB file.
/// It contains multiple streams which can represent arbitrary data, such as the PDB Info Stream, TPI/IPI Streams, DBI Stream, etc.
#[derive(Debug)]
pub struct PdbFile<R> {
    inner: R,
    layouts: Vec<MsfStreamLayout>,
    block_size: u32,
}

impl<R> PdbFile<R>
where
    R: io::Read + io::Seek,
{
    /// Opens a PDB file from a reader and parses its MSF directory layout.
    pub fn open(mut reader: R) -> Result<Self> {
        let super_block = SuperBlock::decode((), &mut reader)?;
        let dir_layout = Self::get_dir_layout(&mut reader, &super_block)?;
        let mut dir_reader =
            MsfStream::<&mut R>::new(&mut reader, &dir_layout, super_block.block_size);
        let num_streams = u32::decode(constants::ENDIANESS, &mut dir_reader)?;
        let stream_sizes: Vec<u32> = Decode::decode(
            (Len(num_streams as usize), constants::ENDIANESS),
            &mut dir_reader,
        )?;
        let mut layouts = Vec::with_capacity(stream_sizes.len());
        for byte_size in stream_sizes {
            if byte_size == u32::MAX {
                continue;
            }
            let block_count = byte_size.div_ceil(super_block.block_size);
            let blocks = Decode::decode(Len(block_count as usize), &mut reader)?;
            layouts.push(MsfStreamLayout::new(blocks, byte_size));
        }

        let res = Self {
            inner: reader,
            layouts,
            block_size: super_block.block_size,
        };
        Ok(res)
    }

    fn get_indexed_stream(&mut self, index: StreamIndex) -> Option<BufMsfStream<'_, &mut R>> {
        let layout = self.layouts.get(index.0 as usize)?;
        let msf = MsfStream::new(&mut self.inner, layout, self.block_size);
        Some(io::BufReader::new(msf))
    }

    fn get_stream(&mut self, stream: BuiltinStream) -> Option<BufMsfStream<'_, &mut R>> {
        self.get_indexed_stream(StreamIndex(stream as u16))
    }

    fn get_dir_layout(reader: &mut R, super_block: &SuperBlock) -> Result<MsfStreamLayout> {
        reader.seek(io::SeekFrom::Start(super_block.block_map_offset().into()))?;
        let blocks = Decode::decode(Len(super_block.block_map_blocks() as usize), reader)?;
        Ok(MsfStreamLayout::new(blocks, super_block.num_dir_bytes))
    }

    /// Reads the PDB Info Stream.
    pub fn get_info(&mut self) -> Result<PdbInfo> {
        let stream = self
            .get_stream(BuiltinStream::Pdb)
            .ok_or(Error::StreamNotFound("PDB"))?;
        PdbInfo::read(stream)
    }

    /// Reads the global string table (`/names` stream).
    pub fn get_strings(&mut self, info: &PdbInfo) -> Result<Strings> {
        let index = info
            .named_streams()
            .get("/names")
            .ok_or(Error::StreamNotFound("names"))?;
        let mut stream = self
            .get_indexed_stream(index)
            .ok_or(Error::StreamNotFound("names"))?;
        Ok(Strings::decode((), &mut stream)?)
    }

    /// Reads the Debug Info (DBI) Stream.
    pub fn get_dbi(&mut self) -> Result<DbiStream> {
        let stream = self
            .get_stream(BuiltinStream::Dbi)
            .ok_or(Error::StreamNotFound("DBI"))?;
        DbiStream::read(stream)
    }

    /// Reads the Type Info (TPI) Stream, containing CodeView type records.
    pub fn get_tpi(&mut self) -> Result<TpiStream> {
        let stream = self
            .get_stream(BuiltinStream::Tpi)
            .ok_or(Error::StreamNotFound("TPI"))?;
        TypeStream::read(stream)
    }

    /// Reads the TPI hash stream for accelerated type lookups.
    pub fn get_tpi_hash<A>(&mut self, tpi: &TypeStream<A>) -> Result<TypeHash> {
        let hash_stream = self
            .get_indexed_stream(tpi.header().hash_stream_index)
            .ok_or(Error::StreamNotFound("TPI hash stream"))?;
        TypeHash::read(hash_stream, &tpi.header().hash_layout)
    }

    /// Reads the ID Info (IPI) Stream, containing CodeView ID records.
    pub fn get_ipi(&mut self) -> Result<IpiStream> {
        let stream = self
            .get_stream(BuiltinStream::Ipi)
            .ok_or(Error::StreamNotFound("IPI"))?;
        TypeStream::read(stream)
    }

    /// Reads the Public Symbol Stream, containing public (exported) symbol records.
    pub fn get_publics(&mut self, dbi: &DbiStream) -> Result<Publics> {
        let stream = self
            .get_indexed_stream(dbi.header().public_symbol_stream_index)
            .ok_or(Error::StreamNotFound("publics"))?;
        Publics::read_with_header(stream)
    }

    /// Reads the Global Symbol Stream, containing a single combined symbol table.
    pub fn get_globals(&mut self, dbi: &DbiStream) -> Result<SymbolMap> {
        let stream = self
            .get_indexed_stream(dbi.header().global_symbol_stream_index)
            .ok_or(Error::StreamNotFound("publics"))?;
        SymbolMap::read_with_header(stream)
    }

    /// Reads the main symbol record stream referenced by the DBI stream.
    pub fn get_symbols(&mut self, dbi: &DbiStream) -> Result<Symbols> {
        let stream = self
            .get_indexed_stream(dbi.header().sym_record_stream_index)
            .ok_or(Error::StreamNotFound("symbols"))?;
        Symbols::read(stream)
    }

    /// Reads the Section Header Stream.
    pub fn get_section_headers(&mut self, dbi: &DbiStream) -> Result<SectionHeaderStream> {
        let index = dbi
            .dbg_streams()
            .get(DbgHeader::SectionHdr as usize)
            .ok_or(Error::StreamNotFound("section HDR"))?;
        let stream = self
            .get_indexed_stream(*index)
            .ok_or(Error::StreamNotFound("section HDR"))?;
        SectionHeaderStream::read(stream)
    }

    /// Reads the Frame Data Stream (New FPO data).
    pub fn get_frame_data(&mut self, dbi: &DbiStream) -> Result<FrameDataStream> {
        let index = dbi
            .dbg_streams()
            .get(DbgHeader::NewFPO as usize)
            .ok_or(Error::StreamNotFound("frame data"))?;
        let stream = self
            .get_indexed_stream(*index)
            .ok_or(Error::StreamNotFound("frame data"))?;
        FrameDataStream::read(stream)
    }

    /// Reads the FPO Data Stream.
    pub fn get_fpo(&mut self, dbi: &DbiStream) -> Result<FpoStream> {
        let index = dbi
            .dbg_streams()
            .get(DbgHeader::Fpo as usize)
            .ok_or(Error::StreamNotFound("fpo"))?;
        let stream = self
            .get_indexed_stream(*index)
            .ok_or(Error::StreamNotFound("fpo"))?;
        FpoStream::read(stream)
    }

    /// Reads a Module Information Stream for a specific compiland, containing its symbols and line info.
    pub fn get_module(&mut self, module: &DbiModule) -> Result<Module> {
        let stream = self
            .get_indexed_stream(module.header.debug_info_stream)
            .ok_or(Error::StreamNotFound("module debug info"))?;
        Module::read(stream, &module.header.layout)
    }
}

pub(crate) type BufMsfStream<'a, R> = io::BufReader<MsfStream<'a, R>>;

#[allow(unused)]
#[derive(Debug)]
enum BuiltinStream {
    OldMsfDirectory = 0,
    Pdb = 1,
    Tpi = 2,
    Dbi = 3,
    Ipi = 4,
}

#[allow(unused)]
#[derive(Debug)]
enum DbgHeader {
    Fpo,
    Exception,
    Fixup,
    OmapToSrc,
    OmapFromSrc,
    SectionHdr,
    TokenRidMap,
    Xdata,
    Pdata,
    NewFPO,
    SectionHdrOrig,
    Max,
}

/// An offset into a string table.
#[derive(Debug, Clone, Copy, Encode, Decode)]
#[declio(ctx_is = "constants::ENDIANESS")]
pub struct StringOffset(u32);

/// Error indicating a type or ID index was zero.
#[derive(Debug)]
pub struct IndexIsZero;

macro_rules! record_index {
    ($name:ident) => {
        #[derive(Clone, Copy)]
        pub struct $name(NonZeroU32);

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}", self.0)
            }
        }

        impl TryFrom<u32> for $name {
            type Error = IndexIsZero;

            fn try_from(value: u32) -> Result<Self, Self::Error> {
                NonZeroU32::new(value).map(Self).ok_or(IndexIsZero)
            }
        }

        impl From<$name> for u32 {
            #[inline]
            fn from(ty: $name) -> Self {
                ty.0.get()
            }
        }

        impl<Ctx> Decode<Ctx> for $name {
            fn decode<R>(_ctx: Ctx, reader: &mut R) -> Result<Self, declio::Error>
            where
                R: io::Read,
            {
                u32::decode(constants::ENDIANESS, reader)?
                    .try_into()
                    .map_err(|_| declio::Error::new("Type index was zero"))
            }
        }

        impl<Ctx> Encode<Ctx> for $name {
            #[inline]
            fn encode<W>(&self, _ctx: Ctx, writer: &mut W) -> Result<(), declio::Error>
            where
                W: io::Write,
            {
                self.0.get().encode(constants::ENDIANESS, writer)
            }
        }

        impl<Ctx> EncodedSize<Ctx> for $name {
            #[inline]
            fn encoded_size(&self, _ctx: Ctx) -> usize {
                mem::size_of::<u32>()
            }
        }
    };
}

/// An offset indicating the position of a symbol record within its stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Decode, Encode, EncodedSize)]
#[declio(ctx_is = "constants::ENDIANESS")]
pub struct SymbolOffset(pub(crate) u32);

impl From<u32> for SymbolOffset {
    fn from(val: u32) -> Self {
        SymbolOffset(val)
    }
}

impl From<SymbolOffset> for u32 {
    fn from(val: SymbolOffset) -> Self {
        val.0
    }
}

record_index!(IdIndex);
record_index!(TypeIndex);

/// A 128-bit identifier guaranteed to be unique across space and time. Used to match a PDB to its corresponding executable.
#[derive(Default, Encode, Decode, EncodedSize)]
pub struct Guid(#[declio(with = "codecs::byte_array")] pub [u8; 16]);

impl fmt::Debug for Guid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "\"{:02X}{:02X}{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}\"",
            self.0[3],
            self.0[2],
            self.0[1],
            self.0[0],
            self.0[5],
            self.0[4],
            self.0[7],
            self.0[6],
            self.0[8],
            self.0[9],
            self.0[10],
            self.0[11],
            self.0[12],
            self.0[13],
            self.0[14],
            self.0[15]
        )
    }
}

/// Represents an integer value encoded in the smallest possible numeric leaf type.
/// Used in CodeView type records.
#[derive(Debug)]
pub enum Integer {
    I16(i16),
    I32(i32),
    I64(i64),
    U8(u8),
    U16(u16),
    U32(u32),
    U64(u64),
}

impl Integer {
    /// Create an Integer from an unsigned value, using smallest encoding
    pub fn from_unsigned(val: u64) -> Self {
        if val <= u16::MAX as u64 {
            Integer::U16(val as u16)
        } else if val <= u32::MAX as u64 {
            Integer::U32(val as u32)
        } else {
            Integer::U64(val)
        }
    }

    /// Create an Integer from a signed value, using smallest encoding
    pub fn from_signed(val: i64) -> Self {
        if val >= i16::MIN as i64 && val <= i16::MAX as i64 {
            Integer::I16(val as i16)
        } else if val >= i32::MIN as i64 && val <= i32::MAX as i64 {
            Integer::I32(val as i32)
        } else {
            Integer::I64(val)
        }
    }
}

impl From<usize> for Integer {
    fn from(val: usize) -> Self {
        Integer::from_unsigned(val as u64)
    }
}

impl From<u32> for Integer {
    fn from(val: u32) -> Self {
        Integer::from_unsigned(val as u64)
    }
}

impl From<u64> for Integer {
    fn from(val: u64) -> Self {
        Integer::from_unsigned(val)
    }
}

impl From<i64> for Integer {
    fn from(val: i64) -> Self {
        Integer::from_signed(val)
    }
}

impl<Ctx: Copy> Decode<Ctx> for Integer {
    fn decode<R>(_ctx: Ctx, reader: &mut R) -> Result<Self, declio::Error>
    where
        R: io::Read,
    {
        match u16::decode(constants::ENDIANESS, reader)? {
            val if val < constants::LF_NUMERIC => Ok(Integer::U16(val)),
            constants::LF_CHAR => Ok(Integer::U8(u8::decode(constants::ENDIANESS, reader)?)),
            constants::LF_SHORT => Ok(Integer::I16(i16::decode(constants::ENDIANESS, reader)?)),
            constants::LF_USHORT => Ok(Integer::U16(u16::decode(constants::ENDIANESS, reader)?)),
            constants::LF_LONG => Ok(Integer::I32(i32::decode(constants::ENDIANESS, reader)?)),
            constants::LF_ULONG => Ok(Integer::U32(u32::decode(constants::ENDIANESS, reader)?)),
            constants::LF_QUADWORD => Ok(Integer::I64(i64::decode(constants::ENDIANESS, reader)?)),
            constants::LF_UQUADWORD => Ok(Integer::U64(u64::decode(constants::ENDIANESS, reader)?)),
            val => todo!("{}", val),
        }
    }
}

impl<Ctx> Encode<Ctx> for Integer {
    fn encode<W>(&self, _ctx: Ctx, writer: &mut W) -> Result<(), declio::Error>
    where
        W: io::Write,
    {
        match self {
            Integer::I16(i) => {
                constants::LF_SHORT.encode(constants::ENDIANESS, writer)?;
                i.encode(constants::ENDIANESS, writer)
            }
            Integer::I32(i) => {
                constants::LF_LONG.encode(constants::ENDIANESS, writer)?;
                i.encode(constants::ENDIANESS, writer)
            }
            Integer::I64(i) => {
                constants::LF_QUADWORD.encode(constants::ENDIANESS, writer)?;
                i.encode(constants::ENDIANESS, writer)
            }
            Integer::U32(i) => {
                constants::LF_ULONG.encode(constants::ENDIANESS, writer)?;
                i.encode(constants::ENDIANESS, writer)
            }
            Integer::U64(i) => {
                constants::LF_UQUADWORD.encode(constants::ENDIANESS, writer)?;
                i.encode(constants::ENDIANESS, writer)
            }
            Integer::U8(i) => u16::from(*i).encode(constants::ENDIANESS, writer),
            Integer::U16(i) => i.encode(constants::ENDIANESS, writer),
        }
    }
}

impl<Ctx> EncodedSize<Ctx> for Integer {
    fn encoded_size(&self, _ctx: Ctx) -> usize {
        match self {
            Integer::I16(_) => 4,
            Integer::U8(_) | Integer::U16(_) => 2,
            Integer::I32(_) | Integer::U32(_) => 6,
            Integer::I64(_) | Integer::U64(_) => 10,
        }
    }
}
