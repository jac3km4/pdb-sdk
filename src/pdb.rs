//! Per-stream access to a PDB in an MSF 7.0 container.
//!
//! See LLVM's [PDB format guide](https://llvm.org/docs/PDB/index.html) for stream roles.

use std::io;

use declio::Decode;
use declio::ctx::Len;

use crate::dbi::{DbiModule, DbiStream, FpoStream, FrameDataStream, SectionHeaderStream};
use crate::info::PdbInfo;
use crate::module::Module;
use crate::msf::{BlockIndex, MsfStream, MsfStreamLayout, SuperBlock};
use crate::result::{Error, Result};
use crate::symbols::Symbols;
use crate::types::{IpiStream, TpiStream, TypeHash, TypeStream};
use crate::{Publics, StreamIndex, Strings, SymbolMap, constants};

/// A PDB reader backed by a seekable MSF 7.0 container.
///
/// Opening reads the stream directory, not every stream. Getters decode the
/// requested stream into owned data; supplied metadata must come from this PDB.
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
    /// Parses the MSF 7.0 header and stream directory.
    ///
    /// The reader must be positioned at the start of the file. Stream offsets are
    /// absolute; embedding a PDB at a nonzero reader offset is not supported.
    pub fn open(mut reader: R) -> Result<Self> {
        let start = reader.stream_position()?;
        let file_len = reader.seek(io::SeekFrom::End(0))?;
        reader.seek(io::SeekFrom::Start(start))?;
        let super_block = SuperBlock::decode((), &mut reader)?;
        super_block.validate(file_len)?;
        let dir_layout = Self::get_dir_layout(&mut reader, &super_block)?;
        let mut dir_reader =
            MsfStream::<&mut R>::new(&mut reader, &dir_layout, super_block.block_size);
        let num_streams = u32::decode(constants::ENDIANESS, &mut dir_reader)?;
        let mut remaining = u64::from(super_block.num_dir_bytes) - 4;
        let sizes_bytes = u64::from(num_streams) * 4;
        if sizes_bytes > remaining {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "stream count exceeds MSF directory",
            )
            .into());
        }
        remaining -= sizes_bytes;
        let stream_sizes: Vec<u32> = Decode::decode(
            (Len(num_streams as usize), constants::ENDIANESS),
            &mut dir_reader,
        )?;

        let mut layouts = Vec::with_capacity(stream_sizes.len());
        for byte_size in stream_sizes {
            if byte_size == u32::MAX {
                layouts.push(MsfStreamLayout::new(Vec::new(), 0));
                continue;
            }
            let block_count = byte_size.div_ceil(super_block.block_size);
            let block_bytes = u64::from(block_count) * 4;
            if block_bytes > remaining {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "stream block list exceeds MSF directory",
                )
                .into());
            }
            remaining -= block_bytes;
            let blocks: Vec<BlockIndex> =
                Decode::decode(Len(block_count as usize), &mut dir_reader)?;
            Self::validate_blocks(&blocks, &super_block)?;
            layouts.push(MsfStreamLayout::new(blocks, byte_size));
        }

        if remaining != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "MSF directory contains unexplained bytes",
            )
            .into());
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
        reader.seek(io::SeekFrom::Start(super_block.block_map_offset()))?;
        let blocks: Vec<BlockIndex> =
            Decode::decode(Len(super_block.block_map_blocks() as usize), reader)?;
        Self::validate_blocks(&blocks, super_block)?;
        Ok(MsfStreamLayout::new(blocks, super_block.num_dir_bytes))
    }

    fn validate_blocks(blocks: &[BlockIndex], super_block: &SuperBlock) -> Result<()> {
        if blocks.iter().any(|block| block.0 >= super_block.num_blocks) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "MSF block reference is outside file",
            )
            .into());
        }
        Ok(())
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

    /// Reads TPI records describing types such as classes, pointers, and procedures.
    ///
    /// Only V80 streams with a 56-byte header and supported record kinds are
    /// decoded. Built-in simple types have indices rather than stored records.
    pub fn get_tpi(&mut self) -> Result<TpiStream> {
        let stream = self
            .get_stream(BuiltinStream::Tpi)
            .ok_or(Error::StreamNotFound("TPI"))?;
        TypeStream::read(stream)
    }

    /// Reads the hash stream referenced by a TPI or IPI header.
    ///
    /// This returns hash metadata, not a collision-resolving name lookup index.
    /// See [`TypeHash::get_index`] for its candidate-lookup limitations.
    pub fn get_tpi_hash<A>(&mut self, tpi: &TypeStream<A>) -> Result<TypeHash> {
        let hash_stream = self
            .get_indexed_stream(tpi.header().hash_stream_index)
            .ok_or(Error::StreamNotFound("TPI hash stream"))?;
        TypeHash::read(
            hash_stream,
            &tpi.header().hash_layout,
            tpi.header().num_hash_buckets,
        )
    }

    /// Reads IPI records for function IDs, strings, build info, and source references.
    ///
    /// IPI uses the TPI layout but a separate index space and record set. It may
    /// be absent, including in older PDBs.
    pub fn get_ipi(&mut self) -> Result<IpiStream> {
        let stream = self
            .get_stream(BuiltinStream::Ipi)
            .ok_or(Error::StreamNotFound("IPI"))?;
        TypeStream::read(stream)
    }

    /// Reads the public-symbol hash index and address/thunk maps.
    ///
    /// Entries refer into the separate stream returned by [`Self::get_symbols`].
    /// PDB public symbols are not the PE export table.
    pub fn get_publics(&mut self, dbi: &DbiStream) -> Result<Publics> {
        let stream = self
            .get_indexed_stream(dbi.header().public_symbol_stream_index)
            .ok_or(Error::StreamNotFound("publics"))?;
        Publics::read_with_header(stream)
    }

    /// Reads the global-symbol hash index, not the symbol records themselves.
    ///
    /// The index refers into the stream returned by [`Self::get_symbols`].
    /// [`SymbolMap`] currently exposes serialization, not name lookup.
    pub fn get_globals(&mut self, dbi: &DbiStream) -> Result<SymbolMap> {
        let stream = self
            .get_indexed_stream(dbi.header().global_symbol_stream_index)
            .ok_or(Error::StreamNotFound("publics"))?;
        SymbolMap::read_with_header(stream)
    }

    /// Reads the shared symbol records referenced by the global/public indexes.
    ///
    /// Module-local records are read separately by [`Self::get_module`]. The
    /// returned collection is in record order, not indexed by byte offset.
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
pub(crate) enum BuiltinStream {
    OldMsfDirectory = 0,
    Pdb = 1,
    Tpi = 2,
    Dbi = 3,
    Ipi = 4,
}

#[allow(unused)]
#[derive(Debug)]
pub(crate) enum DbgHeader {
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

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use declio::Encode;

    use super::*;
    use crate::builders::PdbBuilder;
    use crate::msf::MsfHeader;

    const BLOCK_SIZE: usize = 512;
    const DIRECTORY_OFFSET: usize = 3 * BLOCK_SIZE;

    fn write_u32(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn container() -> Vec<u8> {
        let mut bytes = vec![0; 4 * BLOCK_SIZE];
        let header = SuperBlock {
            magic: MsfHeader,
            block_size: BLOCK_SIZE as u32,
            free_block_map_block: 1,
            num_blocks: 4,
            num_dir_bytes: 12,
            unknown: 0,
            block_map_addr: BlockIndex(2),
        };
        header.encode((), &mut Cursor::new(&mut bytes)).unwrap();
        write_u32(&mut bytes, 2 * BLOCK_SIZE, 3);
        write_u32(&mut bytes, DIRECTORY_OFFSET, 1);
        write_u32(&mut bytes, DIRECTORY_OFFSET + 4, 4);
        write_u32(&mut bytes, DIRECTORY_OFFSET + 8, 1);
        bytes
    }

    #[test]
    fn opens_valid_synthetic_directory() {
        let pdb = PdbFile::open(Cursor::new(container())).unwrap();
        assert_eq!(pdb.block_size, BLOCK_SIZE as u32);
        assert_eq!(pdb.layouts.len(), 1);
        assert_eq!(pdb.layouts[0].byte_size, 4);
        assert_eq!(pdb.layouts[0].blocks[0].0, 1);
    }

    #[test]
    fn rejects_zero_and_unsupported_block_sizes() {
        for block_size in [0, 513, u32::MAX] {
            let mut bytes = container();
            write_u32(&mut bytes, 32, block_size);
            assert!(PdbFile::open(Cursor::new(bytes)).is_err());
        }
    }

    #[test]
    fn rejects_unaligned_or_unconsumed_directory_bytes() {
        for size in [13, 16] {
            let mut bytes = container();
            write_u32(&mut bytes, 44, size);
            assert!(PdbFile::open(Cursor::new(bytes)).is_err());
        }
        // Bytes outside the directory's declared extent are block padding.
        let mut bytes = container();
        write_u32(&mut bytes, DIRECTORY_OFFSET + 12, u32::MAX);
        let pdb = PdbFile::open(Cursor::new(bytes)).unwrap();
        assert_eq!(pdb.layouts[0].byte_size, 4);
        assert_eq!(pdb.layouts[0].blocks[0].0, 1);
    }

    #[test]
    fn rejects_huge_stream_count() {
        let mut bytes = container();
        write_u32(&mut bytes, DIRECTORY_OFFSET, u32::MAX);
        assert!(PdbFile::open(Cursor::new(bytes)).is_err());
    }

    #[test]
    fn rejects_out_of_range_directory_block() {
        let mut bytes = container();
        write_u32(&mut bytes, 2 * BLOCK_SIZE, 4);
        assert!(PdbFile::open(Cursor::new(bytes)).is_err());
    }

    #[test]
    fn rejects_out_of_range_stream_block() {
        let mut bytes = container();
        write_u32(&mut bytes, DIRECTORY_OFFSET + 8, u32::MAX);
        assert!(PdbFile::open(Cursor::new(bytes)).is_err());
    }

    #[test]
    fn rejects_stream_block_list_larger_than_directory() {
        let mut bytes = container();
        write_u32(&mut bytes, DIRECTORY_OFFSET + 4, u32::MAX - 1);
        assert!(PdbFile::open(Cursor::new(bytes)).is_err());
    }

    #[test]
    fn rejects_truncated_builder_output() {
        let mut sink = Cursor::new(Vec::new());
        PdbBuilder::default().commit(&mut sink).unwrap();
        let bytes = sink.into_inner();
        for length in [0, 31, 55, bytes.len() - 1] {
            assert!(PdbFile::open(Cursor::new(&bytes[..length])).is_err());
        }
    }
}
