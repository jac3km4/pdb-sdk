use std::io;

use declio::Encode;

use crate::msf::*;
use crate::result::Result;
use crate::{BuiltinStream, MsfStreamLayout, StreamIndex, constants};

mod dbi;
mod info;
mod module;
mod symbols;
mod types;

pub use self::dbi::DbiBuilder;
pub use self::info::InfoBuilder;
pub use self::module::ModuleBuilder;
pub use self::symbols::{PublicsBuilder, SymbolsBuilder};
pub use self::types::{IpiBuilder, TpiBuilder, TypeStreamBuilder};

#[derive(Debug, Default)]
pub struct PdbBuilder {
    info: InfoBuilder,
    dbi: DbiBuilder,
    tpi: TpiBuilder,
    ipi: IpiBuilder,
}

impl PdbBuilder {
    pub fn info(&mut self) -> &mut InfoBuilder {
        &mut self.info
    }

    pub fn dbi(&mut self) -> &mut DbiBuilder {
        &mut self.dbi
    }

    pub fn tpi(&mut self) -> &mut TpiBuilder {
        &mut self.tpi
    }

    pub fn ipi(&mut self) -> &mut IpiBuilder {
        &mut self.ipi
    }

    /// Writes the PDB to a seekable sink, which must begin at position zero.
    ///
    /// An error may leave partial writes in the sink; writes are not rolled back.
    /// On success, the final position is immediately after the rewritten superblock,
    /// not at the end of the file.
    pub fn commit<S>(mut self, mut sink: S) -> Result<()>
    where
        S: io::Write + io::Seek,
    {
        let mut allocator = StreamAllocator::default();
        // superblock
        sink.write_all(EMPTY_BLOCK)?;
        // initial FPMs
        sink.write_all(FULL_BLOCK)?;
        sink.write_all(FULL_BLOCK)?;

        self.dbi.age = self.info.age;

        let info_layout = self.info.commit(&mut sink)?;
        let dbi_layout = self.dbi.commit(&mut sink, &mut allocator)?;
        let tpi_layout = self.tpi.commit(&mut sink, &mut allocator)?;
        let ipi_layout = self.ipi.commit(&mut sink, &mut allocator)?;
        allocator.insert_builtin(BuiltinStream::Pdb, info_layout);
        allocator.insert_builtin(BuiltinStream::Dbi, dbi_layout);
        allocator.insert_builtin(BuiltinStream::Tpi, tpi_layout);
        allocator.insert_builtin(BuiltinStream::Ipi, ipi_layout);

        let mut directory = DefaultMsfStreamWriter::new(&mut sink)?;
        let num_streams = allocator.streams.len() as u32;
        num_streams.encode(constants::ENDIANESS, &mut directory)?;
        for stream in &allocator.streams {
            stream
                .byte_size
                .encode(constants::ENDIANESS, &mut directory)?;
        }
        for stream in &allocator.streams {
            stream.blocks.encode(((),), &mut directory)?;
        }

        let dir_layout = directory.finish()?;

        let mut addr_map = DefaultMsfStreamWriter::new(&mut sink)?;
        dir_layout.blocks.encode(((),), &mut addr_map)?;
        let addr_map_layout = addr_map.finish()?;
        let dir_bytes = dir_layout.byte_size;
        let block_map_addr = addr_map_layout.blocks.first().copied().unwrap();

        allocator.allocate(dir_layout);
        allocator.allocate(addr_map_layout);

        let end = sink.stream_position()?;
        let block_size = u64::from(DEFAULT_BLOCK_SIZE);
        if !end.is_multiple_of(block_size) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "final MSF extent is not block-aligned",
            )
            .into());
        }
        let num_blocks = u32::try_from(end / block_size).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "MSF block count exceeds u32")
        })?;

        let superblock = SuperBlock {
            magic: MsfHeader,
            block_size: DEFAULT_BLOCK_SIZE,
            free_block_map_block: 1,
            num_blocks,
            num_dir_bytes: dir_bytes,
            unknown: 0,
            block_map_addr,
        };
        FreeBlockMap::write(&superblock, &mut sink)?;

        sink.seek(io::SeekFrom::Start(0))?;
        superblock.encode((), &mut sink)?;

        Ok(())
    }
}

#[derive(Debug)]
struct StreamAllocator {
    streams: Vec<MsfStreamLayout>,
}

impl StreamAllocator {
    const BUILTIN_STREAM_COUNT: usize = 5;

    fn allocate(&mut self, layout: MsfStreamLayout) -> StreamIndex {
        let idx = StreamIndex(self.streams.len() as u16);
        self.streams.push(layout);
        idx
    }

    fn insert_builtin(&mut self, stream: BuiltinStream, layout: MsfStreamLayout) {
        self.streams[stream as usize] = layout;
    }
}

impl Default for StreamAllocator {
    fn default() -> Self {
        let mut streams = Vec::with_capacity(Self::BUILTIN_STREAM_COUNT);
        streams.resize_with(Self::BUILTIN_STREAM_COUNT, MsfStreamLayout::default);
        Self { streams }
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use declio::{Decode, EncodedSize};

    use super::*;
    use crate::PdbFile;
    use crate::codeview::types::IdRecord;
    use crate::codeview::{PrefixedRecord, RECORD_ALIGNMENT};
    use crate::info::PdbFeature;
    use crate::utils::{StrBuf, align_to};

    #[test]
    fn builder_roundtrip_at_fpm_boundary() -> Result<()> {
        let make_record = || IdRecord::StringId {
            id: None,
            string: StrBuf::new("x".repeat(4087)),
        };
        let record = make_record();
        let record_size = align_to(
            u16::default_encoded_size(()) + record.encoded_size(()),
            RECORD_ALIGNMENT,
        );
        assert_eq!(record_size, DEFAULT_BLOCK_SIZE as usize);
        let mut encoded = Vec::new();
        PrefixedRecord(record).encode((), &mut encoded)?;
        assert_eq!(encoded.len(), record_size);

        // Each record occupies one block; stream metadata adds 28 blocks here.
        // Ending at 4096 or 4097 blocks must not count the next FPM pair yet.
        // One more record crosses reserved blocks 4097/4098, reaching 4100.
        // The old allocation formula incorrectly declared 4098/4099/4100.
        for (record_count, expected_blocks) in [(4068, 4096), (4069, 4097), (4070, 4100)] {
            let mut builder = PdbBuilder::default();
            for _ in 0..record_count {
                builder.ipi().add("boundary", make_record());
            }
            let mut sink = Cursor::new(Vec::new());
            builder.commit(&mut sink)?;
            let file_len = sink.get_ref().len() as u64;
            sink.set_position(0);
            let superblock = SuperBlock::decode((), &mut sink)?;
            assert_eq!(superblock.block_size, DEFAULT_BLOCK_SIZE);
            assert_eq!(superblock.num_blocks, expected_blocks);
            assert_eq!(
                u64::from(superblock.num_blocks) * u64::from(DEFAULT_BLOCK_SIZE),
                file_len
            );
            sink.set_position(0);
            let mut pdb = PdbFile::open(sink)?;
            assert_eq!(pdb.get_ipi()?.records().len(), record_count);
        }
        Ok(())
    }

    #[test]
    fn empty_builder_roundtrip() -> Result<()> {
        let mut sink = Cursor::new(Vec::new());
        PdbBuilder::default().commit(&mut sink)?;

        let final_position = sink.position();
        assert!(final_position < sink.get_ref().len() as u64);
        sink.set_position(0);
        SuperBlock::decode((), &mut sink)?;
        assert_eq!(final_position, sink.position());
        sink.set_position(0);

        let mut pdb = PdbFile::open(sink)?;
        let info = pdb.get_info()?;
        assert_eq!(info.header().signature, 0);
        assert_eq!(info.header().age, 1);
        assert_eq!(info.named_streams().iter().count(), 0);
        assert_eq!(info.features(), &[PdbFeature::Vc140]);

        let dbi = pdb.get_dbi()?;
        assert_eq!(dbi.header().age, info.header().age);
        assert!(dbi.modules().is_empty());
        assert!(dbi.section_contribs().is_empty());
        assert!(pdb.get_symbols(&dbi)?.records().is_empty());
        assert!(pdb.get_publics(&dbi)?.address_map().is_empty());
        pdb.get_globals(&dbi)?;

        let tpi = pdb.get_tpi()?;
        assert!(tpi.records().is_empty());
        assert_eq!(tpi.header().type_index_begin, tpi.header().type_index_end);
        assert_eq!(tpi.header().type_record_bytes, 0);
        assert!(pdb.get_tpi_hash(&tpi)?.get_index("missing").is_none());

        let ipi = pdb.get_ipi()?;
        assert!(ipi.records().is_empty());
        assert_eq!(ipi.header().type_index_begin, ipi.header().type_index_end);
        assert_eq!(ipi.header().type_record_bytes, 0);
        assert!(pdb.get_tpi_hash(&ipi)?.get_index("missing").is_none());
        Ok(())
    }
}
