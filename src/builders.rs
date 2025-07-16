use std::collections::BTreeMap;
use std::io::{self, Write};

use declio::{Encode, EncodedSize};

use crate::codeview::symbols::{Public, SymbolRecord};
use crate::codeview::types::{IdRecord, TypeRecord};
use crate::codeview::{PrefixedRecord, RECORD_ALIGNMENT};
use crate::dbi::*;
use crate::hash::{hash_v1, Table};
use crate::info::{PdbFeature, PdbInfoHeader, PdbVersion};
use crate::module::{DebugSubsectionEntry, Module};
use crate::msf::*;
use crate::publics::Publics;
use crate::result::Result;
use crate::strings::StringsBuilder;
use crate::symbol_map::Globals;
use crate::types::{TypeHash, TypeStreamHeader, FIRST_NON_BUILTIN_TYPE, HASH_BUCKET_NUMBER};
use crate::utils::{align_to, StrBuf};
use crate::{
    codecs, constants, BuiltinStream, Guid, MsfStreamLayout, StreamIndex, SymbolOffset, TypeIndex
};

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

    pub fn commit<S>(mut self, mut sink: S) -> Result<()>
    where
        S: io::Write + io::Seek,
    {
        let mut allocator = StreamAllocator::default();
        // superblock
        sink.write_all(EMPTY_BLOCK)?;
        // initial FPMs
        sink.write_all(EMPTY_BLOCK)?;
        sink.write_all(EMPTY_BLOCK)?;

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
            stream.byte_size.encode(constants::ENDIANESS, &mut directory)?;
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

        // stream blocks plus one superblock
        let allocated_blocks = allocator.block_count() as u32 + 1;
        // allocated blocks plus FPM blocks
        let fpm_gap_size = DEFAULT_BLOCK_SIZE - 2;
        let num_blocks = allocated_blocks + (1 + allocated_blocks / fpm_gap_size) * 2;

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

#[derive(Debug, Default)]
pub struct DbiBuilder {
    symbols: SymbolsBuilder,
    modules: Vec<ModuleBuilder>,
    section_contribs: Vec<SectionContrib>,
    section_entries: Vec<SectionMapEntry>,
    section_headers: Vec<SectionHeader>,
    names: StringsBuilder,
    debug_streams: Vec<StreamIndex>,
}

impl DbiBuilder {
    pub fn symbols(&mut self) -> PublicsBuilder {
        PublicsBuilder {
            symbols: &mut self.symbols,
        }
    }

    pub fn add_module(&mut self, module: ModuleBuilder) -> &mut Self {
        self.modules.push(module);
        self
    }

    pub fn add_section_contrib(&mut self, section: SectionContrib) -> &mut Self {
        self.section_contribs.push(section);
        self
    }

    pub fn add_section_entry(&mut self, section: SectionMapEntry) -> &mut Self {
        self.section_entries.push(section);
        self
    }

    pub fn add_section_header(&mut self, section: SectionHeader) -> &mut Self {
        self.section_headers.push(section);
        self
    }

    fn commit<S>(mut self, sink: &mut S, allocator: &mut StreamAllocator) -> Result<MsfStreamLayout>
    where
        S: io::Write + io::Seek,
    {
        let streams = self.symbols.commit(sink, allocator)?;
        let mut modules = Vec::with_capacity(self.modules.len());
        let mut files = Vec::with_capacity(self.modules.len());

        let file_names = self.modules.iter().flat_map(|m| &m.source_files);

        let file_count = file_names.clone().count();
        let file_info_size = u16::default_encoded_size(()) * 2
            + self.modules.len() * u32::default_encoded_size(())
            + file_count * u32::default_encoded_size(());
        let file_names_size: usize = file_names.map(|s| s.len() + 1).sum();

        for module in self.modules {
            let (res, names) = module.commit(sink, allocator)?;
            modules.push(res);
            files.push(names);
        }
        let names = self.names.build();

        let section_headers = if self.section_headers.is_empty() {
            StreamIndex(u16::MAX)
        } else {
            let mut section_headers = DefaultMsfStreamWriter::new(sink)?;
            for section in self.section_headers {
                section.encode((), &mut section_headers)?;
            }
            let section_headers_layout = section_headers.finish()?;
            allocator.allocate(section_headers_layout)
        };

        self.debug_streams.push(StreamIndex(u16::MAX)); // fpo
        self.debug_streams.push(StreamIndex(u16::MAX)); // exception
        self.debug_streams.push(StreamIndex(u16::MAX)); // fixup
        self.debug_streams.push(StreamIndex(u16::MAX)); // omap_to_src
        self.debug_streams.push(StreamIndex(u16::MAX)); // omap_from_src
        self.debug_streams.push(section_headers);

        let header = DbiHeader {
            signature: DbiSignature,
            version: DbiVersion::V70,
            age: 1,
            global_symbol_stream_index: streams.globals,
            build_number: BuildNumber::new()
                .with_major(14)
                .with_minor(11)
                .with_is_new_format(true),
            public_symbol_stream_index: streams.publics,
            dll_version: 0,
            sym_record_stream_index: streams.symbols,
            rbld: 0,
            modi_stream_size: modules.encoded_size(()) as u32,
            sec_contr_stream_size: u16::default_encoded_size(()) as u32 * 2
                + self.section_contribs.encoded_size(()) as u32,
            section_map_size: u16::default_encoded_size(()) as u32 * 2
                + self.section_entries.encoded_size(()) as u32,
            file_info_size: (file_info_size + file_names_size) as u32,
            type_server_size: 0,
            mfc_type_server_index: 0,
            optional_db_header_size: self.debug_streams.encoded_size(()) as u32,
            ec_stream_size: names.encoded_size(()) as u32,
            flags: DbiFlags::new(),
            machine_type: MachineType::Amd64,
            reserved: Default::default(),
        };

        let mut stream = DefaultMsfStreamWriter::new(sink)?;
        header.encode((), &mut stream)?;

        codecs::padded_rem_list::encode(&modules, constants::ENDIANESS, &mut stream)?;

        SectionContribVersion::Ver60.encode(constants::ENDIANESS, &mut stream)?;
        self.section_contribs.encode(((),), &mut stream)?;

        let section_map_len = self.section_entries.len() as u16;
        section_map_len.encode(constants::ENDIANESS, &mut stream)?;
        section_map_len.encode(constants::ENDIANESS, &mut stream)?;
        self.section_entries.encode(((),), &mut stream)?;

        let num_modules = modules.len() as u16;
        num_modules.encode(constants::ENDIANESS, &mut stream)?;
        (file_count as u16).encode(constants::ENDIANESS, &mut stream)?;
        for index in 0..modules.len() as u16 {
            index.encode(constants::ENDIANESS, &mut stream)?;
        }
        for module in &modules {
            module
                .header
                .num_files
                .encode(constants::ENDIANESS, &mut stream)?;
        }
        let mut offset: u32 = 0;
        for name in files.iter().flatten() {
            offset.encode(constants::ENDIANESS, &mut stream)?;
            offset += name.len() as u32 + 1;
        }
        for name in files.iter().flatten() {
            stream.write_all(name.as_bytes())?;
            stream.write_all(b"\0")?;
        }
        names.encode((), &mut stream)?;
        self.debug_streams.encode(((),), &mut stream)?;

        Ok(stream.finish()?)
    }
}

#[derive(Debug, Default)]
pub struct InfoBuilder {
    signature: u32,
    age: u32,
    guid: Guid,
    named_streams: Vec<(StreamIndex, String)>,
}

impl InfoBuilder {
    pub fn signature(&mut self, signature: u32) -> &mut Self {
        self.signature = signature;
        self
    }

    pub fn age(&mut self, age: u32) -> &mut Self {
        self.age = age;
        self
    }

    pub fn guid(&mut self, guid: Guid) -> &mut Self {
        self.guid = guid;
        self
    }

    fn commit<S>(self, sink: &mut S) -> Result<MsfStreamLayout>
    where
        S: io::Write + io::Seek,
    {
        let mut writer = DefaultMsfStreamWriter::new(sink)?;

        let header = PdbInfoHeader {
            version: PdbVersion::Vc70,
            signature: self.signature,
            age: self.age,
            guid: self.guid,
        };
        header.encode((), &mut writer)?;
        let buffer_size: u32 = self.named_streams.iter().map(|(_, s)| s.len() as u32 + 1).sum();
        buffer_size.encode(constants::ENDIANESS, &mut writer)?;

        let mut offsets = Vec::with_capacity(self.named_streams.len());
        let mut offset = 0;
        for (index, name) in self.named_streams {
            offset += name.len() as u32 + 1;
            offsets.push((u16::from(index).into(), offset));

            StrBuf::new(name).encode((), &mut writer)?;
        }
        Table::from_sized_iter(offsets.into_iter()).encode((), &mut writer)?;

        // enables the IPI stream
        PdbFeature::Vc140.encode((), &mut writer)?;

        Ok(writer.finish()?)
    }
}

pub type TpiBuilder = TypeStreamBuilder<TypeRecord>;
pub type IpiBuilder = TypeStreamBuilder<IdRecord>;

#[derive(Debug)]
pub struct TypeStreamBuilder<A> {
    records: Vec<A>,
    hashes: Vec<u32>,
    offset: usize,
    index: u32,
}

impl<A> TypeStreamBuilder<A>
where
    A: Encode + EncodedSize,
{
    pub fn add(&mut self, name: &str, record: A) -> TypeIndex {
        let size = u16::default_encoded_size(()) + record.encoded_size(());
        self.offset += align_to(size, RECORD_ALIGNMENT);
        self.records.push(record);
        self.hashes.push(hash_v1(name.as_bytes()) % HASH_BUCKET_NUMBER);

        let index = TypeIndex::try_from(self.index).unwrap();
        self.index += 1;
        index
    }

    fn commit<S>(self, sink: &mut S, allocator: &mut StreamAllocator) -> Result<MsfStreamLayout>
    where
        S: io::Write + io::Seek,
    {
        let mut writer = DefaultMsfStreamWriter::new(sink)?;
        let hash = TypeHash {
            hash_values: self.hashes,
            index_offsets: vec![],
            hash_adjusters: Table::default(),
        };
        let hash_layout = hash.write(&mut writer)?;
        let hash_stream = allocator.allocate(writer.finish()?);
        let last_index = TypeIndex::try_from(FIRST_NON_BUILTIN_TYPE + self.records.len() as u32).unwrap();

        let mut writer = DefaultMsfStreamWriter::new(sink)?;
        let header = TypeStreamHeader::new(last_index, self.offset as u32, hash_stream, hash_layout);
        header.encode((), &mut writer)?;
        for typ in self.records {
            PrefixedRecord(typ).encode((), &mut writer)?;
        }
        Ok(writer.finish()?)
    }
}

impl<A> Default for TypeStreamBuilder<A> {
    fn default() -> Self {
        Self {
            records: vec![],
            hashes: vec![],
            offset: 0,
            index: FIRST_NON_BUILTIN_TYPE,
        }
    }
}

#[derive(Debug)]
pub struct PublicsBuilder<'a> {
    symbols: &'a mut SymbolsBuilder,
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
    publics: BTreeMap<SymbolOffset, Public>,
    globals: BTreeMap<SymbolOffset, SymbolRecord>,
    offset: u32,
}

impl SymbolsBuilder {
    pub fn add(&mut self, symbol: SymbolRecord) -> SymbolOffset {
        let offset = SymbolOffset(self.offset);
        let size = u16::default_encoded_size(()) + symbol.encoded_size(());
        self.offset += align_to(size, RECORD_ALIGNMENT) as u32;
        self.globals.insert(offset, symbol);
        offset
    }

    fn commit<S>(self, sink: &mut S, allocator: &mut StreamAllocator) -> Result<SymbolStreams>
    where
        S: io::Write + io::Seek,
    {
        let mut globals_stream = DefaultMsfStreamWriter::new(sink)?;
        Globals::from_symbols(&self.globals).write_with_header(&mut globals_stream)?;
        let globals = allocator.allocate(globals_stream.finish()?);

        let mut publics_stream = DefaultMsfStreamWriter::new(sink)?;
        Publics::from_publics(&self.publics).write_with_header(&mut publics_stream)?;
        let publics = allocator.allocate(publics_stream.finish()?);

        let mut syms_stream = DefaultMsfStreamWriter::new(sink)?;
        for (_, sym) in self.publics {
            PrefixedRecord(SymbolRecord::Public32(sym)).encode((), &mut syms_stream)?;
        }
        for (_, sym) in self.globals {
            PrefixedRecord(sym).encode((), &mut syms_stream)?;
        }
        let symbols = allocator.allocate(syms_stream.finish()?);

        Ok(SymbolStreams {
            publics,
            globals,
            symbols,
        })
    }
}

#[derive(Debug)]
pub struct ModuleBuilder {
    name: String,
    obj_file_name: String,
    section_contrib: SectionContrib,
    symbols: Vec<SymbolRecord>,
    debug_entries: Vec<DebugSubsectionEntry>,
    source_files: Vec<String>,
    offset: u32,
}

impl ModuleBuilder {
    pub fn new(name: String, obj_file_name: String, section_contrib: SectionContrib) -> Self {
        Self {
            name,
            obj_file_name,
            section_contrib,
            symbols: vec![],
            debug_entries: vec![],
            source_files: vec![],
            offset: 0,
        }
    }

    pub fn add_symbol(&mut self, symbol: SymbolRecord) -> SymbolOffset {
        let offset = SymbolOffset(self.offset);
        let size = u16::default_encoded_size(()) + symbol.encoded_size(());
        self.offset += align_to(size, RECORD_ALIGNMENT) as u32;
        self.symbols.push(symbol);
        offset
    }

    pub fn add_debug_entry(&mut self, entry: DebugSubsectionEntry) -> &mut Self {
        self.debug_entries.push(entry);
        self
    }

    pub fn add_source_file(&mut self, file: String) -> &mut Self {
        self.source_files.push(file);
        self
    }

    fn commit<S>(self, sink: &mut S, allocator: &mut StreamAllocator) -> Result<(DbiModule, Vec<String>)>
    where
        S: io::Write + io::Seek,
    {
        let mut dbg_stream = DefaultMsfStreamWriter::new(sink)?;
        let layout = Module::new(self.symbols, self.debug_entries).write(&mut dbg_stream)?;
        let debug_info_stream = allocator.allocate(dbg_stream.finish()?);

        let header = ModuleInfoHeader {
            module: 0,
            section_contrib: self.section_contrib,
            flags: ModuleInfoFlags::new(),
            type_server_index: 0,
            debug_info_stream,
            layout,
            num_files: self.source_files.len() as u16,
            pad1: Default::default(),
            file_names_offs: 0,
            src_file_name_ni: 0,
            pdb_file_path_ni: 0,
        };

        let res = DbiModule {
            header,
            module_name: StrBuf::new(self.name),
            obj_file_name: StrBuf::new(self.obj_file_name),
        };
        Ok((res, self.source_files))
    }
}

struct SymbolStreams {
    publics: StreamIndex,
    globals: StreamIndex,
    symbols: StreamIndex,
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

    fn block_count(&self) -> usize {
        self.streams.iter().map(|layout| layout.blocks.len()).sum()
    }
}

impl Default for StreamAllocator {
    fn default() -> Self {
        let mut streams = Vec::with_capacity(Self::BUILTIN_STREAM_COUNT);
        streams.resize_with(Self::BUILTIN_STREAM_COUNT, MsfStreamLayout::default);
        Self { streams }
    }
}
