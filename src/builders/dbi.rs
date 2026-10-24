use std::io::{self, Write};

use declio::{Encode, EncodedSize};

use super::{ModuleBuilder, PublicsBuilder, StreamAllocator, SymbolsBuilder};
use crate::dbi::*;
use crate::msf::DefaultMsfStreamWriter;
use crate::result::Result;
use crate::strings::StringsBuilder;
use crate::{MsfStreamLayout, StreamIndex, codecs, constants};

/// Builds DBI metadata and its module, symbol-index, and section-header streams.
///
/// The DBI header uses the AMD64 machine type. Section maps, contributions, and
/// symbol addresses are caller-supplied and are not reconciled automatically.
/// Module, section-map, and file counts must fit the DBI `u16` fields; these
/// limits are not checked before writing.
#[derive(Debug, Default)]
pub struct DbiBuilder {
    pub(super) age: u32,
    symbols: SymbolsBuilder,
    modules: Vec<ModuleBuilder>,
    section_entries: Vec<SectionMapEntry>,
    section_headers: Vec<SectionHeader>,
    names: StringsBuilder,
    debug_streams: Vec<StreamIndex>,
}

impl DbiBuilder {
    /// Returns the public-symbol builder; finish it to add global records.
    ///
    /// Add all publics before any globals so shared-stream offsets remain valid.
    pub fn symbols(&mut self) -> PublicsBuilder<'_> {
        PublicsBuilder {
            symbols: &mut self.symbols,
        }
    }

    /// Appends a module in DBI order; its MSF stream index is assigned at commit.
    ///
    /// Module references in symbol records must be supplied by the caller.
    pub fn add_module(&mut self, module: ModuleBuilder) -> &mut Self {
        self.modules.push(module);
        self
    }

    /// Appends a logical section-map entry without creating a section header.
    pub fn add_section_entry(&mut self, section: SectionMapEntry) -> &mut Self {
        self.section_entries.push(section);
        self
    }

    /// Appends a PE/COFF section header in section-number order.
    ///
    /// A separate section-header stream is emitted only when headers are present.
    pub fn add_section_header(&mut self, section: SectionHeader) -> &mut Self {
        self.section_headers.push(section);
        self
    }

    pub(super) fn commit<S>(
        mut self,
        sink: &mut S,
        allocator: &mut StreamAllocator,
    ) -> Result<MsfStreamLayout>
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

        let mut section_contribs = Vec::with_capacity(modules.len());
        for module in self.modules {
            section_contribs.push(module.section_contrib.clone());
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
        self.debug_streams.push(StreamIndex(u16::MAX)); // token_rid_map
        self.debug_streams.push(StreamIndex(u16::MAX)); // xdata
        self.debug_streams.push(StreamIndex(u16::MAX)); // pdata
        self.debug_streams.push(StreamIndex(u16::MAX)); // framedata
        self.debug_streams.push(StreamIndex(u16::MAX)); // original_section_headers

        let modi_stream_size =
            codecs::padded_rem_list::encoded_size(&modules, constants::ENDIANESS) as u32;

        let header = DbiHeader {
            signature: DbiSignature,
            version: DbiVersion::V70,
            age: self.age,
            global_symbol_stream_index: streams.globals,
            build_number: BuildNumber::new()
                .with_major(14)
                .with_minor(11)
                .with_is_new_format(true),
            public_symbol_stream_index: streams.publics,
            dll_version: 0,
            sym_record_stream_index: streams.symbols,
            rbld: 0,
            modi_stream_size,
            sec_contr_stream_size: u16::default_encoded_size(()) as u32 * 2
                + section_contribs.encoded_size(()) as u32,
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
        // header size
        header.encode((), &mut stream)?;

        // modi_stream_size
        codecs::padded_rem_list::encode(&modules, constants::ENDIANESS, &mut stream)?;

        // sec_contr_stream_size
        SectionContribVersion::Ver60.encode(constants::ENDIANESS, &mut stream)?;
        section_contribs.encode(((),), &mut stream)?;

        // section_map_size
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
