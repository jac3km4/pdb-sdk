use std::io;

use declio::EncodedSize;

use super::StreamAllocator;
use crate::SymbolOffset;
use crate::codeview::RECORD_ALIGNMENT;
use crate::codeview::symbols::SymbolRecord;
use crate::dbi::{DbiModule, ModuleInfoFlags, ModuleInfoHeader, SectionContrib};
use crate::module::{DebugSubsectionEntry, Module};
use crate::msf::DefaultMsfStreamWriter;
use crate::result::Result;
use crate::utils::{StrBuf, align_to};

#[derive(Debug)]
pub struct ModuleBuilder {
    name: String,
    obj_file_name: String,
    pub(super) section_contrib: SectionContrib,
    pub symbols: Vec<SymbolRecord>,
    debug_entries: Vec<DebugSubsectionEntry>,
    pub(super) source_files: Vec<String>,
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
            offset: 4, // sizeof(DebugSectionSignature)
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

    pub(super) fn commit<S>(
        self,
        sink: &mut S,
        allocator: &mut StreamAllocator,
    ) -> Result<(DbiModule, Vec<String>)>
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
