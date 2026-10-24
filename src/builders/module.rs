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

/// Builds one module's DBI entry, symbols, and C13 debug subsections.
///
/// Source-file names are DBI metadata; line tables and checksum subsections must
/// be supplied separately. Symbol scope links and type references are not fixed up.
#[derive(Debug)]
pub struct ModuleBuilder {
    name: String,
    obj_file_name: String,
    pub(super) section_contrib: SectionContrib,
    /// Symbols in emission order. Direct edits do not update offset bookkeeping;
    /// changing encoded sizes invalidates offsets returned by [`Self::add_symbol`].
    pub symbols: Vec<SymbolRecord>,
    debug_entries: Vec<DebugSubsectionEntry>,
    pub(super) source_files: Vec<String>,
    offset: u32,
}

impl ModuleBuilder {
    /// Creates a module with DBI display/object-file names and one contribution.
    ///
    /// The contribution's section and module references are used as supplied.
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

    /// Appends a symbol and returns its length-prefix offset in the module stream.
    ///
    /// The first offset is 4, after the signature; records are aligned to 4 bytes.
    pub fn add_symbol(&mut self, symbol: SymbolRecord) -> SymbolOffset {
        let offset = SymbolOffset(self.offset);
        let size = u16::default_encoded_size(()) + symbol.encoded_size(());
        self.offset += align_to(size, RECORD_ALIGNMENT) as u32;
        self.symbols.push(symbol);
        offset
    }

    /// Appends a C13 subsection without validating its payload or cross-references.
    pub fn add_debug_entry(&mut self, entry: DebugSubsectionEntry) -> &mut Self {
        self.debug_entries.push(entry);
        self
    }

    /// Appends a filename to DBI file info; does not read the file or add line data.
    ///
    /// Names are not deduplicated. The per-module file count must fit in `u16`.
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
