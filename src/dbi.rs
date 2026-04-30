use std::io::{self, Read};

use declio::ctx::Len;
use declio::util::Bytes;
use declio::{magic_bytes, Decode, Encode, EncodedSize};
use derive_getters::Getters;
use modular_bitfield::bitfield;
use modular_bitfield::prelude::*;

use crate::module::ModuleLayout;
use crate::result::{Error, Result};
use crate::strings::Strings;
use crate::utils::StrBuf;
use crate::{
    codecs, constants, impl_bitfield_codecs, impl_bitfield_specifier_codecs, BufMsfStream,
    StreamIndex,
};

magic_bytes! {
    #[derive(Debug)]
    pub DbiSignature(&(-1i32).to_le_bytes());
}

/// The Debug Info (DBI) Stream.
/// Contains information about how the program was compiled, the compilands (modules) used to link the program, source files used, and references to other streams with more detailed information.
#[derive(Debug, Getters)]
pub struct DbiStream {
    header: DbiHeader,
    modules: Vec<DbiModule>,
    section_contribs: Vec<SectionContrib>,
    sec_map: SectionMap,
    file_info: FileInfo,
    file_names: Vec<u8>,
    type_server_stream: Vec<u8>,
    ec_stream: Strings,
    dbg_streams: Vec<StreamIndex>,
}

impl DbiStream {
    /// Reads the DBI Stream from a reader.
    pub fn read<R: io::Read>(mut reader: R) -> Result<Self> {
        let header = DbiHeader::decode((), &mut reader)?;
        if !matches!(header.version, DbiVersion::V70 | DbiVersion::V110) {
            return Err(Error::UnsupportedFeature("DBI version older than V70"));
        }

        let mut modi_stream = reader.by_ref().take(header.modi_stream_size.into());
        let modules = codecs::padded_rem_list::decode((), &mut modi_stream)?;

        let mut sect_contr_stream = reader.by_ref().take(header.sec_contr_stream_size.into());
        let mut section_contribs = vec![];
        if sect_contr_stream.limit() > 0 {
            let version =
                SectionContribVersion::decode(constants::ENDIANESS, &mut sect_contr_stream)?;
            while sect_contr_stream.limit() > 0 {
                section_contribs.push(SectionContrib::decode((), &mut sect_contr_stream)?);
                if version == SectionContribVersion::V2 {
                    // isect coff
                    u32::decode(constants::ENDIANESS, &mut sect_contr_stream)?;
                }
            }
        }

        let mut sec_map_stream = reader.by_ref().take(header.section_map_size.into());
        let sec_map = if sec_map_stream.limit() > 0 {
            SectionMap::decode((), &mut sec_map_stream)?
        } else {
            SectionMap {
                sec_count: 0,
                sec_count_log: 0,
                entries: vec![],
            }
        };
        debug_assert_eq!(sec_map_stream.limit(), 0);

        let mut file_info_stream = reader.by_ref().take(header.file_info_size.into());
        let file_info = if file_info_stream.limit() > 0 {
            FileInfo::decode((), &mut file_info_stream)?
        } else {
            FileInfo {
                num_modules: 0,
                num_source_files: 0,
                module_indicies: vec![],
                module_file_counts: vec![],
                file_name_offsets: vec![],
            }
        };

        let mut file_names = vec![];
        file_info_stream.read_to_end(&mut file_names)?;
        debug_assert_eq!(file_info_stream.limit(), 0);

        let type_server_stream: Bytes<'_> =
            Decode::decode(Len(header.type_server_size as usize), &mut reader)?;

        let ec_stream: Strings = Strings::decode((), &mut reader)?;

        let dbg_stream_count = header.optional_db_header_size as usize / 2;
        let dbg_streams: Vec<StreamIndex> = Decode::decode(Len(dbg_stream_count), &mut reader)?;

        let dbi = DbiStream {
            header,
            modules,
            section_contribs,
            sec_map,
            file_info,
            file_names,
            type_server_stream: type_server_stream.into_vec(),
            ec_stream,
            dbg_streams,
        };

        Ok(dbi)
    }
}

/// The fixed-size header of the DBI stream.
#[derive(Debug, Encode, Decode)]
#[declio(ctx_is = "constants::ENDIANESS")]
pub struct DbiHeader {
    /// Version signature, always -1.
    pub signature: DbiSignature,
    /// The version of the DBI stream.
    pub version: DbiVersion,
    /// The number of times the PDB has been written.
    pub age: u32,
    /// The index of the Global Symbol Stream.
    pub global_symbol_stream_index: StreamIndex,
    /// A bitfield containing the major and minor version number of the toolchain.
    pub build_number: BuildNumber,
    /// The index of the Public Symbol Stream.
    pub public_symbol_stream_index: StreamIndex,
    /// The version number of mspdbXXXX.dll used to produce this PDB.
    pub dll_version: u16,
    /// The stream containing all CodeView symbol records used by the program.
    pub sym_record_stream_index: StreamIndex,
    /// Unknown rebuild data.
    pub rbld: u16,
    /// The length of the Module Info Substream.
    pub modi_stream_size: u32,
    /// The length of the Section Contribution Substream.
    pub sec_contr_stream_size: u32,
    /// The length of the Section Map Substream.
    pub section_map_size: u32,
    /// The length of the File Info Substream.
    pub file_info_size: u32,
    /// The length of the Type Server Map Substream.
    pub type_server_size: u32,
    /// The index of the MFC type server in the Type Server Map Substream.
    pub mfc_type_server_index: u32,
    /// The length of the Optional Debug Header Stream.
    pub optional_db_header_size: u32,
    /// The length of the EC Substream.
    pub ec_stream_size: u32,
    /// Various information about how the program was built.
    pub flags: DbiFlags,
    /// The target CPU type.
    pub machine_type: MachineType,
    #[declio(with = "codecs::byte_array")]
    pub reserved: [u8; 4],
}

/// The version of the DBI stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Specifier)]
#[bits = 32]
pub enum DbiVersion {
    /// Version VC41.
    Vc41 = 930_803,
    /// Version V50.
    V50 = 19_960_307,
    /// Version V60.
    V60 = 19_970_606,
    /// Version V70.
    V70 = 19_990_903,
    /// Version V110.
    V110 = 20_091_201,
}

impl_bitfield_specifier_codecs!(DbiVersion);

/// Version of the Section Contribution Substream.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Specifier)]
#[bits = 32]
#[repr(u32)]
pub enum SectionContribVersion {
    /// Version 60.
    Ver60 = 0xeffe_0000 + 19_970_605,
    /// Version V2.
    V2 = 0xeffe_0000 + 20_140_516,
}

impl_bitfield_specifier_codecs!(SectionContribVersion);

/// A bitfield containing values representing the major and minor version number of the toolchain used to build the program.
#[bitfield(bits = 16)]
#[derive(Debug, Clone, Copy)]
pub struct BuildNumber {
    pub minor: B8,
    pub major: B7,
    pub is_new_format: bool,
}

impl_bitfield_codecs!(BuildNumber);

/// A bitfield containing various information about how the program was built.
#[bitfield(bits = 16)]
#[derive(Debug, Clone, Copy)]
pub struct DbiFlags {
    pub is_incrementally_linked: bool,
    pub is_stripped: bool,
    pub has_c_types: bool,
    #[skip]
    padding: B13,
}

impl_bitfield_codecs!(DbiFlags);

/// Describes a single module (e.g. object file) linked into the program.
#[derive(Debug, Encode, Decode, EncodedSize)]
#[declio(ctx_is = "constants::ENDIANESS")]
pub struct DbiModule {
    /// Header of the DBI Module.
    pub header: ModuleInfoHeader,
    /// Name of the module.
    pub module_name: StrBuf,
    /// Object file name.
    pub obj_file_name: StrBuf,
}

/// Header for a DbiModule.
#[derive(Debug, Encode, Decode, EncodedSize)]
#[declio(ctx_is = "constants::ENDIANESS")]
pub struct ModuleInfoHeader {
    /// Unknown. Typically 0.
    pub module: u32,
    /// Describes the properties of the section in the final binary which contain the code and data from this module.
    pub section_contrib: SectionContrib,
    /// Module info flags.
    pub flags: ModuleInfoFlags,
    /// Type Server Index for this module.
    pub type_server_index: u8,
    /// The index of the stream that contains symbol information for this module.
    pub debug_info_stream: StreamIndex,
    /// Sizes of the symbol and line info streams.
    pub layout: ModuleLayout,
    /// The number of source files that contributed to this module during compilation.
    pub num_files: u16,
    pub pad1: [u8; 2],
    /// Unknown offset.
    pub file_names_offs: u32,
    /// The offset in the names buffer of the primary translation unit used to build this module.
    pub src_file_name_ni: u32,
    /// The offset in the names buffer of the PDB file containing this module's symbol information.
    pub pdb_file_path_ni: u32,
}

/// Flags for a DbiModule.
#[bitfield(bits = 8)]
#[derive(Debug, Clone, Copy)]
pub struct ModuleInfoFlags {
    pub is_dirty: bool,
    pub is_ec_enabled: bool,
    #[skip]
    padding: B6,
}

impl_bitfield_codecs!(ModuleInfoFlags);

/// Describes the properties of the section in the final binary which contain the code and data from a module.
#[derive(Debug, Clone, Encode, Decode, EncodedSize)]
#[declio(ctx_is = "constants::ENDIANESS")]
pub struct SectionContrib {
    /// The index of the section.
    pub i_sect: u16,
    pub pad1: [u8; 2],
    /// The offset within the section.
    pub offset: i32,
    /// The size of the contribution.
    pub size: u32,
    /// Corresponds to the Characteristics field of the IMAGE_SECTION_HEADER structure.
    pub characteristics: u32,
    /// The index of the module.
    pub i_mod: u16,
    pub pad2: [u8; 2],
    /// CRC of the data.
    pub data_crc: u32,
    /// CRC of relocations.
    pub reloc_crc: u32,
}

/// The Section Map Substream.
#[derive(Debug, Encode, Decode, EncodedSize)]
#[declio(ctx_is = "constants::ENDIANESS")]
pub struct SectionMap {
    /// Number of segment descriptors.
    pub sec_count: u16,
    /// Number of logical segment descriptors.
    pub sec_count_log: u16,
    /// Array of segment descriptors.
    #[declio(ctx = "Len(*sec_count as usize)")]
    pub entries: Vec<SectionMapEntry>,
}

/// An entry in the Section Map Substream describing a segment descriptor.
#[derive(Debug, Encode, Decode, EncodedSize)]
#[declio(ctx_is = "constants::ENDIANESS")]
pub struct SectionMapEntry {
    /// Descriptor flags.
    pub flags: DescriptorFlags,
    /// Logical overlay number.
    pub logical_overlay: u16,
    /// Group index into descriptor array.
    pub group: u16,
    /// Frame representation (e.g. selector or absolute address).
    pub frame: u16,
    /// Byte index of segment / group name in string table, or 0xFFFF.
    pub sec_name: u16,
    /// Byte index of class in string table, or 0xFFFF.
    pub class_name: u16,
    /// Byte offset of the logical segment within physical segment.
    pub offset: u32,
    /// Byte count of the segment or group.
    pub sec_byte_length: u32,
}

/// The File Info Substream. Defines the mapping from module to the source files that contribute to that module.
#[derive(Debug, Encode, Decode, EncodedSize)]
#[declio(ctx_is = "constants::ENDIANESS")]
pub struct FileInfo {
    /// The number of modules for which source file information is contained.
    pub num_modules: u16,
    /// The number of source files, capped at 64K.
    pub num_source_files: u16,
    /// Array of module indices.
    #[declio(ctx = "(Len(*num_modules as usize), constants::ENDIANESS)")]
    pub module_indicies: Vec<u16>,
    /// Array of integers, containing the number of source files contributing to each module.
    #[declio(ctx = "(Len(*num_modules as usize), constants::ENDIANESS)")]
    pub module_file_counts: Vec<u16>,
    /// Offsets into the string table pointing to null terminated strings.
    #[declio(ctx = "(Len(*num_source_files as usize), constants::ENDIANESS)")]
    pub file_name_offsets: Vec<u32>,
}

/// Flags for a SectionMapEntry.
#[bitfield(bits = 16)]
#[derive(Debug, Clone, Copy)]
pub struct DescriptorFlags {
    pub is_readable: bool,
    pub is_writable: bool,
    pub is_executable: bool,
    pub is_32bit: bool,
    #[skip]
    padding: B4,
    pub is_selector: bool,
    pub is_absolute: bool,
    pub is_group: bool,
    #[skip]
    padding: B5,
}

impl_bitfield_codecs!(DescriptorFlags);

/// A section header from the original executable.
#[derive(Debug, Encode, Decode, EncodedSize)]
#[declio(ctx_is = "constants::ENDIANESS")]
pub struct SectionHeader {
    /// Name of the section.
    #[declio(with = "codecs::byte_array")]
    pub name: [u8; 8],
    /// Virtual size.
    pub virtual_size: u32,
    /// Virtual address.
    pub virtual_address: u32,
    /// Size of raw data.
    pub size_of_raw_data: u32,
    /// Pointer to raw data.
    pub pointer_to_raw_data: u32,
    /// Pointer to relocations.
    pub pointer_to_relocations: u32,
    /// Pointer to line numbers.
    pub pointer_to_line_numbers: u32,
    /// Number of relocations.
    pub number_of_relocations: u16,
    /// Number of line numbers.
    pub number_of_line_numbers: u16,
    /// Section characteristics.
    pub characteristics: u32,
}

/// A dump of all section headers from the original executable.
#[derive(Debug, Getters)]
pub struct SectionHeaderStream {
    headers: Vec<SectionHeader>,
}

impl SectionHeaderStream {
    const ENTRY_SIZE: u32 = 40;

    pub(crate) fn read<R: io::Read + io::Seek>(mut reader: BufMsfStream<'_, R>) -> Result<Self> {
        let count = reader.get_ref().length() / Self::ENTRY_SIZE;
        let records = Decode::decode(Len(count as usize), &mut reader)?;
        debug_assert!(reader.get_ref().is_eof());
        Ok(Self { headers: records })
    }
}

/// FPO Data record.
#[derive(Debug, Encode, Decode, EncodedSize)]
#[declio(ctx_is = "constants::ENDIANESS")]
pub struct FpoData {
    /// Offset of the function.
    pub offset: u32,
    /// Size of the function.
    pub size: u32,
    /// Number of locals.
    pub num_locals: u32,
    /// Number of parameters.
    pub num_params: u16,
    /// Attributes of the function.
    pub attributes: u16,
}

/// An array of FPO_DATA structures. Contains the relocated contents of any .debug$F section from any of the linker inputs.
#[derive(Debug, Getters)]
pub struct FpoStream {
    records: Vec<FpoData>,
}

impl FpoStream {
    const ENTRY_SIZE: u32 = 16;

    pub(crate) fn read<R: io::Read + io::Seek>(mut reader: BufMsfStream<'_, R>) -> Result<Self> {
        let count = reader.get_ref().length() / Self::ENTRY_SIZE;
        let records = Decode::decode(Len(count as usize), &mut reader)?;
        debug_assert!(reader.get_ref().is_eof());
        Ok(Self { records })
    }
}

/// Frame Data record.
#[derive(Debug, Encode, Decode, EncodedSize)]
#[declio(ctx_is = "constants::ENDIANESS")]
pub struct FrameData {
    /// Start relative virtual address.
    pub rva_start: u32,
    /// Code size.
    pub code_size: u32,
    /// Local variables size.
    pub local_size: u32,
    /// Parameters size.
    pub params_size: u32,
    /// Max stack size.
    pub max_stack_size: u32,
    /// Frame function string.
    pub frame_func: u32,
    /// Prolog size.
    pub prolog_size: u16,
    /// Saved registers size.
    pub saved_regs_size: u16,
    /// Frame data flags.
    pub flags: u32,
}

/// A stream containing frame data.
#[derive(Debug, Getters)]
pub struct FrameDataStream {
    frames: Vec<FrameData>,
}

impl FrameDataStream {
    const ENTRY_SIZE: u32 = 32;

    pub(crate) fn read<R: io::Read + io::Seek>(mut reader: BufMsfStream<'_, R>) -> Result<Self> {
        if !reader.get_ref().length().is_multiple_of(Self::ENTRY_SIZE) {
            // reloc_ptr
            u32::decode(constants::ENDIANESS, &mut reader)?;
        }
        let count = reader.get_ref().length() / Self::ENTRY_SIZE;
        let frames = Decode::decode(Len(count as usize), &mut reader)?;
        debug_assert!(reader.get_ref().is_eof());
        Ok(Self { frames })
    }
}

/// The CPU type.
#[derive(Debug, Clone, Copy, Specifier)]
#[bits = 16]
pub enum MachineType {
    /// Invalid machine type.
    Invalid = 0xffff,
    /// Unknown machine type.
    Unknown = 0x0,
    /// Am33 machine type.
    Am33 = 0x13,
    /// Amd64 machine type.
    Amd64 = 0x8664,
    /// Arm machine type.
    Arm = 0x1C0,
    /// Arm64 machine type.
    Arm64 = 0xaa64,
    /// ArmNT machine type.
    ArmNT = 0x1C4,
    /// Ebc machine type.
    Ebc = 0xEBC,
    /// X86 machine type.
    X86 = 0x14C,
    /// Ia64 machine type.
    Ia64 = 0x200,
    /// M32R machine type.
    M32R = 0x9041,
    /// Mips16 machine type.
    Mips16 = 0x266,
    /// MipsFpu machine type.
    MipsFpu = 0x366,
    /// MipsFpu16 machine type.
    MipsFpu16 = 0x466,
    /// PowerPC machine type.
    PowerPC = 0x1F0,
    /// PowerPCFP machine type.
    PowerPCFP = 0x1F1,
    /// R4000 machine type.
    R4000 = 0x166,
    /// Sh3 machine type.
    Sh3 = 0x1A2,
    /// Sh3Dsp machine type.
    Sh3Dsp = 0x1A3,
    /// Sh4 machine type.
    Sh4 = 0x1A6,
    /// Sh5 machine type.
    Sh5 = 0x1A8,
    /// Thumb machine type.
    Thumb = 0x1C2,
    /// WceMipsV2 machine type.
    WceMipsV2 = 0x169,
}

impl_bitfield_specifier_codecs!(MachineType);
