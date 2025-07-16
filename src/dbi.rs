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
    codecs, constants, impl_bitfield_codecs, impl_bitfield_specifier_codecs, BufMsfStream, StreamIndex
};

magic_bytes! {
    #[derive(Debug)]
    pub DbiSignature(&(-1i32).to_le_bytes());
}

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
    pub fn read<R: io::Read>(mut reader: R) -> Result<Self> {
        let header = DbiHeader::decode((), &mut reader)?;
        if !matches!(header.version, DbiVersion::V70 | DbiVersion::V110) {
            return Err(Error::UnsupportedFeature("DBI version older than V70"));
        }

        let mut modi_stream = reader.by_ref().take(header.modi_stream_size.into());
        let modules = codecs::padded_rem_list::decode((), &mut modi_stream)?;

        let mut sect_contr_stream = reader.by_ref().take(header.sec_contr_stream_size.into());
        let mut section_contribs = vec![];
        let version = SectionContribVersion::decode(constants::ENDIANESS, &mut sect_contr_stream)?;

        while sect_contr_stream.limit() > 0 {
            section_contribs.push(SectionContrib::decode((), &mut sect_contr_stream)?);
            if version == SectionContribVersion::V2 {
                // isect coff
                u32::decode(constants::ENDIANESS, &mut sect_contr_stream)?;
            }
        }

        let mut sec_map_stream = reader.by_ref().take(header.section_map_size.into());
        let sec_map = SectionMap::decode((), &mut sec_map_stream)?;
        debug_assert_eq!(sec_map_stream.limit(), 0);

        let mut file_info_stream = reader.by_ref().take(header.file_info_size.into());
        let file_info = FileInfo::decode((), &mut file_info_stream)?;

        let mut file_names = vec![];
        file_info_stream.read_to_end(&mut file_names)?;
        debug_assert_eq!(file_info_stream.limit(), 0);

        let type_server_stream: Bytes = Decode::decode(Len(header.type_server_size as usize), &mut reader)?;

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

#[derive(Debug, Encode, Decode)]
#[declio(ctx_is = "constants::ENDIANESS")]
pub struct DbiHeader {
    pub signature: DbiSignature,
    pub version: DbiVersion,
    pub age: u32,
    pub global_symbol_stream_index: StreamIndex,
    pub build_number: BuildNumber,
    pub public_symbol_stream_index: StreamIndex,
    pub dll_version: u16,
    pub sym_record_stream_index: StreamIndex,
    pub rbld: u16,
    pub modi_stream_size: u32,
    pub sec_contr_stream_size: u32,
    pub section_map_size: u32,
    pub file_info_size: u32,
    pub type_server_size: u32,
    pub mfc_type_server_index: u32,
    pub optional_db_header_size: u32,
    pub ec_stream_size: u32,
    pub flags: DbiFlags,
    pub machine_type: MachineType,
    #[declio(with = "codecs::byte_array")]
    pub reserved: [u8; 4],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, BitfieldSpecifier)]
#[bits = 32]
pub enum DbiVersion {
    Vc41 = 930803,
    V50 = 19960307,
    V60 = 19970606,
    V70 = 19990903,
    V110 = 20091201,
}

impl_bitfield_specifier_codecs!(DbiVersion);

#[derive(Debug, Clone, Copy, PartialEq, Eq, BitfieldSpecifier)]
#[bits = 32]
#[repr(u32)]
pub enum SectionContribVersion {
    Ver60 = 0xeffe0000 + 19970605,
    V2 = 0xeffe0000 + 20140516,
}

impl_bitfield_specifier_codecs!(SectionContribVersion);

#[bitfield(bits = 16)]
#[derive(Debug, Clone, Copy)]
pub struct BuildNumber {
    pub minor: B8,
    pub major: B7,
    pub is_new_format: bool,
}

impl_bitfield_codecs!(BuildNumber);

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

#[derive(Debug, Encode, Decode, EncodedSize)]
#[declio(ctx_is = "constants::ENDIANESS")]
pub struct DbiModule {
    pub header: ModuleInfoHeader,
    pub module_name: StrBuf,
    pub obj_file_name: StrBuf,
}

#[derive(Debug, Encode, Decode, EncodedSize)]
#[declio(ctx_is = "constants::ENDIANESS")]
pub struct ModuleInfoHeader {
    pub module: u32,
    pub section_contrib: SectionContrib,
    pub flags: ModuleInfoFlags,
    pub type_server_index: u8,
    pub debug_info_stream: StreamIndex,
    pub layout: ModuleLayout,
    pub num_files: u16,
    pub pad1: [u8; 2],
    pub file_names_offs: u32,
    pub src_file_name_ni: u32,
    pub pdb_file_path_ni: u32,
}

#[bitfield(bits = 8)]
#[derive(Debug, Clone, Copy)]
pub struct ModuleInfoFlags {
    pub is_dirty: bool,
    pub is_ec_enabled: bool,
    #[skip]
    padding: B6,
}

impl_bitfield_codecs!(ModuleInfoFlags);

#[derive(Debug, Encode, Decode, EncodedSize)]
#[declio(ctx_is = "constants::ENDIANESS")]
pub struct SectionContrib {
    pub i_sect: u16,
    pub pad1: [u8; 2],
    pub offset: i32,
    pub size: u32,
    pub characteristics: u32,
    pub i_mod: u16,
    pub pad2: [u8; 2],
    pub data_crc: u32,
    pub reloc_crc: u32,
}

#[derive(Debug, Encode, Decode, EncodedSize)]
#[declio(ctx_is = "constants::ENDIANESS")]
pub struct SectionMap {
    pub sec_count: u16,
    pub sec_count_log: u16,
    #[declio(ctx = "Len(*sec_count as usize)")]
    pub entries: Vec<SectionMapEntry>,
}

#[derive(Debug, Encode, Decode, EncodedSize)]
#[declio(ctx_is = "constants::ENDIANESS")]
pub struct SectionMapEntry {
    pub flags: DescriptorFlags,
    pub logical_overlay: u16,
    pub group: u16,
    pub frame: u16,
    pub sec_name: u16,
    pub class_name: u16,
    pub offset: u32,
    pub sec_byte_length: u32,
}

#[derive(Debug, Encode, Decode, EncodedSize)]
#[declio(ctx_is = "constants::ENDIANESS")]
pub struct FileInfo {
    pub num_modules: u16,
    pub num_source_files: u16,
    #[declio(ctx = "(Len(*num_modules as usize), constants::ENDIANESS)")]
    pub module_indicies: Vec<u16>,
    #[declio(ctx = "(Len(*num_modules as usize), constants::ENDIANESS)")]
    pub module_file_counts: Vec<u16>,
    #[declio(ctx = "(Len(*num_source_files as usize), constants::ENDIANESS)")]
    pub file_name_offsets: Vec<u32>,
}

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

#[derive(Debug, Encode, Decode, EncodedSize)]
#[declio(ctx_is = "constants::ENDIANESS")]
pub struct SectionHeader {
    #[declio(with = "codecs::byte_array")]
    pub name: [u8; 8],
    pub virtual_size: u32,
    pub virtual_address: u32,
    pub size_of_raw_data: u32,
    pub pointer_to_raw_data: u32,
    pub pointer_to_relocations: u32,
    pub pointer_to_line_numbers: u32,
    pub number_of_relocations: u16,
    pub number_of_line_numbers: u16,
    pub characteristics: u32,
}

#[derive(Debug, Getters)]
pub struct SectionHeaderStream {
    headers: Vec<SectionHeader>,
}

impl SectionHeaderStream {
    const ENTRY_SIZE: u32 = 40;

    pub(crate) fn read<R: io::Read + io::Seek>(mut reader: BufMsfStream<R>) -> Result<Self> {
        let count = reader.get_ref().length() / Self::ENTRY_SIZE;
        let records = Decode::decode(Len(count as usize), &mut reader)?;
        debug_assert!(reader.get_ref().is_eof());
        Ok(Self { headers: records })
    }
}

#[derive(Debug, Encode, Decode, EncodedSize)]
#[declio(ctx_is = "constants::ENDIANESS")]
pub struct FpoData {
    pub offset: u32,
    pub size: u32,
    pub num_locals: u32,
    pub num_params: u16,
    pub attributes: u16,
}

#[derive(Debug, Getters)]
pub struct FpoStream {
    records: Vec<FpoData>,
}

impl FpoStream {
    const ENTRY_SIZE: u32 = 16;

    pub(crate) fn read<R: io::Read + io::Seek>(mut reader: BufMsfStream<R>) -> Result<Self> {
        let count = reader.get_ref().length() / Self::ENTRY_SIZE;
        let records = Decode::decode(Len(count as usize), &mut reader)?;
        debug_assert!(reader.get_ref().is_eof());
        Ok(Self { records })
    }
}

#[derive(Debug, Encode, Decode, EncodedSize)]
#[declio(ctx_is = "constants::ENDIANESS")]
pub struct FrameData {
    pub rva_start: u32,
    pub code_size: u32,
    pub local_size: u32,
    pub params_size: u32,
    pub max_stack_size: u32,
    pub frame_func: u32,
    pub prolog_size: u16,
    pub saved_regs_size: u16,
    pub flags: u32,
}

#[derive(Debug, Getters)]
pub struct FrameDataStream {
    frames: Vec<FrameData>,
}

impl FrameDataStream {
    const ENTRY_SIZE: u32 = 32;

    pub(crate) fn read<R: io::Read + io::Seek>(mut reader: BufMsfStream<R>) -> Result<Self> {
        if reader.get_ref().length() % Self::ENTRY_SIZE != 0 {
            // reloc_ptr
            u32::decode(constants::ENDIANESS, &mut reader)?;
        }
        let count = reader.get_ref().length() / Self::ENTRY_SIZE;
        let frames = Decode::decode(Len(count as usize), &mut reader)?;
        debug_assert!(reader.get_ref().is_eof());
        Ok(Self { frames })
    }
}

#[derive(Debug, Clone, Copy, BitfieldSpecifier)]
#[bits = 16]
pub enum MachineType {
    Invalid = 0xffff,
    Unknown = 0x0,
    Am33 = 0x13,
    Amd64 = 0x8664,
    Arm = 0x1C0,
    Arm64 = 0xaa64,
    ArmNT = 0x1C4,
    Ebc = 0xEBC,
    X86 = 0x14C,
    Ia64 = 0x200,
    M32R = 0x9041,
    Mips16 = 0x266,
    MipsFpu = 0x366,
    MipsFpu16 = 0x466,
    PowerPC = 0x1F0,
    PowerPCFP = 0x1F1,
    R4000 = 0x166,
    Sh3 = 0x1A2,
    Sh3Dsp = 0x1A3,
    Sh4 = 0x1A6,
    Sh5 = 0x1A8,
    Thumb = 0x1C2,
    WceMipsV2 = 0x169,
}

impl_bitfield_specifier_codecs!(MachineType);
