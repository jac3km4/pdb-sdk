//! DBI module, source-file, section, and auxiliary debug-stream metadata.
//!
//! See LLVM's [DBI guide](https://llvm.org/docs/PDB/DbiStream.html) for the
//! substream layout and optional debug-stream slots.

use std::io::{self, Read};

use declio::ctx::Len;
use declio::{Decode, Encode, EncodedSize, magic_bytes};
use derive_getters::Getters;
use modular_bitfield::bitfield;
use modular_bitfield::prelude::*;

use crate::module::ModuleLayout;
use crate::result::{Error, Result};
use crate::strings::Strings;
use crate::utils::StrBuf;
use crate::{
    BufMsfStream, StreamIndex, codecs, constants, impl_bitfield_codecs,
    impl_bitfield_specifier_codecs,
};

magic_bytes! {
    #[derive(Debug)]
    pub DbiSignature(&(-1i32).to_le_bytes());
}

/// DBI (stream 3): build metadata, modules, section contributions, and source files.
///
/// References identify module streams, global/public indexes, shared symbol
/// records, and optional debug streams. Reading DBI does not read those streams.
/// Type-server data is retained as bytes rather than resolved.
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
    /// Decodes a DBI stream with version V70 or V110.
    pub fn read<R: io::Read>(mut reader: R) -> Result<Self> {
        let header = DbiHeader::decode((), &mut reader)?;
        if !matches!(header.version, DbiVersion::V70 | DbiVersion::V110) {
            return Err(Error::UnsupportedFeature("DBI version older than V70"));
        }

        let mut modi_stream = reader.by_ref().take(header.modi_stream_size.into());
        let modules = codecs::padded_rem_list::decode((), &mut modi_stream)?;
        require_consumed(modi_stream.limit())?;

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
        require_consumed(sec_map_stream.limit())?;

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
        read_incrementally(&mut file_info_stream, &mut file_names)?;
        require_consumed(file_info_stream.limit())?;

        let type_server_stream = read_substream(&mut reader, header.type_server_size)?;
        let ec_bytes = read_substream(&mut reader, header.ec_stream_size)?;
        let ec_stream = if ec_bytes.len() >= 4 && ec_bytes[0..4] == 0xEFFE_EFFE_u32.to_le_bytes() {
            let mut bytes = ec_bytes.as_slice();
            let strings = Strings::decode((), &mut bytes)?;
            require_consumed(bytes.len() as u64)?;
            strings
        } else {
            Strings::empty()
        };

        if !header.optional_db_header_size.is_multiple_of(2) {
            return Err(declio::Error::new("DBI debug header has a partial stream index").into());
        }
        let dbg_streams = read_records(&mut reader, header.optional_db_header_size / 2)?;

        let dbi = DbiStream {
            header,
            modules,
            section_contribs,
            sec_map,
            file_info,
            file_names,
            type_server_stream,
            ec_stream,
            dbg_streams,
        };

        Ok(dbi)
    }
}

// Read into a fixed scratch buffer first: neither `Read` nor a declared DBI size
// guarantees the bytes exist, so allocation must follow successful reads.
fn read_incrementally<R: Read>(reader: &mut R, bytes: &mut Vec<u8>) -> io::Result<()> {
    let mut scratch = [0; 8192];
    loop {
        match reader.read(&mut scratch) {
            Ok(0) => return Ok(()),
            Ok(count) => bytes.extend_from_slice(&scratch[..count]),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }
}

fn require_consumed(remaining: u64) -> Result<()> {
    if remaining != 0 {
        return Err(declio::Error::new("DBI substream size does not match its contents").into());
    }
    Ok(())
}

fn read_substream<R: Read>(reader: &mut R, size: u32) -> Result<Vec<u8>> {
    let mut stream = reader.take(u64::from(size));
    let mut bytes = Vec::new();
    read_incrementally(&mut stream, &mut bytes)?;
    require_consumed(stream.limit())?;
    Ok(bytes)
}

fn read_records<T: Decode, R: Read>(reader: &mut R, count: u32) -> Result<Vec<T>> {
    let mut records = Vec::new();
    for _ in 0..count {
        records.push(T::decode((), reader)?);
    }
    Ok(records)
}

// Unlike a count-sized allocation, this also bounds memory use on truncated
// generic readers whose declared record count cannot be checked up front.
mod incremental_list {
    use super::*;

    pub fn decode<T: Decode<Ctx>, Ctx: Copy, R: Read>(
        (Len(count), ctx): (Len, Ctx),
        reader: &mut R,
    ) -> std::result::Result<Vec<T>, declio::Error> {
        let mut records = Vec::new();
        for _ in 0..count {
            records.push(T::decode(ctx, reader)?);
        }
        Ok(records)
    }

    pub fn encode<T: Encode<Ctx>, Ctx: Copy, W: io::Write>(
        records: &[T],
        (_, ctx): (Len, Ctx),
        writer: &mut W,
    ) -> std::result::Result<(), declio::Error> {
        for record in records {
            record.encode(ctx, writer)?;
        }
        Ok(())
    }

    pub fn encoded_size<T: EncodedSize<Ctx>, Ctx: Copy>(
        records: &[T],
        (_, ctx): (Len, Ctx),
    ) -> usize {
        records.iter().map(|record| record.encoded_size(ctx)).sum()
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
    /// Index of the global-symbol hash index, not the symbol record stream.
    pub global_symbol_stream_index: StreamIndex,
    /// A bitfield containing the major and minor version number of the toolchain.
    pub build_number: BuildNumber,
    /// Index of the public-symbol hash index and address/thunk maps.
    pub public_symbol_stream_index: StreamIndex,
    /// The version number of mspdbXXXX.dll used to produce this PDB.
    pub dll_version: u16,
    /// Shared symbol record stream referenced by global/public indexes.
    /// Module-local symbol records are stored in separate module streams.
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
    /// Byte length of the optional debug-header substream (an array of stream indices).
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
    /// Module symbol/line stream index, or `0xffff` if no debug stream is present.
    pub debug_info_stream: StreamIndex,
    /// Byte sizes of the symbol, C11, and C13 regions within the module stream.
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
    #[declio(with = "incremental_list", ctx = "(Len(*sec_count as usize), ())")]
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

/// Source-file contributions grouped by module.
///
/// Filename offsets refer to [`DbiStream::file_names`], not the `/names` stream.
/// The offset array's true count is the sum of module counts, not the legacy
/// 16-bit `num_source_files` field.
#[derive(Debug, Encode, Decode, EncodedSize)]
#[declio(ctx_is = "constants::ENDIANESS")]
pub struct FileInfo {
    /// The number of modules for which source file information is contained.
    pub num_modules: u16,
    /// Legacy 16-bit source-file count; may not reflect the full contribution count.
    pub num_source_files: u16,
    /// Array of module indices.
    #[declio(
        with = "incremental_list",
        ctx = "(Len(*num_modules as usize), constants::ENDIANESS)"
    )]
    pub module_indicies: Vec<u16>,
    /// Array of integers, containing the number of source files contributing to each module.
    #[declio(
        with = "incremental_list",
        ctx = "(Len(*num_modules as usize), constants::ENDIANESS)"
    )]
    pub module_file_counts: Vec<u16>,
    /// Byte offsets into the DBI filename buffer, pointing to NUL-terminated names.
    #[declio(
        with = "incremental_list",
        ctx = "(Len(module_file_counts.iter().map(|&count| usize::from(count)).sum()), constants::ENDIANESS)"
    )]
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
    /// Relative virtual address (RVA) of the section in the image.
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
        let size = reader.get_ref().length();
        if !size.is_multiple_of(Self::ENTRY_SIZE) {
            return Err(declio::Error::new("partial section-header record").into());
        }
        let records = read_records(&mut reader, size / Self::ENTRY_SIZE)?;
        Ok(Self { headers: records })
    }
}

/// FPO Data record.
#[derive(Debug, Encode, Decode, EncodedSize)]
#[declio(ctx_is = "constants::ENDIANESS")]
pub struct FpoData {
    /// Function start RVA.
    pub offset: u32,
    /// Size of the function.
    pub size: u32,
    /// Local stack storage size in 4-byte units, not a variable count.
    pub num_locals: u32,
    /// Parameter stack storage size in 4-byte units, not a parameter count.
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
        let size = reader.get_ref().length();
        if !size.is_multiple_of(Self::ENTRY_SIZE) {
            return Err(declio::Error::new("partial FPO record").into());
        }
        let records = read_records(&mut reader, size / Self::ENTRY_SIZE)?;
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
    /// Offset of the frame-program string in the PDB `/names` table.
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
        let size = reader.get_ref().length();
        match size % Self::ENTRY_SIZE {
            0 => (),
            4 => {
                // Optional relocation pointer precedes the frame records.
                u32::decode(constants::ENDIANESS, &mut reader)?;
            }
            _ => return Err(declio::Error::new("partial frame-data record").into()),
        }
        let frames = read_records(&mut reader, size / Self::ENTRY_SIZE)?;
        Ok(Self { frames })
    }
}

#[cfg(test)]
mod tests {
    use std::io::{BufReader, Cursor};

    use super::*;
    use crate::msf::{BlockIndex, MsfStream, MsfStreamLayout};

    fn empty_header() -> DbiHeader {
        let mut bytes = [0; 64];
        bytes[..4].copy_from_slice(&(-1i32).to_le_bytes());
        bytes[4..8].copy_from_slice(&(DbiVersion::V70 as u32).to_le_bytes());
        DbiHeader::decode((), &mut bytes.as_slice()).unwrap()
    }

    fn encode_stream(header: &DbiHeader, payload: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::new();
        header.encode((), &mut bytes).unwrap();
        bytes.extend_from_slice(payload);
        bytes
    }

    // This reader has no Seek/length API and refuses oversized read requests.
    struct ShortReader<'a>(&'a [u8]);

    impl Read for ShortReader<'_> {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            assert!(buffer.len() <= 8192);
            self.0.read(buffer)
        }
    }

    #[test]
    fn huge_declared_substreams_on_short_generic_readers_return_errors() {
        for field in 0..7 {
            let mut header = empty_header();
            let size = match field {
                0 => &mut header.modi_stream_size,
                1 => &mut header.sec_contr_stream_size,
                2 => &mut header.section_map_size,
                3 => &mut header.file_info_size,
                4 => &mut header.type_server_size,
                5 => &mut header.ec_stream_size,
                _ => &mut header.optional_db_header_size,
            };
            *size = u32::MAX - 1;
            let bytes = encode_stream(&header, &[]);
            assert!(
                DbiStream::read(ShortReader(&bytes)).is_err(),
                "field {field}"
            );
        }
    }

    #[test]
    fn substream_bounds_are_enforced_without_consuming_the_next_stream() {
        // A section map must consume exactly its declared region.
        let mut header = empty_header();
        header.section_map_size = 5;
        let bytes = encode_stream(&header, &[0; 7]);
        let mut reader = Cursor::new(bytes);
        assert!(DbiStream::read(&mut reader).is_err());
        assert_eq!(reader.position(), 68);

        // A module/file-name region that ends early must not masquerade as EOF.
        for field in 0..2 {
            let mut header = empty_header();
            if field == 0 {
                header.modi_stream_size = 4;
            } else {
                header.file_info_size = 8;
            }
            assert!(DbiStream::read(encode_stream(&header, &[0; 4]).as_slice()).is_err());
        }

        // Odd debug-header sizes must not silently discard their final byte.
        let mut header = empty_header();
        header.optional_db_header_size = 3;
        assert!(DbiStream::read(encode_stream(&header, &[0; 3]).as_slice()).is_err());

        // Partial contribution records must stay inside the declared substream.
        header = empty_header();
        header.sec_contr_stream_size = 5;
        let mut payload = Vec::new();
        SectionContribVersion::Ver60
            .encode(constants::ENDIANESS, &mut payload)
            .unwrap();
        payload.extend_from_slice(&[0; 32]);
        let mut reader = Cursor::new(encode_stream(&header, &payload));
        assert!(DbiStream::read(&mut reader).is_err());
        assert_eq!(reader.position(), 69);
    }

    #[test]
    fn file_info_uses_module_sum_even_when_legacy_count_wraps() {
        let info = FileInfo {
            num_modules: 2,
            num_source_files: 0,
            module_indicies: vec![0, 1],
            module_file_counts: vec![u16::MAX, 1],
            file_name_offsets: (0..=u32::from(u16::MAX)).collect(),
        };
        let mut bytes = Vec::new();
        info.encode((), &mut bytes).unwrap();
        bytes.extend_from_slice(b"names\0");
        let mut reader = bytes.as_slice();
        let decoded = FileInfo::decode((), &mut reader).unwrap();
        assert_eq!(decoded.file_name_offsets, info.file_name_offsets);
        assert_eq!(reader, b"names\0");

        // Even the maximum possible offset count must not be allocated up front.
        let mut bytes = vec![0xff; 4 + usize::from(u16::MAX) * 4];
        bytes[2..4].fill(0);
        assert!(FileInfo::decode((), &mut ShortReader(&bytes)).is_err());
    }

    #[test]
    fn auxiliary_streams_validate_record_sizes_and_decode_values() {
        for size in 0..=80u32 {
            let mut bytes = vec![0; size as usize];
            let layout = MsfStreamLayout::new(vec![BlockIndex(0)], size);
            let make_reader =
                |bytes| BufReader::new(MsfStream::new(Cursor::new(bytes), &layout, 4096));
            assert_eq!(
                SectionHeaderStream::read(make_reader(bytes.clone())).is_ok(),
                size % 40 == 0
            );
            assert_eq!(
                FpoStream::read(make_reader(bytes.clone())).is_ok(),
                size % 16 == 0
            );
            let frames = FrameDataStream::read(make_reader(bytes.clone()));
            assert_eq!(frames.is_ok(), matches!(size % 32, 0 | 4), "size {size}");
            if size == 32 || size == 36 {
                let start = (size % 32) as usize;
                bytes[start..start + 4].copy_from_slice(&123u32.to_le_bytes());
                let mut source = Cursor::new(bytes);
                let reader = BufReader::new(MsfStream::new(&mut source, &layout, 4096));
                let frames = FrameDataStream::read(reader).unwrap();
                assert_eq!(frames.frames[0].rva_start, 123);
                assert_eq!(source.position(), u64::from(size));
            }
        }
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
