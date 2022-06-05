use std::io;

use declio::util::Bytes;
use declio::{Decode, Encode, EncodedSize};
use derive_getters::Getters;
use modular_bitfield::BitfieldSpecifier;

use crate::hash::Table;
use crate::result::{Error, Result};
use crate::{codecs, constants, impl_bitfield_specifier_codecs, Guid, StreamIndex};

const SUPPORTED_VERSIOMS: &[PdbVersion] = &[
    PdbVersion::Vc70,
    PdbVersion::Vc80,
    PdbVersion::Vc110,
    PdbVersion::Vc140,
];

#[derive(Debug, Getters)]
pub struct PdbInfo {
    header: PdbInfoHeader,
    named_streams: NamedStreams,
    features: Vec<PdbFeature>,
}

impl PdbInfo {
    pub fn read<R: io::Read>(mut reader: R) -> Result<Self> {
        let header = PdbInfoHeader::decode((), &mut reader)?;
        if !SUPPORTED_VERSIOMS.contains(&header.version) {
            return Err(Error::UnsupportedFeature("Invalid PDB stream version"));
        }
        let named_streams = NamedStreams::decode((), &mut reader)?;
        let features = codecs::padded_rem_list::decode(constants::ENDIANESS, &mut reader)?;

        Ok(Self {
            header,
            named_streams,
            features,
        })
    }
}

#[derive(Debug, Encode, Decode)]
#[declio(ctx_is = "constants::ENDIANESS")]
pub struct PdbInfoHeader {
    pub version: PdbVersion,
    pub signature: u32,
    pub age: u32,
    pub guid: Guid,
}

#[derive(Debug, Encode, Decode)]
#[declio(ctx_is = "constants::ENDIANESS")]
pub struct NamedStreams {
    #[declio(via = "Bytes<u32>")]
    name_buffer: Vec<u8>,
    offset_index_map: Table,
}

impl NamedStreams {
    pub fn iter(&self) -> impl Iterator<Item = (&str, StreamIndex)> {
        self.offset_index_map.entries().iter().filter_map(|kv| {
            let v = &self.name_buffer[kv.key as usize..].split(|&n| n == 0).next()?;
            let str = std::str::from_utf8(v).ok()?;
            Some((str, StreamIndex(kv.val as u16)))
        })
    }

    pub fn get(&self, name: &str) -> Option<StreamIndex> {
        self.iter().find(|(k, _)| k == &name).map(|(_, v)| v)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, BitfieldSpecifier)]
#[bits = 32]
pub enum PdbVersion {
    Vc2 = 19941610,
    Vc4 = 19950623,
    Vc41 = 19950814,
    Vc50 = 19960307,
    Vc98 = 19970604,
    Vc70Dep = 19990604,
    Vc70 = 20000404,
    Vc80 = 20030901,
    Vc110 = 20091201,
    Vc140 = 20140508,
}

impl_bitfield_specifier_codecs!(PdbVersion);

#[derive(Debug, Clone, Copy, PartialEq, Eq, BitfieldSpecifier)]
#[bits = 32]
pub enum PdbFeature {
    None = 0,
    Vc110 = 20091201,
    Vc140 = 20140508,
    NoTypeMerge = 0x4D544F4E,
    MinimalDebugInfo = 0x494E494D,
}

impl_bitfield_specifier_codecs!(PdbFeature);
