use std::io;

use declio::util::Bytes;
use declio::{Decode, Encode, EncodedSize};
use derive_getters::Getters;
use modular_bitfield::Specifier;

use crate::hash::Table;
use crate::result::{Error, Result};
use crate::{codecs, constants, impl_bitfield_specifier_codecs, Guid, StreamIndex};

const SUPPORTED_VERSIOMS: &[PdbVersion] = &[
    PdbVersion::Vc70,
    PdbVersion::Vc80,
    PdbVersion::Vc110,
    PdbVersion::Vc140,
];

/// The PDB Info Stream (aka the PDB Stream).
/// It contains basic file information, the named stream map, and features to match the PDB to its executable.
#[derive(Debug, Getters)]
pub struct PdbInfo {
    header: PdbInfoHeader,
    named_streams: NamedStreams,
    features: Vec<PdbFeature>,
}

impl PdbInfo {
    /// Reads the PDB Info Stream from a reader.
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

/// The fixed-size header of the PDB Info Stream.
#[derive(Debug, Encode, Decode)]
#[declio(ctx_is = "constants::ENDIANESS")]
pub struct PdbInfoHeader {
    pub version: PdbVersion,
    pub signature: u32,
    pub age: u32,
    pub guid: Guid,
}

/// A serialized hash table mapping stream names to stream indices.
/// Consulting this is often the only way to discover a named stream's index.
#[derive(Debug, Encode, Decode)]
#[declio(ctx_is = "constants::ENDIANESS")]
pub struct NamedStreams {
    #[declio(via = "Bytes<'_, u32>")]
    name_buffer: Vec<u8>,
    offset_index_map: Table,
}

impl NamedStreams {
    /// Iterates over the named streams.
    pub fn iter(&self) -> impl Iterator<Item = (&str, StreamIndex)> {
        self.offset_index_map.entries().iter().filter_map(|kv| {
            let v = &self.name_buffer[kv.key as usize..].split(|&n| n == 0).next()?;
            let str = std::str::from_utf8(v).ok()?;
            Some((str, StreamIndex(kv.val as u16)))
        })
    }

    /// Gets the stream index for a given stream name.
    pub fn get(&self, name: &str) -> Option<StreamIndex> {
        self.iter().find(|(k, _)| k == &name).map(|(_, v)| v)
    }
}

/// The version of the PDB stream (e.g. VC70).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Specifier)]
#[bits = 32]
pub enum PdbVersion {
    Vc2 = 19_941_610,
    Vc4 = 19_950_623,
    Vc41 = 19_950_814,
    Vc50 = 19_960_307,
    Vc98 = 19_970_604,
    Vc70Dep = 19_990_604,
    Vc70 = 20_000_404,
    Vc80 = 20_030_901,
    Vc110 = 20_091_201,
    Vc140 = 20_140_508,
}

impl_bitfield_specifier_codecs!(PdbVersion);

/// PDB Feature Codes specifying additional features, like minimal debug info or presence of an IPI stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Specifier)]
#[bits = 32]
pub enum PdbFeature {
    None = 0,
    Vc110 = 20_091_201,
    Vc140 = 20_140_508,
    NoTypeMerge = 0x4D54_4F4E,
    MinimalDebugInfo = 0x494E_494D,
}

impl_bitfield_specifier_codecs!(PdbFeature);
