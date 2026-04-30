use std::{fmt, io};

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
    /// The version of the PDB stream. Typically VC70.
    pub version: PdbVersion,
    /// A 32-bit time-stamp generated with a call to time(). Often ignored in favor of Guid.
    pub signature: u32,
    /// The number of times the PDB file has been written.
    pub age: u32,
    /// A 128-bit identifier guaranteed to be unique across space and time.
    pub guid: Guid,
}

/// A serialized hash table mapping stream names to stream indices.
/// Consulting this is often the only way to discover a named stream's index.
#[derive(Encode, Decode)]
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

impl fmt::Debug for NamedStreams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list()
            .entries(self.iter().map(|(k, v)| (k, v.0)))
            .finish()
    }
}

/// The version of the PDB stream (e.g. VC70).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Specifier)]
#[bits = 32]
pub enum PdbVersion {
    /// Version VC2 (19941610).
    Vc2 = 19_941_610,
    /// Version VC4 (19950623).
    Vc4 = 19_950_623,
    /// Version VC41 (19950814).
    Vc41 = 19_950_814,
    /// Version VC50 (19960307).
    Vc50 = 19_960_307,
    /// Version VC98 (19970604).
    Vc98 = 19_970_604,
    /// Version VC70Dep (19990604).
    Vc70Dep = 19_990_604,
    /// Version VC70 (20000404). The standard observed version.
    Vc70 = 20_000_404,
    /// Version VC80 (20030901).
    Vc80 = 20_030_901,
    /// Version VC110 (20091201).
    Vc110 = 20_091_201,
    /// Version VC140 (20140508).
    Vc140 = 20_140_508,
}

impl_bitfield_specifier_codecs!(PdbVersion);

/// PDB Feature Codes specifying additional features, like minimal debug info or presence of an IPI stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Specifier)]
#[bits = 32]
pub enum PdbFeature {
    /// No features.
    None = 0,
    /// No other features flags are present. PDB contains an IPI Stream.
    Vc110 = 20_091_201,
    /// Other feature flags may be present. PDB contains an IPI Stream.
    Vc140 = 20_140_508,
    /// Presumably duplicate types can appear in the TPI Stream.
    NoTypeMerge = 0x4D54_4F4E,
    /// Program was linked with /DEBUG:FASTLINK. No TPI/IPI stream; all type info is in the original object files.
    MinimalDebugInfo = 0x494E_494D,
}

impl_bitfield_specifier_codecs!(PdbFeature);
