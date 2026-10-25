//! PDB identity, named-stream discovery, and feature signatures (stream 1).
//!
//! See LLVM's [Info stream guide](https://llvm.org/docs/PDB/PdbStream.html).

use std::{fmt, io};

use declio::{Decode, Encode, EncodedSize};
use derive_getters::Getters;
use modular_bitfield::Specifier;

use crate::hash::Table;
use crate::result::{Error, Result};
use crate::{Guid, StreamIndex, codecs, constants, impl_bitfield_specifier_codecs};

const SUPPORTED_VERSIOMS: &[PdbVersion] = &[
    PdbVersion::Vc70,
    PdbVersion::Vc80,
    PdbVersion::Vc110,
    PdbVersion::Vc140,
];

/// PDB identity, named-stream map, and trailing feature signatures.
///
/// For an RSDS executable debug record, match both GUID and age. Feature
/// signatures describe format capabilities; they are not identity fields.
#[derive(Debug, Getters)]
pub struct PdbInfo {
    header: PdbInfoHeader,
    named_streams: NamedStreams,
    features: Vec<PdbFeature>,
}

impl PdbInfo {
    /// Decodes an Info stream with version VC70, VC80, VC110, or VC140.
    pub fn read<R: io::Read>(mut reader: R) -> Result<Self> {
        let header = PdbInfoHeader::decode((), &mut reader)?;
        if !SUPPORTED_VERSIOMS.contains(&header.version) {
            return Err(Error::UnsupportedFeature("Invalid PDB stream version"));
        }
        let named_streams = NamedStreams::decode((), &mut reader)?;
        let mut features = Vec::new();
        loop {
            let mut bytes = [0; 4];
            match reader.read(&mut bytes[..1]) {
                Ok(0) => break,
                Ok(_) => {}
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error.into()),
            }
            reader.read_exact(&mut bytes[1..])?;
            // Unknown signatures are extensions, not a reason to reject Info.
            if let Ok(feature) = PdbFeature::decode((), &mut bytes.as_slice()) {
                features.push(feature);
                if feature == PdbFeature::Vc110 {
                    break;
                }
            }
        }

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
    /// Legacy signature, often a timestamp; not necessarily a wall-clock time.
    pub signature: u32,
    /// Revision counter used with `guid` to match the executable's debug record.
    pub age: u32,
    /// PDB identifier used with `age` for executable matching.
    pub guid: Guid,
}

/// A serialized hash table mapping stream names to stream indices.
/// Consulting this is often the only way to discover a named stream's index.
#[derive(Encode, Decode)]
#[declio(ctx_is = "constants::ENDIANESS")]
pub struct NamedStreams {
    #[declio(with = "codecs::prefixed_bytes")]
    name_buffer: Vec<u8>,
    offset_index_map: Table,
}

impl NamedStreams {
    /// Iterates over UTF-8 stream names and their MSF indices.
    ///
    /// Invalid offsets, unterminated/non-UTF-8 names, and indices exceeding
    /// `u16` are skipped; fixed-index streams need not appear in this map.
    pub fn iter(&self) -> impl Iterator<Item = (&str, StreamIndex)> {
        self.offset_index_map.entries().iter().filter_map(|kv| {
            let bytes = self.name_buffer.get(kv.key as usize..)?;
            let end = bytes.iter().position(|&b| b == 0)?;
            let name = std::str::from_utf8(&bytes[..end]).ok()?;
            Some((name, StreamIndex(u16::try_from(kv.val).ok()?)))
        })
    }

    /// Finds a stream by an exact, case-sensitive name using a linear scan.
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
    /// `/DEBUG:FASTLINK` marker: type information may require original object files.
    /// This library does not retrieve those external records.
    MinimalDebugInfo = 0x494E_494D,
}

impl_bitfield_specifier_codecs!(PdbFeature);

#[cfg(test)]
mod tests {
    use super::*;

    fn info_bytes(features: &[u32]) -> Vec<u8> {
        let mut bytes = Vec::new();
        PdbInfoHeader {
            version: PdbVersion::Vc70,
            signature: 0,
            age: 1,
            guid: Guid::default(),
        }
        .encode((), &mut bytes)
        .unwrap();
        NamedStreams {
            name_buffer: Vec::new(),
            offset_index_map: Table::default(),
        }
        .encode((), &mut bytes)
        .unwrap();
        for feature in features {
            bytes.extend_from_slice(&feature.to_le_bytes());
        }
        bytes
    }

    #[test]
    fn features_ignore_unknown_signatures_and_stop_at_vc110() {
        let bytes = info_bytes(&[
            0xdead_beef,
            PdbFeature::Vc140 as u32,
            PdbFeature::NoTypeMerge as u32,
        ]);
        assert_eq!(
            PdbInfo::read(bytes.as_slice()).unwrap().features(),
            &[PdbFeature::Vc140, PdbFeature::NoTypeMerge]
        );
        let bytes = info_bytes(&[
            PdbFeature::Vc110 as u32,
            PdbFeature::Vc140 as u32,
            0xdead_beef,
        ]);
        let mut reader = std::io::Cursor::new(&bytes);
        assert_eq!(
            PdbInfo::read(&mut reader).unwrap().features(),
            &[PdbFeature::Vc110]
        );
        assert_eq!(reader.position() as usize, bytes.len() - 8);
    }

    #[test]
    fn truncated_feature_is_an_error() {
        let mut bytes = info_bytes(&[]);
        bytes.push(1);
        assert!(PdbInfo::read(bytes.as_slice()).is_err());
    }

    #[test]
    fn named_streams_reject_untrusted_truncated_extents() {
        assert!(NamedStreams::decode((), &mut u32::MAX.to_le_bytes().as_slice()).is_err());
        // Empty name buffer followed by a table declaring a huge present bitmap.
        let mut bytes = Vec::new();
        for word in [0u32, 0, 8, u32::MAX] {
            bytes.extend_from_slice(&word.to_le_bytes());
        }
        assert!(NamedStreams::decode((), &mut bytes.as_slice()).is_err());
        // Empty bitmaps followed by an impossible packed-entry count.
        bytes.clear();
        for word in [0u32, u32::MAX, u32::MAX, 0, 0] {
            bytes.extend_from_slice(&word.to_le_bytes());
        }
        assert!(NamedStreams::decode((), &mut bytes.as_slice()).is_err());
    }

    #[test]
    fn named_streams_skip_malformed_offsets_names_and_indices() {
        let streams = NamedStreams {
            name_buffer: b"/ok\0\xff\0unterminated".to_vec(),
            offset_index_map: Table::from_sized_iter(
                [(0, 7), (4, 8), (6, 9), (u32::MAX, 10), (1, u32::MAX)].into_iter(),
                |key| key,
            ),
        };
        assert_eq!(
            streams
                .iter()
                .map(|(name, index)| (name, index.0))
                .collect::<Vec<_>>(),
            [("/ok", 7)]
        );
        assert_eq!(streams.get("/ok").map(|index| index.0), Some(7));
        assert!(streams.get("unterminated").is_none());
        assert!(format!("{streams:?}").contains("/ok"));
    }
}
