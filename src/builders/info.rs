use std::io;

use declio::Encode;

use crate::hash::Table;
use crate::info::{PdbFeature, PdbInfoHeader, PdbVersion};
use crate::msf::DefaultMsfStreamWriter;
use crate::result::Result;
use crate::utils::StrBuf;
use crate::{Guid, MsfStreamLayout, StreamIndex, constants};

/// Builds the PDB Info identity header, an empty named-stream map, and VC140 feature.
///
/// Defaults to signature zero, age one, and an all-zero GUID. No identity is
/// generated automatically; set GUID and age to match an executable when needed.
#[derive(Debug)]
pub struct InfoBuilder {
    signature: u32,
    pub(super) age: u32,
    guid: Guid,
    named_streams: Vec<(StreamIndex, String)>,
}

impl Default for InfoBuilder {
    fn default() -> Self {
        Self {
            signature: 0,
            age: 1,
            guid: Guid::default(),
            named_streams: Vec::default(),
        }
    }
}

impl InfoBuilder {
    /// Sets the legacy timestamp signature, written verbatim (default: zero).
    pub fn signature(&mut self, signature: u32) -> &mut Self {
        self.signature = signature;
        self
    }

    /// Sets the age in both Info and DBI (default: one); commit does not increment it.
    pub fn age(&mut self, age: u32) -> &mut Self {
        self.age = age;
        self
    }

    /// Sets the GUID used with age to match a PDB to an executable.
    pub fn guid(&mut self, guid: Guid) -> &mut Self {
        self.guid = guid;
        self
    }

    pub(super) fn commit<S>(self, sink: &mut S) -> Result<MsfStreamLayout>
    where
        S: io::Write + io::Seek,
    {
        let mut writer = DefaultMsfStreamWriter::new(sink)?;

        let header = PdbInfoHeader {
            version: PdbVersion::Vc70,
            signature: self.signature,
            age: self.age,
            guid: self.guid,
        };
        header.encode((), &mut writer)?;
        let buffer_size: u32 = self
            .named_streams
            .iter()
            .map(|(_, s)| s.len() as u32 + 1)
            .sum();
        buffer_size.encode(constants::ENDIANESS, &mut writer)?;

        let mut offsets = Vec::with_capacity(self.named_streams.len());
        let mut offset = 0;
        for (index, name) in self.named_streams {
            offset += name.len() as u32 + 1;
            offsets.push((u16::from(index).into(), offset));

            StrBuf::new(name).encode((), &mut writer)?;
        }
        Table::from_sized_iter(offsets.into_iter()).encode((), &mut writer)?;

        // enables the IPI stream
        PdbFeature::Vc140.encode((), &mut writer)?;

        Ok(writer.finish()?)
    }
}
