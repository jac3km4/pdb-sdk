use std::io;

use declio::Encode;

use crate::hash::{Table, hash_v1};
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
        let mut name_buffer = Vec::with_capacity(buffer_size as usize);
        for (index, name) in self.named_streams {
            offsets.push((name_buffer.len() as u32, u32::from(u16::from(index))));
            StrBuf::new(name).encode((), &mut name_buffer)?;
        }
        io::Write::write_all(&mut writer, &name_buffer)?;
        Table::from_sized_iter(offsets.into_iter(), |offset| {
            let bytes = &name_buffer[offset as usize..];
            let end = bytes.iter().position(|&b| b == 0).unwrap();
            u32::from(hash_v1(&bytes[..end]) as u16)
        })
        .encode((), &mut writer)?;

        // enables the IPI stream
        PdbFeature::Vc140.encode((), &mut writer)?;

        Ok(writer.finish()?)
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Cursor, Seek};

    use declio::Decode;

    use super::*;
    use crate::info::{NamedStreams, PdbInfo};
    use crate::msf::{DEFAULT_BLOCK_SIZE, MsfStream};

    #[test]
    fn nonempty_named_stream_map_uses_start_offsets_and_stream_indices() {
        let names: Vec<_> = (0..1000)
            .map(|i| format!("/stream{i}"))
            .filter(|name| (hash_v1(name.as_bytes()) as u16) % 8 == 7)
            .take(6)
            .collect();
        assert_eq!(names.len(), 6);
        let builder = InfoBuilder {
            named_streams: names
                .iter()
                .enumerate()
                .map(|(i, name)| (StreamIndex(42 + i as u16), name.clone()))
                .collect(),
            ..InfoBuilder::default()
        };
        let mut sink = Cursor::new(Vec::new());
        let layout = builder.commit(&mut sink).unwrap();
        let mut stream = MsfStream::new(&mut sink, &layout, DEFAULT_BLOCK_SIZE);
        PdbInfoHeader::decode((), &mut stream).unwrap();
        // Check the name offsets and stream indices in the serialized entries.
        let size = u32::decode(constants::ENDIANESS, &mut stream).unwrap();
        let mut buffer = vec![0; size as usize];
        io::Read::read_exact(&mut stream, &mut buffer).unwrap();
        let count = u32::decode(constants::ENDIANESS, &mut stream).unwrap();
        let cap = u32::decode(constants::ENDIANESS, &mut stream).unwrap();
        assert_eq!((count, cap), (6, 8));
        let words = u32::decode(constants::ENDIANESS, &mut stream).unwrap();
        assert_eq!(words, 1);
        let present = u32::decode(constants::ENDIANESS, &mut stream).unwrap();
        assert_eq!(present, 0b1001_1111);
        assert_eq!(u32::decode(constants::ENDIANESS, &mut stream).unwrap(), 0);
        let entries: Vec<_> = (0..count)
            .map(|_| {
                let key = u32::decode(constants::ENDIANESS, &mut stream).unwrap();
                let val = u32::decode(constants::ENDIANESS, &mut stream).unwrap();
                (key, val)
            })
            .collect();
        let mut offset = 0u32;
        for (i, name) in names.iter().enumerate() {
            let mut slot = u32::from(hash_v1(name.as_bytes()) as u16) % cap;
            loop {
                assert_ne!(present & (1 << slot), 0);
                let packed = (present & ((1u32 << slot) - 1)).count_ones() as usize;
                let (key, val) = entries[packed];
                if key == offset {
                    assert_eq!(val, 42 + i as u32);
                    assert_eq!(
                        &buffer[key as usize..key as usize + name.len()],
                        name.as_bytes()
                    );
                    break;
                }
                slot = (slot + 1) % cap;
            }
            offset += name.len() as u32 + 1;
        }
        assert_eq!(
            PdbFeature::decode((), &mut stream).unwrap(),
            PdbFeature::Vc140
        );
        assert_eq!(
            stream.stream_position().unwrap(),
            u64::from(layout.byte_size)
        );
        stream.rewind().unwrap();
        let info = PdbInfo::read(&mut stream).unwrap();
        for (i, name) in names.iter().enumerate() {
            assert_eq!(
                info.named_streams().get(name).map(|index| index.0),
                Some(42 + i as u16)
            );
        }
        assert_eq!(info.features(), &[PdbFeature::Vc140]);
        stream.rewind().unwrap();
        PdbInfoHeader::decode((), &mut stream).unwrap();
        let map = NamedStreams::decode((), &mut stream).unwrap();
        assert_eq!(map.iter().count(), 6);
    }
}
