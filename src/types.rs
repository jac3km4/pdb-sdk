use std::fmt::Debug;
use std::io;

use declio::ctx::Len;
use declio::{Decode, Encode, EncodedSize, magic_bytes};
use derive_getters::Getters;
use modular_bitfield::Specifier;

use crate::codeview::PrefixedRecord;
use crate::codeview::types::{IdRecord, TypeRecord};
use crate::hash::{Table, hash_v1};
use crate::msf::MsfStreamWriter;
use crate::result::{Error, Result};
use crate::{IdIndex, StreamIndex, TypeIndex, constants, impl_bitfield_specifier_codecs};

pub(crate) const HASH_BUCKET_NUMBER: u32 = 0x40000u32 - 1;
pub(crate) const FIRST_NON_BUILTIN_TYPE: u32 = 0x1000;

magic_bytes! {
    #[derive(Debug)]
    pub HeaderSize(&TypeStreamHeader::BYTE_SIZE.to_le_bytes());
    #[derive(Debug)]
    pub HashKeySize(&4u32.to_le_bytes());
}

/// The PDB TPI Stream, containing CodeView Type Records.
pub type TpiStream = TypeStream<TypeRecord>;
/// The PDB IPI Stream, containing CodeView ID Records.
pub type IpiStream = TypeStream<IdRecord>;

/// Represents the TPI or IPI stream, containing information about types or IDs.
/// It contains a header followed by a list of CodeView records.
#[derive(Debug, Getters)]
pub struct TypeStream<A> {
    header: TypeStreamHeader,
    records: Vec<A>,
}

impl<A> TypeStream<A> {
    pub(crate) fn read<R>(mut input: R) -> Result<Self>
    where
        A: Decode,
        R: io::Read,
    {
        let header = TypeStreamHeader::decode((), &mut input)?;
        if !matches!(header.version, TypeStreamVersion::V80) {
            return Err(Error::UnsupportedFeature("TPI version older than V80"));
        }

        let first_index = u32::from(header.type_index_begin);
        let expected_count = u32::from(header.type_index_end)
            .checked_sub(first_index)
            .ok_or_else(|| {
                Error::EncodingFailed(declio::Error::new("type stream: reversed index range"))
            })?;
        let mut records: Vec<A> = vec![];
        let total = u64::from(header.type_record_bytes);
        let mut input = input.take(total);
        let mut consumed: u64 = 0;
        while input.limit() != 0 {
            if records.len() as u64 >= u64::from(expected_count) {
                return Err(Error::EncodingFailed(declio::Error::new(
                    "type stream: record count exceeds index range",
                )));
            }
            // The count check above bounds this addition by type_index_end.
            let type_index = first_index + records.len() as u32;
            let (record, size) = PrefixedRecord::<A>::decode_with_size(&mut input).map_err(|e| {
                Error::EncodingFailed(declio::Error::new(format!(
                    "type stream: TI=0x{type_index:x} (record #{}) at byte offset {consumed}: {e}",
                    records.len()
                )))
            })?;
            consumed += size;
            records.push(record.into_inner());
        }

        if records.len() as u64 != u64::from(expected_count) {
            return Err(Error::EncodingFailed(declio::Error::new(format!(
                "type stream: expected {expected_count} records, decoded {}",
                records.len()
            ))));
        }
        Ok(TypeStream { header, records })
    }
}

impl TypeStream<TypeRecord> {
    /// Retrieves a type or ID record by its index.
    pub fn record(&self, idx: TypeIndex) -> Option<&TypeRecord> {
        let offset = u32::from(idx).checked_sub(u32::from(self.header.type_index_begin))?;
        self.records.get(usize::try_from(offset).ok()?)
    }
}

impl TypeStream<IdRecord> {
    /// Retrieves a type or ID record by its index.
    pub fn record(&self, idx: IdIndex) -> Option<&IdRecord> {
        let offset = u32::from(idx).checked_sub(u32::from(self.header.type_index_begin))?;
        self.records.get(usize::try_from(offset).ok()?)
    }
}

/// The header of a TPI or IPI stream.
#[derive(Debug, Encode, Decode)]
#[declio(ctx_is = "constants::ENDIANESS")]
pub struct TypeStreamHeader {
    /// The version of the TPI/IPI stream.
    pub version: TypeStreamVersion,
    /// Size of the header.
    pub header_size: HeaderSize,
    /// The numeric value of the type index representing the first type record in the stream.
    pub type_index_begin: TypeIndex,
    /// One greater than the numeric value of the type index representing the last type record.
    pub type_index_end: TypeIndex,
    /// The number of bytes of type record data following the header.
    pub type_record_bytes: u32,

    /// The index of a stream which contains a list of hashes for every type record.
    pub hash_stream_index: StreamIndex,
    /// Presumably the index of a stream which contains a separate hash table.
    pub hash_aux_stream_index: StreamIndex,
    /// The size of a hash value (usually 4 bytes).
    pub hash_key_size: HashKeySize,
    /// The number of hash buckets used to bucket type-record name hashes.
    pub num_hash_buckets: u32,

    /// Offsets and lengths within the hash stream.
    pub hash_layout: TypeHashLayout,
}

impl TypeStreamHeader {
    const BYTE_SIZE: u32 = 56;

    pub(crate) fn new(
        last_type: TypeIndex,
        type_bytes: u32,
        hash_stream: StreamIndex,
        hash_layout: TypeHashLayout,
    ) -> Self {
        Self {
            version: TypeStreamVersion::V80,
            header_size: HeaderSize,
            type_index_begin: TypeIndex::try_from(FIRST_NON_BUILTIN_TYPE).unwrap(),
            type_index_end: last_type,
            type_record_bytes: type_bytes,
            hash_stream_index: hash_stream,
            hash_aux_stream_index: StreamIndex(u16::MAX),
            hash_key_size: HashKeySize,
            num_hash_buckets: HASH_BUCKET_NUMBER,
            hash_layout,
        }
    }
}

/// The layout of the TPI/IPI Hash Stream.
#[derive(Debug, Encode, Decode)]
pub struct TypeHashLayout {
    /// Hash values embedded buffer.
    hash_values: EmbeddedBuf,
    /// Index offsets embedded buffer.
    index_offsets: EmbeddedBuf,
    /// Hash adjusters embedded buffer.
    hash_adjusters: EmbeddedBuf,
}

/// The TPI/IPI Hash Stream, providing accelerated O(log(n)) lookup by type index.
#[derive(Debug)]
pub struct TypeHash {
    pub(crate) hash_values: Vec<u32>,
    pub(crate) index_offsets: Vec<IndexOffset>,
    pub(crate) hash_adjusters: Table,
    pub(crate) bucket_count: u32,
}

impl TypeHash {
    /// Gets the type index for a given name using the hash stream.
    pub fn get_index(&self, name: &str) -> Option<TypeIndex> {
        let hash = hash_v1(name.as_bytes()).checked_rem(self.bucket_count)?;
        let i = self.hash_values.iter().position(|&i| i == hash)?;
        TypeIndex::try_from(FIRST_NON_BUILTIN_TYPE.checked_add(u32::try_from(i).ok()?)?).ok()
    }

    pub(crate) fn read<R>(mut input: R, layout: &TypeHashLayout, bucket_count: u32) -> Result<Self>
    where
        R: io::Read + io::Seek,
    {
        if bucket_count == 0 {
            return Err(Error::EncodingFailed(declio::Error::new(
                "type hash: zero buckets",
            )));
        }
        let stream_len = input.seek(io::SeekFrom::End(0))?;
        // Validate every region before decoding any length-driven collection.
        layout.hash_values.validate(stream_len, 4, 4)?;
        layout.index_offsets.validate(stream_len, 4, 8)?;
        layout.hash_adjusters.validate(stream_len, 1, 1)?;

        let hash_values = if layout.hash_values.length > 0 {
            input.seek(io::SeekFrom::Start(layout.hash_values.offset.into()))?;
            Decode::decode(
                (
                    Len((layout.hash_values.length / 4) as usize),
                    constants::ENDIANESS,
                ),
                &mut input,
            )?
        } else {
            vec![]
        };
        let index_offsets = if layout.index_offsets.length > 0 {
            input.seek(io::SeekFrom::Start(layout.index_offsets.offset.into()))?;
            Decode::decode(
                (
                    Len((layout.index_offsets.length / 8) as usize),
                    constants::ENDIANESS,
                ),
                &mut input,
            )?
        } else {
            vec![]
        };
        let hash_adjusters = if layout.hash_adjusters.length > 0 {
            input.seek(io::SeekFrom::Start(layout.hash_adjusters.offset.into()))?;
            Decode::decode(
                (),
                &mut io::Read::take(&mut input, u64::from(layout.hash_adjusters.length)),
            )?
        } else {
            Table::default()
        };
        let this = Self {
            hash_values,
            index_offsets,
            hash_adjusters,
            bucket_count,
        };
        Ok(this)
    }

    pub(crate) fn write<W, const N: u32>(
        &self,
        output: &mut MsfStreamWriter<'_, W, N>,
    ) -> Result<TypeHashLayout>
    where
        W: io::Write + io::Seek,
    {
        let hash_values =
            EmbeddedBuf::from_encoded(&self.hash_values, (constants::ENDIANESS,), output)?;
        let index_offsets =
            EmbeddedBuf::from_encoded(&self.index_offsets, (constants::ENDIANESS,), output)?;
        let hash_adjusters = EmbeddedBuf::from_encoded(&self.hash_adjusters, (), output)?;
        let res = TypeHashLayout {
            hash_values,
            index_offsets,
            hash_adjusters,
        };
        Ok(res)
    }
}

#[derive(Debug, Encode, Decode)]
#[declio(ctx_is = "constants::ENDIANESS")]
pub(crate) struct IndexOffset {
    pub(crate) index: TypeIndex,
    pub(crate) offset: u32,
}

#[derive(Debug, Encode, Decode)]
#[declio(ctx_is = "constants::ENDIANESS")]
struct EmbeddedBuf {
    offset: u32,
    length: u32,
}

impl EmbeddedBuf {
    fn validate(&self, stream_len: u64, offset_alignment: u32, item_size: u32) -> Result<()> {
        // Empty buffers can carry sentinel offsets (including u32::MAX).
        if self.length == 0 {
            return Ok(());
        }
        if !self.offset.is_multiple_of(offset_alignment) || !self.length.is_multiple_of(item_size) {
            return Err(Error::EncodingFailed(declio::Error::new(
                "type hash: unaligned embedded buffer",
            )));
        }
        let end = u64::from(self.offset).checked_add(u64::from(self.length));
        if end.is_none_or(|end| end > stream_len) {
            return Err(Error::EncodingFailed(declio::Error::new(
                "type hash: embedded buffer exceeds stream length",
            )));
        }
        Ok(())
    }

    fn from_encoded<A, W, Ctx, const N: u32>(
        value: &A,
        ctx: Ctx,
        out: &mut MsfStreamWriter<'_, W, N>,
    ) -> Result<Self>
    where
        A: Encode<Ctx>,
        W: io::Write + io::Seek,
    {
        let offset = out.position();
        value.encode(ctx, out)?;
        let length = out.position() - offset;
        Ok(Self { offset, length })
    }
}

/// The version of the TPI/IPI stream.
#[derive(Debug, Clone, Copy, Specifier)]
#[bits = 32]
pub enum TypeStreamVersion {
    V40 = 19_950_410,
    V41 = 19_951_122,
    V50 = 19_961_031,
    V70 = 19_990_903,
    V80 = 20_040_203,
}

impl_bitfield_specifier_codecs!(TypeStreamVersion);

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, PartialEq, Decode)]
    #[declio(ctx_is = "constants::ENDIANESS")]
    struct Kind(u16);

    fn header(begin: u32, end: u32, bytes: u32) -> TypeStreamHeader {
        let mut header = TypeStreamHeader::new(
            TypeIndex::try_from(end).unwrap(),
            bytes,
            StreamIndex(u16::MAX),
            TypeHashLayout {
                hash_values: EmbeddedBuf {
                    offset: 0,
                    length: 0,
                },
                index_offsets: EmbeddedBuf {
                    offset: 0,
                    length: 0,
                },
                hash_adjusters: EmbeddedBuf {
                    offset: 0,
                    length: 0,
                },
            },
        );
        header.type_index_begin = TypeIndex::try_from(begin).unwrap();
        header
    }

    fn stream_bytes(begin: u32, end: u32, byte_count: u32, body: &[u8]) -> Vec<u8> {
        let mut bytes = vec![];
        header(begin, end, byte_count)
            .encode((), &mut bytes)
            .unwrap();
        bytes.extend_from_slice(body);
        bytes
    }

    fn hash_layout() -> TypeHashLayout {
        TypeHashLayout {
            hash_values: EmbeddedBuf {
                offset: 0,
                length: 4,
            },
            index_offsets: EmbeddedBuf {
                offset: 4,
                length: 8,
            },
            hash_adjusters: EmbeddedBuf {
                offset: 12,
                length: 16,
            },
        }
    }

    // Invalid metadata must be rejected before any decoder can allocate from it.
    struct NoRead(io::Cursor<Vec<u8>>);

    impl io::Read for NoRead {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            panic!("read before validating all type hash metadata");
        }
    }

    impl io::Seek for NoRead {
        fn seek(&mut self, pos: io::SeekFrom) -> io::Result<u64> {
            self.0.seek(pos)
        }
    }

    #[test]
    fn rejects_malformed_type_hash_metadata_before_reading() {
        let layout = hash_layout();
        assert!(TypeHash::read(NoRead(io::Cursor::new(vec![0; 28])), &layout, 0).is_err());

        // (buffer index, offset, length): alignment, range, truncation, and
        // offset + length overflow in u32 arithmetic, for every embedded region.
        for (region, offset, length) in [
            (0, 1, 4),
            (0, 0, 1),
            (0, 0, 3),
            (0, 0, 5),
            (1, 5, 8),
            (1, 4, 4),
            (1, 4, 7),
            (1, 4, 9),
            (0, 28, 4),
            (1, 28, 8),
            (2, 28, 16),
            (0, 32, 4),
            (1, 32, 8),
            (2, 32, 16),
            (0, 24, 8),
            (1, 24, 8),
            (2, 24, 8),
            (0, 0, u32::MAX - 3),
            (1, 4, u32::MAX - 7),
            (2, 12, u32::MAX),
            (0, u32::MAX - 3, 8),
            (1, u32::MAX - 3, 8),
            (2, u32::MAX, 16),
        ] {
            let mut layout = hash_layout();
            let buffers = [
                &mut layout.hash_values,
                &mut layout.index_offsets,
                &mut layout.hash_adjusters,
            ];
            *buffers.into_iter().nth(region).unwrap() = EmbeddedBuf { offset, length };
            assert!(
                TypeHash::read(NoRead(io::Cursor::new(vec![0; 28])), &layout, 1).is_err(),
                "region {region}, offset {offset}, length {length}"
            );
        }
        for len in 0..28 {
            assert!(
                TypeHash::read(NoRead(io::Cursor::new(vec![0; len])), &layout, 1).is_err(),
                "truncated stream length {len}"
            );
        }
    }

    #[test]
    fn reads_type_hash_regions_and_ignores_empty_sentinel_offsets() {
        let name = "Sample";
        let bucket_count = 17;
        let value = hash_v1(name.as_bytes()) % bucket_count;
        let mut bytes = value.to_le_bytes().to_vec();
        bytes.extend_from_slice(&FIRST_NON_BUILTIN_TYPE.to_le_bytes());
        bytes.extend_from_slice(&0x1234u32.to_le_bytes());
        Table::default().encode((), &mut bytes).unwrap();
        assert_eq!(bytes.len(), 28);
        let mut input = io::Cursor::new(&bytes);
        let hash = TypeHash::read(&mut input, &hash_layout(), bucket_count).unwrap();
        assert_eq!(hash.hash_values, [value]);
        assert_eq!(hash.index_offsets.len(), 1);
        assert_eq!(
            u32::from(hash.index_offsets[0].index),
            FIRST_NON_BUILTIN_TYPE
        );
        assert_eq!(hash.index_offsets[0].offset, 0x1234);
        assert!(hash.hash_adjusters.entries().is_empty());
        assert_eq!(
            u32::from(hash.get_index(name).unwrap()),
            FIRST_NON_BUILTIN_TYPE
        );
        assert_eq!(input.position(), 28);

        // Keep each region nonempty in turn, ignoring the other sentinel offsets.
        for active in 0..3 {
            let mut layout = hash_layout();
            for (i, buffer) in [
                &mut layout.hash_values,
                &mut layout.index_offsets,
                &mut layout.hash_adjusters,
            ]
            .into_iter()
            .enumerate()
            {
                if i != active {
                    *buffer = EmbeddedBuf {
                        offset: u32::MAX,
                        length: 0,
                    };
                }
            }
            let mut input = io::Cursor::new(&bytes);
            let hash = TypeHash::read(&mut input, &layout, bucket_count).unwrap();
            assert_eq!(hash.hash_values.len(), usize::from(active == 0));
            assert_eq!(hash.index_offsets.len(), usize::from(active == 1));
            assert_eq!(input.position(), [4, 12, 28][active]);
        }
        let empty = EmbeddedBuf {
            offset: u32::MAX,
            length: 0,
        };
        let layout = TypeHashLayout {
            hash_values: EmbeddedBuf { ..empty },
            index_offsets: EmbeddedBuf { ..empty },
            hash_adjusters: empty,
        };
        let hash = TypeHash::read(NoRead(io::Cursor::new(vec![])), &layout, 1).unwrap();
        assert!(hash.hash_values.is_empty());
        assert!(hash.index_offsets.is_empty());
        assert!(hash.hash_adjusters.entries().is_empty());
        assert!(hash.get_index(name).is_none());
        let zero_buckets = TypeHash {
            bucket_count: 0,
            ..hash
        };
        assert!(zero_buckets.get_index(name).is_none());
    }

    #[test]
    fn rejects_hash_adjusters_crossing_declared_boundary() {
        let mut bytes = vec![0; 12];
        bytes[4..8].copy_from_slice(&FIRST_NON_BUILTIN_TYPE.to_le_bytes());
        Table::default().encode((), &mut bytes).unwrap();
        for length in 1..16 {
            let mut layout = hash_layout();
            layout.hash_adjusters.length = length;
            let mut input = io::Cursor::new(&bytes);
            assert!(TypeHash::read(&mut input, &layout, 1).is_err());
            assert_eq!(input.position(), 12 + u64::from(length));
        }
    }

    #[test]
    fn reads_exact_record_region_and_leaves_trailing_bytes() {
        let bytes = stream_bytes(
            0x2000,
            0x2002,
            8,
            &[2, 0, 0x34, 0x12, 2, 0, 0x78, 0x56, 0xaa],
        );
        let mut input = io::Cursor::new(bytes);
        let stream = TypeStream::<Kind>::read(&mut input).unwrap();
        assert_eq!(stream.records, [Kind(0x1234), Kind(0x5678)]);
        assert_eq!(input.position(), u64::from(TypeStreamHeader::BYTE_SIZE) + 8);
        let empty = stream_bytes(0x2000, 0x2000, 0, &[0xaa]);
        let mut input = io::Cursor::new(empty);
        assert!(
            TypeStream::<Kind>::read(&mut input)
                .unwrap()
                .records
                .is_empty()
        );
        assert_eq!(input.position(), u64::from(TypeStreamHeader::BYTE_SIZE));
    }

    #[test]
    fn rejects_record_crossing_byte_boundary() {
        for byte_count in [1, 2, 3] {
            // Physical bytes exist beyond the declared region, but must not be read.
            let bytes = stream_bytes(0x2000, 0x2001, byte_count, &[2, 0, 0x34, 0x12, 0xaa]);
            let mut input = io::Cursor::new(bytes);
            assert!(TypeStream::<Kind>::read(&mut input).is_err());
            assert_eq!(
                input.position(),
                u64::from(TypeStreamHeader::BYTE_SIZE) + u64::from(byte_count)
            );
        }
    }

    #[test]
    fn rejects_reversed_ranges_and_count_mismatches() {
        for (begin, end, byte_count, body) in [
            (0x2001, 0x2000, 0, &[][..]),
            (0x2000, 0x2001, 0, &[][..]),
            (0x2000, 0x2002, 4, &[2, 0, 1, 0][..]),
            (0x2000, 0x2000, 4, &[2, 0, 1, 0][..]),
            (0x2000, 0x2001, 8, &[2, 0, 1, 0, 2, 0, 2, 0][..]),
            (0x2000, 0x2001, 4, &[2, 0, 1][..]),
            (0x2000, 0x2001, 2, &[0, 0][..]),
        ] {
            let bytes = stream_bytes(begin, end, byte_count, body);
            assert!(TypeStream::<Kind>::read(bytes.as_slice()).is_err());
        }
    }

    #[test]
    fn lookups_use_header_begin_and_check_bounds() {
        let types = TypeStream {
            header: header(0x2000, 0x2001, 0),
            records: vec![TypeRecord::FieldList { fields: vec![] }],
        };
        let ids = TypeStream {
            header: header(0x2000, 0x2001, 0),
            records: vec![IdRecord::StringList {
                count: 0,
                strings: vec![],
            }],
        };
        for raw in [1, 0x1000, 0x1fff, 0x2000, 0x2001, u32::MAX] {
            assert_eq!(
                types.record(TypeIndex::try_from(raw).unwrap()).is_some(),
                raw == 0x2000
            );
            assert_eq!(
                ids.record(IdIndex::try_from(raw).unwrap()).is_some(),
                raw == 0x2000
            );
        }
    }
}
