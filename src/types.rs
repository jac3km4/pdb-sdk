use std::fmt::Debug;
use std::io::{self, Read};

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
    #[derive(Debug)]
    pub HashBucketNumber(&HASH_BUCKET_NUMBER.to_le_bytes());
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

        let mut records: Vec<A> = vec![];
        let mut type_record_stream = input.by_ref().take(header.type_record_bytes.into());
        while type_record_stream.limit() > 0 {
            let record = PrefixedRecord::decode(&mut type_record_stream)?;
            records.push(record.into_inner());
        }

        Ok(TypeStream { header, records })
    }
}

impl TypeStream<TypeRecord> {
    /// Retrieves a type or ID record by its index.
    pub fn record(&self, idx: TypeIndex) -> Option<&TypeRecord> {
        self.records
            .get((u32::from(idx) - FIRST_NON_BUILTIN_TYPE) as usize)
    }
}

impl TypeStream<IdRecord> {
    /// Retrieves a type or ID record by its index.
    pub fn record(&self, idx: IdIndex) -> Option<&IdRecord> {
        self.records
            .get((u32::from(idx) - FIRST_NON_BUILTIN_TYPE) as usize)
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
    /// The number of buckets used to generate the hash values in the hash streams.
    pub num_hash_buckets: HashBucketNumber,

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
            num_hash_buckets: HashBucketNumber,
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
}

impl TypeHash {
    /// Gets the type index for a given name using the hash stream.
    pub fn get_index(&self, name: &str) -> Option<TypeIndex> {
        let hash = hash_v1(name.as_bytes()) % HASH_BUCKET_NUMBER;
        let i = self.hash_values.iter().position(|&i| i == hash)?;
        TypeIndex::try_from(FIRST_NON_BUILTIN_TYPE + i as u32).ok()
    }

    pub(crate) fn read<R>(mut input: R, layout: &TypeHashLayout) -> Result<Self>
    where
        R: io::Read + io::Seek,
    {
        input.seek(io::SeekFrom::Start(layout.hash_values.offset.into()))?;
        let num_hash_values = layout.hash_values.length / 4;
        let hash_values = Decode::decode(
            (Len(num_hash_values as usize), constants::ENDIANESS),
            &mut input,
        )?;
        input.seek(io::SeekFrom::Start(layout.index_offsets.offset.into()))?;
        let num_index_offsets = layout.index_offsets.length / 8;
        let index_offsets = Decode::decode(
            (Len(num_index_offsets as usize), constants::ENDIANESS),
            &mut input,
        )?;
        input.seek(io::SeekFrom::Start(layout.hash_adjusters.offset.into()))?;
        let hash_adjusters = Decode::decode((), &mut input)?;
        let this = Self {
            hash_values,
            index_offsets,
            hash_adjusters,
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
