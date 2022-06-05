use std::fmt::Debug;
use std::io::{self, Read};

use declio::ctx::Len;
use declio::{magic_bytes, Decode, Encode, EncodedSize};
use derive_getters::Getters;
use modular_bitfield::BitfieldSpecifier;

use crate::codeview::types::{IdRecord, TypeRecord};
use crate::codeview::PrefixedRecord;
use crate::hash::{hash_v1, Table};
use crate::msf::MsfStreamWriter;
use crate::result::{Error, Result};
use crate::{constants, impl_bitfield_specifier_codecs, IdIndex, StreamIndex, TypeIndex};

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

pub type TpiStream = TypeStream<TypeRecord>;
pub type IpiStream = TypeStream<IdRecord>;

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
    pub fn record(&self, idx: TypeIndex) -> Option<&TypeRecord> {
        self.records
            .get((u32::from(idx) - FIRST_NON_BUILTIN_TYPE) as usize)
    }
}

impl TypeStream<IdRecord> {
    pub fn record(&self, idx: IdIndex) -> Option<&IdRecord> {
        self.records
            .get((u32::from(idx) - FIRST_NON_BUILTIN_TYPE) as usize)
    }
}

#[derive(Debug, Encode, Decode)]
#[declio(ctx_is = "constants::ENDIANESS")]
pub struct TypeStreamHeader {
    pub version: TypeStreamVersion,
    pub header_size: HeaderSize,
    pub type_index_begin: TypeIndex,
    pub type_index_end: TypeIndex,
    pub type_record_bytes: u32,

    pub hash_stream_index: StreamIndex,
    pub hash_aux_stream_index: StreamIndex,
    pub hash_key_size: HashKeySize,
    pub num_hash_buckets: HashBucketNumber,

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

#[derive(Debug, Encode, Decode)]
pub struct TypeHashLayout {
    hash_values: EmbeddedBuf,
    index_offsets: EmbeddedBuf,
    hash_adjusters: EmbeddedBuf,
}

#[derive(Debug)]
pub struct TypeHash {
    pub(crate) hash_values: Vec<u32>,
    pub(crate) index_offsets: Vec<IndexOffset>,
    pub(crate) hash_adjusters: Table,
}

impl TypeHash {
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
        let hash_values =
            Decode::decode((Len(num_hash_values as usize), constants::ENDIANESS), &mut input)?;
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
        output: &mut MsfStreamWriter<W, N>,
    ) -> Result<TypeHashLayout>
    where
        W: io::Write + io::Seek,
    {
        let hash_values = EmbeddedBuf::from_encoded(&self.hash_values, (constants::ENDIANESS,), output)?;
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
    index: TypeIndex,
    offset: u32,
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
        out: &mut MsfStreamWriter<W, N>,
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

#[derive(Debug, Clone, Copy, BitfieldSpecifier)]
#[bits = 32]
pub enum TypeStreamVersion {
    V40 = 19950410,
    V41 = 19951122,
    V50 = 19961031,
    V70 = 19990903,
    V80 = 20040203,
}

impl_bitfield_specifier_codecs!(TypeStreamVersion);
