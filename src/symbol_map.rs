use std::collections::BTreeMap;
use std::fmt::Debug;
use std::io;

use declio::ctx::Len;
use declio::{magic_bytes, Decode, Encode, EncodedSize};

use crate::codeview::NamedSymbol;
use crate::hash::hash_v1;
use crate::result::Result;
use crate::utils::CaseInsensitiveStr;
use crate::{constants, SymbolOffset};

const HDR_VERSION: u32 = 0xeffe0000 + 19990810;
const IPHR_HASH: usize = 4096;
const BITMAP_SIZE: usize = (IPHR_HASH + 32) / 32;

type Bitmap = [u32; BITMAP_SIZE];

magic_bytes! {
    #[derive(Debug)]
    SignatureVersion(&u32::MAX.to_le_bytes());
    #[derive(Debug)]
    HdrVersion(&HDR_VERSION.to_le_bytes());
}

pub type Globals = SymbolMap;

#[derive(Debug, EncodedSize)]
pub struct SymbolMap {
    hash_records: Vec<IndexRecord>,
    bitmap: Bitmap,
    buckets: Vec<u32>,
}

impl SymbolMap {
    pub(crate) fn from_symbols<S>(mapping: &BTreeMap<SymbolOffset, S>) -> Self
    where
        S: NamedSymbol,
    {
        let mut bucket_starts = [0u32; IPHR_HASH];
        let mut hash_records = Vec::with_capacity(mapping.len());

        for (offset, el) in mapping {
            let hash = hash_v1(el.name().unwrap_or_default().as_bytes());
            let bucket_index = hash % IPHR_HASH as u32;
            bucket_starts[bucket_index as usize] += 1;
            hash_records.push(IndexRecord::new(SymbolOffset(offset.0 + 1)));
        }

        let mut sum = 0;
        for start in bucket_starts.iter_mut() {
            let val = *start;
            *start += sum;
            sum += val;
        }

        let mut slice = &bucket_starts[..];
        while let [start, tail @ ..] = slice {
            let end = tail.first().copied().unwrap_or(mapping.len() as u32);

            hash_records[*start as usize..end as usize].sort_by(|lhs, rhs| {
                let lhs_name = mapping
                    .get(&lhs.offset())
                    .and_then(S::name)
                    .map(CaseInsensitiveStr);
                let rhs_name = mapping
                    .get(&rhs.offset())
                    .and_then(S::name)
                    .map(CaseInsensitiveStr);
                lhs_name
                    .cmp(&rhs_name)
                    .then_with(|| lhs.offset().cmp(&rhs.offset()))
            });

            slice = tail;
        }

        let (bitmap, buckets) = allocate_buckets(&bucket_starts, mapping.len() as u32);
        Self {
            hash_records,
            bitmap,
            buckets,
        }
    }

    pub fn read_with_header<R>(mut input: R) -> Result<Self>
    where
        R: io::Read,
    {
        let gsi_header = GsiHashHeader::decode((), &mut input)?;
        let num_records = gsi_header.hr_size / 8;
        let hash_records = Decode::decode(Len(num_records as usize), &mut input)?;
        let bitmap: Bitmap = Decode::decode(constants::ENDIANESS, &mut input)?;
        let bucket_count: u32 = bitmap.iter().map(|b| b.count_ones()).sum();
        let buckets = Decode::decode((Len(bucket_count as usize), constants::ENDIANESS), &mut input)?;

        Ok(Self {
            hash_records,
            bitmap,
            buckets,
        })
    }

    pub fn write_with_header<S>(&self, sink: &mut S) -> Result<()>
    where
        S: io::Write,
    {
        self.get_header().encode((), sink)?;
        self.encode((), sink)?;
        Ok(())
    }

    pub(crate) fn get_header(&self) -> GsiHashHeader {
        GsiHashHeader {
            signature: SignatureVersion,
            ver_hdr: HdrVersion,
            hr_size: self.hash_records.encoded_size(()) as u32,
            num_buckets: (self.bitmap.encoded_size(()) + self.buckets.encoded_size(())) as u32,
        }
    }
}

impl<Ctx> Encode<Ctx> for SymbolMap {
    fn encode<W>(&self, _ctx: Ctx, writer: &mut W) -> Result<(), declio::Error>
    where
        W: io::Write,
    {
        self.hash_records.encode(((),), writer)?;
        self.bitmap.encode(constants::ENDIANESS, writer)?;
        self.buckets.encode((constants::ENDIANESS,), writer)?;

        Ok(())
    }
}

#[derive(Debug, Encode, Decode, EncodedSize)]
#[declio(ctx_is = "constants::ENDIANESS")]
pub(crate) struct GsiHashHeader {
    signature: SignatureVersion,
    ver_hdr: HdrVersion,
    hr_size: u32,
    num_buckets: u32,
}

#[derive(Debug, Encode, Decode, EncodedSize)]
#[declio(ctx_is = "constants::ENDIANESS")]
struct IndexRecord {
    offset: SymbolOffset,
    ref_count: u32,
}

impl IndexRecord {
    pub(crate) fn new(offset: SymbolOffset) -> Self {
        Self { offset, ref_count: 1 }
    }

    pub fn offset(&self) -> SymbolOffset {
        self.offset
    }
}

fn allocate_buckets(bucket_starts: &[u32], size: u32) -> (Bitmap, Vec<u32>) {
    let mut bitmap = [0u32; BITMAP_SIZE];
    let mut buckets = vec![];

    for (n, elem) in bitmap.iter_mut().enumerate() {
        for bit in 0..32 {
            let bucket_index = n * 32 + bit;
            let start = bucket_starts.get(bucket_index);
            let end = bucket_starts.get(bucket_index + 1).copied().unwrap_or(size);
            match start {
                Some(&start) if start == end => {}
                None => {}
                Some(&start) => {
                    *elem |= 1 << bit;
                    buckets.push(start * 12);
                }
            }
        }
    }
    (bitmap, buckets)
}
