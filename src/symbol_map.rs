//! GSI hash-index serialization shared by the global and public symbol streams.

use std::collections::BTreeMap;
use std::fmt::Debug;
use std::io;

use declio::ctx::Len;
use declio::{Decode, Encode, EncodedSize, magic_bytes};

use crate::codeview::NamedSymbol;
use crate::hash::hash_v1;
use crate::result::Result;
use crate::utils::CaseInsensitiveStr;
use crate::{SymbolOffset, constants};

const HDR_VERSION: u32 = 0xeffe_0000 + 19_990_810;
const IPHR_HASH: usize = 4096;
const BITMAP_SIZE: usize = (IPHR_HASH + 32) / 32;

type Bitmap = [u32; BITMAP_SIZE];

magic_bytes! {
    #[derive(Debug)]
    SignatureVersion(&u32::MAX.to_le_bytes());
    #[derive(Debug)]
    HdrVersion(&HDR_VERSION.to_le_bytes());
}

/// The global-symbol index, represented by the shared GSI hash-table format.
pub type Globals = SymbolMap;

/// A Global Symbol Information (GSI) hash index.
///
/// Used by both global and public streams to refer to records in a separate
/// symbol record stream. This type reads and writes index data; it does not
/// currently expose name lookup or resolve symbol records.
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
        #[derive(Clone, Copy)]
        struct PreparedEntry<'a> {
            offset: SymbolOffset,
            name: CaseInsensitiveStr<'a>,
            bucket: usize,
        }

        let mut bucket_starts = [0u32; IPHR_HASH];
        let mut entries: Vec<_> = mapping
            .iter()
            .map(|(&offset, symbol)| {
                let name = symbol.name().unwrap_or_default();
                let bucket = (hash_v1(name.as_bytes()) % IPHR_HASH as u32) as usize;
                bucket_starts[bucket] += 1;
                PreparedEntry {
                    offset,
                    name: CaseInsensitiveStr::new(name),
                    bucket,
                }
            })
            .collect();

        let mut sum = 0;
        for start in &mut bucket_starts {
            let val = *start;
            *start = sum;
            sum += val;
        }

        // Partition in place: each cursor marks the first unfilled slot in its
        // bucket. A displaced entry is moved directly to its own bucket.
        let mut bucket_cursors = bucket_starts;
        for bucket in 0..IPHR_HASH {
            let end = bucket_starts
                .get(bucket + 1)
                .copied()
                .unwrap_or(mapping.len() as u32);
            while bucket_cursors[bucket] < end {
                let index = bucket_cursors[bucket] as usize;
                let target = entries[index].bucket;
                if target != bucket {
                    entries.swap(index, bucket_cursors[target] as usize);
                }
                bucket_cursors[target] += 1;
            }
        }

        // Keep offsets zero-based through sorting. Only GSI's wire offsets
        // are one-based; shared-stream and public address-map offsets are not.
        let mut slice = &bucket_starts[..];
        while let [start, tail @ ..] = slice {
            let end = tail.first().copied().unwrap_or(mapping.len() as u32);

            entries[*start as usize..end as usize].sort_unstable_by(|lhs, rhs| {
                lhs.name
                    .cmp(&rhs.name)
                    .then_with(|| lhs.offset.cmp(&rhs.offset))
            });

            slice = tail;
        }

        let hash_records = entries
            .into_iter()
            .map(|entry| IndexRecord::new(SymbolOffset(entry.offset.0 + 1)))
            .collect();

        let (bitmap, buckets) = allocate_buckets(&bucket_starts, mapping.len() as u32);
        Self {
            hash_records,
            bitmap,
            buckets,
        }
    }

    /// Reads a GSI header followed by hash records, bitmap, and bucket offsets.
    pub fn read_with_header<R>(mut input: R) -> Result<Self>
    where
        R: io::Read,
    {
        let gsi_header = GsiHashHeader::decode((), &mut input)?;
        let num_records = gsi_header.hr_size / 8;
        let hash_records = Decode::decode(Len(num_records as usize), &mut input)?;

        let (bitmap, buckets) = if gsi_header.num_buckets == 0 {
            ([0u32; BITMAP_SIZE], Vec::new())
        } else {
            let bitmap: Bitmap = Decode::decode(constants::ENDIANESS, &mut input)?;
            let bucket_count: u32 = bitmap.iter().map(|b| b.count_ones()).sum();
            let buckets = Decode::decode(
                (Len(bucket_count as usize), constants::ENDIANESS),
                &mut input,
            )?;
            (bitmap, buckets)
        };

        Ok(Self {
            hash_records,
            bitmap,
            buckets,
        })
    }

    /// Writes the GSI header and index data, without the referenced symbol records.
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
        Self {
            offset,
            ref_count: 1,
        }
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

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::cmp::Ordering;

    use super::*;

    struct Name(String);

    impl NamedSymbol for Name {
        fn name(&self) -> Option<&str> {
            Some(&self.0)
        }
    }

    #[test]
    fn llvm_name_comparison() {
        for (lhs, rhs, expected) in [
            ("z", "aa", Ordering::Less),
            ("Z", "a", Ordering::Greater),
            ("aZ", "Az", Ordering::Equal),
            ("[", "a", Ordering::Less),
            ("Aé", "aé", Ordering::Less),
            ("Zz", "é", Ordering::Less),
            ("é", "Zz", Ordering::Greater),
            ("Zé", "aé", Ordering::Less),
            ("Zé", "aab", Ordering::Less),
            ("aab", "Zé", Ordering::Greater),
            ("", "", Ordering::Equal),
            ("é", "zz", Ordering::Greater),
            ("é", "aaa", Ordering::Less),
        ] {
            assert_eq!(
                CaseInsensitiveStr::new(lhs).cmp(&CaseInsensitiveStr::new(rhs)),
                expected
            );
            assert_eq!(
                CaseInsensitiveStr::new(lhs) == CaseInsensitiveStr::new(rhs),
                expected == Ordering::Equal
            );
        }
    }

    #[test]
    fn buckets_contain_their_names_in_llvm_order() {
        // Case variants and duplicates deliberately collide. The generated names
        // exercise many buckets and collisions across different name lengths.
        let names = ["z", "Z", "z", "aZ", "Az", "Aé", "aé"]
            .into_iter()
            .map(str::to_owned)
            .chain((0..6000).map(|i| format!("symbol_{i}")));
        let mapping: BTreeMap<_, _> = names
            .enumerate()
            .map(|(i, name)| (SymbolOffset(i as u32 * 20), Name(name)))
            .collect();
        let map = SymbolMap::from_symbols(&mapping);
        let mut bytes = Vec::new();
        map.write_with_header(&mut bytes).unwrap();
        let decoded = SymbolMap::read_with_header(&bytes[..]).unwrap();
        let mut next = 0;
        let mut bucket_number = 0;
        let mut seen = Vec::new();
        let mut has_collision = false;
        for bucket in 0..IPHR_HASH {
            if decoded.bitmap[bucket / 32] & (1 << (bucket % 32)) == 0 {
                continue;
            }
            let start = decoded.buckets[bucket_number] as usize / 12;
            assert_eq!(start, next);
            bucket_number += 1;
            let end = decoded
                .buckets
                .get(bucket_number)
                .map(|offset| *offset as usize / 12)
                .unwrap_or(mapping.len());
            assert!(end > start);
            has_collision |= end - start > 1;
            let records = &decoded.hash_records[start..end];
            for record in records {
                assert_eq!(record.ref_count, 1);
                assert_ne!(record.offset.0, 0);
                let offset = SymbolOffset(record.offset.0 - 1);
                let name = &mapping[&offset].0;
                assert_eq!(hash_v1(name.as_bytes()) as usize % IPHR_HASH, bucket);
                seen.push(offset);
            }
            for pair in records.windows(2) {
                let lhs = SymbolOffset(pair[0].offset.0 - 1);
                let rhs = SymbolOffset(pair[1].offset.0 - 1);
                let order = CaseInsensitiveStr::new(&mapping[&lhs].0)
                    .cmp(&CaseInsensitiveStr::new(&mapping[&rhs].0))
                    .then(lhs.cmp(&rhs));
                assert_eq!(order, Ordering::Less);
            }
            next = end;
        }
        assert!(has_collision);
        assert_eq!(decoded.bitmap[BITMAP_SIZE - 1], 0);
        assert_eq!(bucket_number, decoded.buckets.len());
        seen.sort_unstable();
        assert_eq!(seen, mapping.keys().copied().collect::<Vec<_>>());
        assert_eq!(next, mapping.len());
    }

    #[test]
    fn resolves_each_name_once() {
        struct CountedName {
            name: Option<&'static str>,
            calls: Cell<usize>,
        }

        impl NamedSymbol for CountedName {
            fn name(&self) -> Option<&str> {
                self.calls.set(self.calls.get() + 1);
                self.name
            }
        }

        let mapping = [Some("z"), Some("Z"), Some("z"), Some("Aé"), None, Some("")]
            .into_iter()
            .enumerate()
            .map(|(i, name)| {
                (
                    SymbolOffset(i as u32 * 20),
                    CountedName {
                        name,
                        calls: Cell::new(0),
                    },
                )
            })
            .collect();
        let map = SymbolMap::from_symbols(&mapping);
        assert_eq!(map.hash_records.len(), mapping.len());
        let case_variant_offsets: Vec<_> = map
            .hash_records
            .iter()
            .map(|record| record.offset.0)
            .filter(|&offset| offset <= 41)
            .collect();
        assert_eq!(case_variant_offsets, [1, 21, 41]);
        for symbol in mapping.values() {
            assert_eq!(symbol.calls.get(), 1);
        }
    }

    #[test]
    fn empty_index_has_no_buckets() {
        let map = SymbolMap::from_symbols(&BTreeMap::<SymbolOffset, Name>::new());
        assert!(map.hash_records.is_empty());
        assert!(map.buckets.is_empty());
        assert_eq!(map.bitmap, [0; BITMAP_SIZE]);
    }
}
