use std::fmt;
use std::io::Write;

use declio::util::{Bytes, PrefixVec};
use declio::{Decode, Encode, EncodedSize, magic_bytes};
use modular_bitfield::Specifier;

use crate::hash::hash_v1;
use crate::result::Result;
use crate::{StringOffset, constants, impl_bitfield_specifier_codecs};

magic_bytes! {
    #[derive(Debug)]
    StringsSignature(&0xEFFE_EFFE_u32.to_le_bytes());
}

/// Represents the PDB String Table (or `/names` stream).
/// It contains a deduplicated table of strings mapped to their offsets.
/// Analogous to `PDBStringTable` in LLVM.
#[derive(Encode, Decode, EncodedSize)]
#[declio(ctx_is = "constants::ENDIANESS")]
pub struct Strings {
    signature: StringsSignature,
    hash_version: HashVersion,
    #[declio(via = "Bytes<'_, u32>")]
    bytes: Vec<u8>,
    #[declio(via = "PrefixVec<'_, u32, u32>")]
    ids: Vec<u32>,
    name_count: u32,
}

impl Strings {
    pub fn get(&self, offset: StringOffset) -> Option<&str> {
        let str = &self.bytes[offset.0 as usize..].split(|&n| n == 0).next()?;
        str::from_utf8(str).ok()
    }
}

impl fmt::Debug for Strings {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Strings")
            .field("hash_version", &self.hash_version)
            .field(
                "strings",
                &fmt::from_fn(|f| {
                    let mut list = f.debug_list();
                    for offset in &self.ids {
                        if let Some(str) = self.get(StringOffset(*offset)) {
                            list.entry(&str);
                        }
                    }
                    list.finish()
                }),
            )
            .finish()
    }
}

#[derive(Debug)]
pub(crate) struct StringsBuilder {
    bytes: Vec<u8>,
    offsets: Vec<(u32, u32)>,
}

impl StringsBuilder {
    #[allow(unused)]
    pub fn add(&mut self, str: &str) -> Result<()> {
        let offset = self.bytes.len();
        self.bytes.write_all(str.as_bytes())?;
        self.bytes.write_all(b"\0")?;
        self.offsets.push((hash_v1(str.as_bytes()), offset as u32));
        Ok(())
    }

    pub fn build(self) -> Strings {
        let buckets = bucket_counts::get_bucket_count(self.offsets.len() as u32);
        let mut ids = vec![0; buckets as usize];
        let count = self.offsets.len() as u32;

        for (hash, offset) in self.offsets {
            for i in 0..buckets {
                let slot = (hash + i) % buckets;
                match ids.get_mut(slot as usize) {
                    Some(el) if *el != 0 => {
                        *el = offset;
                        break;
                    }
                    _ => {}
                }
            }
        }

        Strings {
            signature: StringsSignature,
            hash_version: HashVersion::V1,
            bytes: self.bytes,
            ids,
            name_count: count,
        }
    }
}

impl Default for StringsBuilder {
    fn default() -> Self {
        Self {
            bytes: vec![0],
            offsets: vec![],
        }
    }
}

#[derive(Debug, Clone, Copy, Specifier)]
#[bits = 32]
enum HashVersion {
    V1 = 1,
    V2 = 2,
}

impl_bitfield_specifier_codecs!(HashVersion);

mod bucket_counts {
    static BUCKET_COUNTS: [(u32, u32); 28] = generate_buckets();

    const fn generate_buckets() -> [(u32, u32); 28] {
        let mut buf = [(0, 0); 28];
        let mut cur_buckets = 1;
        let mut len_buckets = 0;
        let mut i = 0;
        let mut j = 0;
        loop {
            if len_buckets == buf.len() {
                return buf;
            }
            if cur_buckets * 3 / 4 < i {
                buf[len_buckets] = (j, cur_buckets);
                j = i;
                cur_buckets = cur_buckets * 3 / 2 + 1;
                len_buckets += 1;
            }
            i += 1;
        }
    }

    pub fn get_bucket_count(n: u32) -> u32 {
        let idx = BUCKET_COUNTS
            .binary_search_by_key(&n, |(k, _)| *k)
            .unwrap_or_else(|i| i - 1);
        BUCKET_COUNTS[idx].1
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn get_bucket_counts() {
            assert_eq!(get_bucket_count(0), 1);
            assert_eq!(get_bucket_count(1), 2);
            assert_eq!(get_bucket_count(2), 4);
            assert_eq!(get_bucket_count(3), 4);
            assert_eq!(get_bucket_count(4), 7);
            assert_eq!(get_bucket_count(5), 7);
            assert_eq!(get_bucket_count(6), 11);
            assert_eq!(get_bucket_count(7), 11);
            assert_eq!(get_bucket_count(8), 11);
            assert_eq!(get_bucket_count(9), 17);
            assert_eq!(get_bucket_count(20482), 40963);
        }
    }
}
