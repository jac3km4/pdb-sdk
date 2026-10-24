//! PDB string-table serialization and byte-offset access.

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

/// A PDB string table, notably the named `/names` stream.
///
/// Strings are NUL-terminated bytes referenced by byte offset, not ordinal index.
/// The serialized table also contains hash metadata; access here uses offsets
/// directly. DBI filenames and module C13 string tables are separate buffers.
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
    /// Reads a NUL-terminated UTF-8 string starting at `offset`.
    ///
    /// Returns `None` for an out-of-range offset, missing terminator, or invalid
    /// UTF-8. The offset need not be a known string boundary.
    pub fn get(&self, offset: StringOffset) -> Option<&str> {
        let bytes = self.bytes.get(offset.0 as usize..)?;
        let end = bytes.iter().position(|&byte| byte == 0)?;
        str::from_utf8(&bytes[..end]).ok()
    }

    /// Builds an empty `Strings` table - used when a substream is sized 0
    pub(crate) fn empty() -> Self {
        Self {
            signature: StringsSignature,
            hash_version: HashVersion::V1,
            bytes: vec![],
            ids: vec![],
            name_count: 0,
        }
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
    /// Adds a string to the string table builder.
    pub fn add(&mut self, str: &str) -> Result<()> {
        let offset = self.bytes.len();
        self.bytes.write_all(str.as_bytes())?;
        self.bytes.write_all(b"\0")?;
        self.offsets.push((hash_v1(str.as_bytes()), offset as u32));
        Ok(())
    }

    /// Builds the `Strings` table.
    pub fn build(self) -> Strings {
        let buckets = bucket_counts::get_bucket_count(self.offsets.len() as u32);
        let mut ids = vec![0; buckets as usize];
        let count = self.offsets.len() as u32;

        for (hash, offset) in self.offsets {
            for i in 0..buckets {
                let slot = (u64::from(hash % buckets) + u64::from(i)) % u64::from(buckets);
                match ids.get_mut(slot as usize) {
                    Some(el) if *el == 0 => {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builder_inserts_collisions_with_wraparound() {
        // Three distinct names all hash to the final slot in a four-bucket table.
        let names: Vec<_> = (0..1000)
            .map(|i| format!("name{i}"))
            .filter(|name| hash_v1(name.as_bytes()) % 4 == 3)
            .take(3)
            .collect();
        assert_eq!(names.len(), 3);
        let mut builder = StringsBuilder::default();
        let mut offsets = Vec::new();
        for name in &names {
            offsets.push(builder.bytes.len() as u32);
            builder.add(name).unwrap();
        }
        let strings = builder.build();
        assert_eq!(strings.ids, [offsets[1], offsets[2], 0, offsets[0]]);
        assert_eq!(strings.name_count, 3);
        let mut bytes = Vec::new();
        strings.encode((), &mut bytes).unwrap();
        assert_eq!(strings.encoded_size(()), bytes.len());
        let mut reader = std::io::Cursor::new(bytes);
        let decoded = Strings::decode((), &mut reader).unwrap();
        assert_eq!(reader.position() as usize, reader.get_ref().len());
        for (name, offset) in names.iter().zip(offsets) {
            assert_eq!(decoded.get(StringOffset(offset)), Some(name.as_str()));
            let mut slot = hash_v1(name.as_bytes()) as usize % decoded.ids.len();
            while decoded.ids[slot] != offset {
                assert_ne!(
                    decoded.ids[slot], 0,
                    "LLVM lookup stopped at an empty bucket"
                );
                slot = (slot + 1) % decoded.ids.len();
            }
        }
    }

    #[test]
    fn probing_large_hash_does_not_overflow() {
        let strings = StringsBuilder {
            bytes: b"\0a\0b\0".to_vec(),
            offsets: vec![(u32::MAX, 1), (u32::MAX, 3)],
        }
        .build();
        assert_eq!(strings.ids, [3, 0, 0, 1]);
    }

    #[test]
    fn string_lookup_checks_bounds_termination_and_utf8() {
        let mut strings = Strings::empty();
        strings.bytes = b"hello\0\0\xff\0tail".to_vec();
        assert_eq!(strings.get(StringOffset(0)), Some("hello"));
        assert_eq!(strings.get(StringOffset(5)), Some(""));
        assert_eq!(strings.get(StringOffset(6)), Some(""));
        assert_eq!(strings.get(StringOffset(7)), None);
        assert_eq!(strings.get(StringOffset(9)), None);
        assert_eq!(strings.get(StringOffset(strings.bytes.len() as u32)), None);
        assert_eq!(strings.get(StringOffset(u32::MAX)), None);
        assert_eq!(Strings::empty().get(StringOffset(0)), None);
    }
}

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

    /// Gets the bucket count for a given number of strings.
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
