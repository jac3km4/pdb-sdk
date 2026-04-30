use declio::ctx::Len;
use declio::{Decode, Encode};

use crate::constants;

#[derive(Encode, Decode)]
#[declio(ctx_is = "constants::ENDIANESS")]
pub(crate) struct Table {
    size: u32,
    cap: u32,
    present: BitVector,
    deleted: BitVector,
    #[declio(ctx = "Len(*size as usize)")]
    entries: Vec<KeyVal>,
}

impl Table {
    pub fn from_sized_iter<I: ExactSizeIterator<Item = (u32, u32)>>(it: I) -> Self {
        let size = it.len() as u32;
        let entries = it.map(|(k, v)| KeyVal::new(k, v)).collect();
        Table {
            size,
            cap: size.max(8),
            present: BitVector::new_filled(size),
            deleted: BitVector::default(),
            entries,
        }
    }

    pub fn entries(&self) -> &[KeyVal] {
        &self.entries
    }
}

impl std::fmt::Debug for Table {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_map()
            .entries(self.entries.iter().map(|kv| (kv.key, kv.val)))
            .finish()
    }
}

impl Default for Table {
    fn default() -> Self {
        Self {
            size: 0,
            cap: 8,
            present: BitVector::default(),
            deleted: BitVector::default(),
            entries: vec![],
        }
    }
}

/// A key-value pair in a PDB Serialized Hash Table. The key is always a uint32.
#[derive(Debug, Encode, Decode)]
#[declio(ctx_is = "constants::ENDIANESS")]
pub struct KeyVal {
    /// The key.
    pub key: u32,
    /// The value.
    pub val: u32,
}

impl KeyVal {
    /// Creates a new key-value pair.
    pub fn new(key: u32, val: u32) -> Self {
        Self { key, val }
    }
}

/// A serialized bit vector indicating the status (e.g. present or deleted) of buckets in a hash table.
#[derive(Debug, Default, Encode, Decode)]
#[declio(ctx_is = "constants::ENDIANESS")]
pub struct BitVector {
    words: u32,
    #[declio(ctx = "Len(*words as usize * 4)")]
    buf: Vec<u8>,
}

impl BitVector {
    /// Creates a new filled bit vector.
    pub fn new_filled(n: u32) -> Self {
        let words = n.div_ceil(32);
        let bytes = words * 4;
        let mut this = Self {
            words,
            buf: vec![0; bytes as usize],
        };
        for i in 0..n {
            this.set(i as usize);
        }
        this
    }

    /// Gets the bit at the specified index.
    #[allow(unused)]
    pub fn get(&self, n: usize) -> Option<bool> {
        let elem = self.buf.get(n / 8)?;
        Some(*elem & (1 << (n % 8)) != 0)
    }

    /// Sets the bit at the specified index.
    pub fn set(&mut self, n: usize) {
        let elem = self.buf.get_mut(n / 8).unwrap();
        *elem |= 1 << (n % 8);
    }

    /// Counts the number of ones in the bit vector.
    #[allow(unused)]
    pub fn count_ones(&self) -> u32 {
        self.buf.iter().map(|b| b.count_ones()).sum()
    }
}

pub(crate) fn hash_v1(bytes: &[u8]) -> u32 {
    let mut hash = 0;
    let mut slice = bytes;

    while let [b1, b2, b3, b4, tail @ ..] = slice {
        hash ^= u32::from_le_bytes([*b1, *b2, *b3, *b4]);
        slice = tail;
    }
    if let [b1, b2, tail @ ..] = slice {
        hash ^= u32::from(u16::from_le_bytes([*b1, *b2]));
        slice = tail;
    }
    if let [b] = slice {
        hash ^= u32::from(*b);
    }

    hash |= 0x2020_2020;
    hash ^= hash >> 11;
    hash ^ (hash >> 16)
}
