//! Serialized PDB hash-table components and the V1 name hash.
//!
//! This table format is used by named streams and type hash adjusters; symbol
//! GSI indexes have a different layout. See LLVM's
//! [serialized hash-table guide](https://llvm.org/docs/PDB/HashTable.html).

use std::fmt;

use declio::ctx::Len;
use declio::{Decode, Encode};

use crate::constants;

/// Serialized bucket state and packed 32-bit key/value entries.
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
    pub fn from_sized_iter<I, H>(it: I, hash_key: H) -> Self
    where
        I: ExactSizeIterator<Item = (u32, u32)>,
        H: Fn(u32) -> u32,
    {
        let cap = it.len().max(8);
        let mut buckets: Vec<Option<KeyVal>> = (0..cap).map(|_| None).collect();
        for (key, val) in it {
            let mut slot = hash_key(key) as usize % cap;
            while let Some(entry) = &buckets[slot] {
                if entry.key == key {
                    break;
                }
                slot = (slot + 1) % cap;
            }
            buckets[slot] = Some(KeyVal::new(key, val));
        }
        let mut present = BitVector {
            words: cap.div_ceil(32) as u32,
            buf: vec![0; cap.div_ceil(32) * 4],
        };
        let mut entries = Vec::new();
        for (slot, entry) in buckets.into_iter().enumerate() {
            if let Some(entry) = entry {
                present.set(slot);
                entries.push(entry);
            }
        }
        Self {
            size: entries.len() as u32,
            cap: cap as u32,
            present,
            deleted: BitVector::default(),
            entries,
        }
    }

    pub fn entries(&self) -> &[KeyVal] {
        &self.entries
    }
}

impl fmt::Debug for Table {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
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

/// A 32-bit key/value pair in this implementation's serialized PDB hash table.
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
    /// Sets the first `n` bits, with zero padding to a 32-bit word boundary.
    #[allow(unused)]
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

    /// Returns a bit, or `None` beyond the allocated word storage.
    #[allow(unused)]
    pub fn get(&self, n: usize) -> Option<bool> {
        let elem = self.buf.get(n / 8)?;
        Some(*elem & (1 << (n % 8)) != 0)
    }

    /// Sets a bit within the allocated word storage.
    ///
    /// # Panics
    /// Panics if `n` is outside that storage.
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

/// Computes the PDB V1 byte hash; this is not a cryptographic hash.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_preserves_hash_placement_and_collision_probing() {
        let table = Table::from_sized_iter([(10, 100), (20, 200), (30, 300)].into_iter(), |_| 7);
        assert_eq!(table.cap, 8);
        assert_eq!(table.present.count_ones(), 3);
        assert_eq!(table.present.get(7), Some(true));
        assert_eq!(table.present.get(0), Some(true));
        assert_eq!(table.present.get(1), Some(true));
        assert_eq!(
            table
                .entries
                .iter()
                .map(|e| (e.key, e.val))
                .collect::<Vec<_>>(),
            [(20, 200), (30, 300), (10, 100)]
        );
    }

    #[test]
    fn table_uses_previous_capacity_without_growth_policy() {
        for count in [0, 6, 8, 9, 32] {
            let table = Table::from_sized_iter((0..count).map(|key| (key, key + 1)), |_| 7);
            assert_eq!(table.cap, count.max(8));
            assert_eq!(table.size, count);
            assert_eq!(table.present.count_ones(), count);
        }
        let table = Table::from_sized_iter([(1, 2), (1, 3)].into_iter(), |key| key);
        assert_eq!(table.size, 1);
        assert_eq!(table.entries[0].val, 3);
    }
}
