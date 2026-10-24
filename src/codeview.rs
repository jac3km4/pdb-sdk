//! CodeView type, ID, and symbol records used within PDB streams.
//!
//! Leaf type/ID records and symbol records begin with a little-endian `u16`
//! length (excluding itself) and a `u16` kind. Stream readers handle the length
//! prefix separately from the kind and body.
//! See LLVM's [PDB overview](https://llvm.org/docs/PDB/index.html),
//! [type records](https://llvm.org/docs/PDB/CodeViewTypes.html), and
//! [symbol records](https://llvm.org/docs/PDB/CodeViewSymbols.html).

use std::cmp::Ordering;
use std::io;

use declio::{Decode, Encode, EncodedSize};
use symbols::{Public, SymbolRecord};

use crate::constants;
use crate::utils::align_to;

pub mod symbols;
pub mod types;

pub(crate) const RECORD_ALIGNMENT: usize = 4;

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, PartialEq, Encode, Decode, EncodedSize)]
    #[declio(ctx_is = "constants::ENDIANESS")]
    struct Kind(u16);

    struct Body(usize);

    impl Encode for Body {
        fn encode<W: io::Write>(&self, (): (), writer: &mut W) -> Result<(), declio::Error> {
            writer.write_all(&vec![0; self.0])?;
            Ok(())
        }
    }

    impl EncodedSize for Body {
        fn encoded_size(&self, (): ()) -> usize {
            self.0
        }
    }

    #[test]
    fn terminator_distinguishes_clean_eof_and_partial_prefix() {
        assert!(
            PrefixedRecord::<Kind>::decode_or_terminator(&mut &[][..])
                .unwrap()
                .is_none()
        );
        for byte in [0, 1, 2, 0xff] {
            assert!(PrefixedRecord::<Kind>::decode_or_terminator(&mut &[byte][..]).is_err());
        }
        for len in [0, 1] {
            assert!(
                PrefixedRecord::<Kind>::decode_or_terminator(&mut &[len, 0][..])
                    .unwrap()
                    .is_none()
            );
            assert!(PrefixedRecord::<Kind>::decode_with_size(&mut &[len, 0][..]).is_err());
        }
        assert!(PrefixedRecord::<Kind>::decode_or_terminator(&mut &[2, 0, 1][..]).is_err());
        assert!(PrefixedRecord::<Kind>::decode_with_size(&mut &[2, 0, 1][..]).is_err());
    }

    #[test]
    fn record_lengths_padding_and_positions() {
        for (size, padding) in [
            (2, &[][..]),
            (3, &[0xf3, 0xf2, 0xf1][..]),
            (4, &[0xf2, 0xf1][..]),
            (5, &[0xf1][..]),
        ] {
            let mut bytes = vec![];
            PrefixedRecord(Body(size)).encode((), &mut bytes).unwrap();
            let len = size + padding.len();
            assert_eq!(u16::from_le_bytes([bytes[0], bytes[1]]) as usize, len);
            assert_eq!(&bytes[2 + size..], padding);
            bytes.extend_from_slice(&[2, 0, 0x34, 0x12]);
            let mut cursor = io::Cursor::new(bytes);
            let (_, consumed) = PrefixedRecord::<Kind>::decode_with_size(&mut cursor).unwrap();
            assert_eq!(consumed, (len + 2) as u64);
            assert_eq!(cursor.position(), consumed);
            let next = PrefixedRecord::<Kind>::decode_or_terminator(&mut cursor)
                .unwrap()
                .unwrap();
            assert_eq!(next.into_inner(), Kind(0x1234));
        }
    }

    #[test]
    fn record_size_limits() {
        let mut bytes = vec![];
        PrefixedRecord(Body(65_534)).encode((), &mut bytes).unwrap();
        assert_eq!(&bytes[..2], &65_534u16.to_le_bytes());
        for size in [65_535, 65_536, usize::MAX] {
            let mut bytes = vec![];
            assert!(PrefixedRecord(Body(size)).encode((), &mut bytes).is_err());
            assert!(bytes.is_empty());
        }
    }
}

/// Length-prefixed record; encoding aligns the prefix and body to four bytes.
#[derive(Debug)]
pub(crate) struct PrefixedRecord<A>(pub A);

impl<A> PrefixedRecord<A> {
    /// Unwraps the prefixed record, returning the inner value.
    pub fn into_inner(self) -> A {
        self.0
    }
}

impl<A> PrefixedRecord<A> {
    /// Decodes a length-prefixed CodeView record and returns the total number
    /// of bytes consumed from `reader` (2-byte length prefix plus body).
    /// Trailing bytes the inner parser leaves unconsumed are discarded.
    pub fn decode_with_size<R>(reader: &mut R) -> Result<(Self, u64), declio::Error>
    where
        A: Decode,
        R: io::Read,
    {
        let len = u16::decode(constants::ENDIANESS, reader)? as usize;
        if len < 2 {
            return Err(declio::Error::new(
                "record length is too short for a kind tag",
            ));
        }
        let mut buf = vec![0u8; len];
        reader.read_exact(&mut buf)?;
        let mut slice: &[u8] = &buf;
        let res = A::decode((), &mut slice)?;
        Ok((Self(res), (len + 2) as u64))
    }

    /// Like [`Self::decode_with_size`], but accepts clean EOF or a length below
    /// two as a terminator. A partial length prefix or truncated body is an error.
    pub fn decode_or_terminator<R>(reader: &mut R) -> Result<Option<Self>, declio::Error>
    where
        A: Decode,
        R: io::Read,
    {
        let mut len_buf = [0u8; 2];
        loop {
            match reader.read(&mut len_buf[..1]) {
                Ok(0) => return Ok(None),
                Ok(_) => break,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e.into()),
            }
        }
        reader.read_exact(&mut len_buf[1..])?;
        let len = u16::from_le_bytes(len_buf) as usize;
        if len < 2 {
            return Ok(None);
        }
        let mut buf = vec![0u8; len];
        reader.read_exact(&mut buf)?;
        let mut slice: &[u8] = &buf;
        let res = A::decode((), &mut slice)?;
        Ok(Some(Self(res)))
    }
}

impl<A> Encode for PrefixedRecord<A>
where
    A: Encode + EncodedSize,
{
    fn encode<W>(&self, _ctx: (), writer: &mut W) -> Result<(), declio::Error>
    where
        W: io::Write,
    {
        const PREFIX_SIZE: usize = std::mem::size_of::<u16>();

        let size = self.0.encoded_size(());
        if size > usize::from(u16::MAX) {
            return Err(declio::Error::new("record size exceeds u16 limit"));
        }
        let full_size = align_to(size + PREFIX_SIZE, RECORD_ALIGNMENT) - PREFIX_SIZE;
        let full_size_u16 = u16::try_from(full_size).map_err(|_| {
            declio::Error::new(format!(
                "type record too large: {full_size} bytes exceeds u16 limit"
            ))
        })?;
        full_size_u16.encode(constants::ENDIANESS, writer)?;
        self.0.encode((), writer)?;

        // CodeView padding is a descending run of LF_PADn markers
        let padding = full_size - size;
        for i in (1..=padding).rev() {
            writer.write_all(&[i as u8 | constants::LF_PAD0])?;
        }
        Ok(())
    }
}

#[derive(Debug, PartialEq, Eq, Encode, Decode, EncodedSize)]
#[declio(ctx_is = "constants::ENDIANESS")]
/// Section-relative address, not a PDB stream offset or an RVA.
///
/// Ordering compares the segment first, then the byte offset.
pub struct DataRegionOffset {
    /// Byte offset within the segment.
    pub offset: u32,
    /// CodeView segment (section) index.
    pub segment: u16,
}

impl DataRegionOffset {
    /// Creates a new data region offset.
    pub fn new(offset: u32, segment: u16) -> Self {
        Self { offset, segment }
    }
}

impl PartialOrd for DataRegionOffset {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for DataRegionOffset {
    fn cmp(&self, other: &Self) -> Ordering {
        self.segment
            .cmp(&other.segment)
            .then(self.offset.cmp(&other.offset))
    }
}

#[derive(Debug, Encode, Decode, EncodedSize)]
#[declio(ctx_is = "constants::ENDIANESS")]
/// CodeView register number, interpreted for the symbol's target architecture.
pub struct Register(pub u16);

pub(crate) trait NamedSymbol {
    fn name(&self) -> Option<&str>;
}

impl NamedSymbol for SymbolRecord {
    #[inline]
    fn name(&self) -> Option<&str> {
        self.name()
    }
}

impl NamedSymbol for Public {
    #[inline]
    fn name(&self) -> Option<&str> {
        Some(self.name.as_ref())
    }
}
