//! Shared CodeView indices, offsets, identifiers, and numeric leaves.
//!
//! `TypeIndex` identifies a simple type or a TPI record; `IdIndex` identifies an
//! IPI record. Neither is a byte offset. `SymbolOffset` and `StringOffset` are
//! byte offsets in their respective streams or tables. See LLVM's
//! [PDB format documentation](https://llvm.org/docs/PDB/index.html).

use std::num::NonZeroU32;
use std::{fmt, io, mem};

use declio::{Decode, Encode, EncodedSize};

use crate::result::Result;
use crate::{codecs, constants};

/// Byte offset into a string table, not an IPI string ID.
#[derive(Debug, Clone, Copy, Encode, Decode)]
#[declio(ctx_is = "constants::ENDIANESS")]
pub struct StringOffset(pub(crate) u32);

/// Error indicating a type or ID index was zero.
#[derive(Debug)]
pub struct IndexIsZero;

macro_rules! record_index {
    ($name:ident) => {
        /// Nonzero CodeView index, not a byte offset.
        ///
        /// `TypeIndex` is used for simple types and TPI references; `IdIndex` for
        /// IPI references. Construction checks only that the value is nonzero,
        /// not that a corresponding record exists.
        #[derive(Clone, Copy, PartialEq, Eq, Hash)]
        pub struct $name(NonZeroU32);

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}", self.0)
            }
        }

        impl TryFrom<u32> for $name {
            type Error = IndexIsZero;

            fn try_from(value: u32) -> Result<Self, Self::Error> {
                NonZeroU32::new(value).map(Self).ok_or(IndexIsZero)
            }
        }

        impl From<$name> for u32 {
            #[inline]
            fn from(ty: $name) -> Self {
                ty.0.get()
            }
        }

        impl<Ctx> Decode<Ctx> for $name {
            fn decode<R>(_ctx: Ctx, reader: &mut R) -> Result<Self, declio::Error>
            where
                R: io::Read,
            {
                u32::decode(constants::ENDIANESS, reader)?
                    .try_into()
                    .map_err(|_| declio::Error::new("Type index was zero"))
            }
        }

        impl<Ctx> Encode<Ctx> for $name {
            #[inline]
            fn encode<W>(&self, _ctx: Ctx, writer: &mut W) -> Result<(), declio::Error>
            where
                W: io::Write,
            {
                self.0.get().encode(constants::ENDIANESS, writer)
            }
        }

        impl<Ctx> EncodedSize<Ctx> for $name {
            #[inline]
            fn encoded_size(&self, _ctx: Ctx) -> usize {
                mem::size_of::<u32>()
            }
        }
    };
}

/// Byte offset of a symbol record within its symbol stream, not a type index.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Decode, Encode, EncodedSize)]
#[declio(ctx_is = "constants::ENDIANESS")]
pub struct SymbolOffset(pub(crate) u32);

impl From<u32> for SymbolOffset {
    fn from(val: u32) -> Self {
        SymbolOffset(val)
    }
}

impl From<SymbolOffset> for u32 {
    fn from(val: SymbolOffset) -> Self {
        val.0
    }
}

record_index!(IdIndex);
record_index!(TypeIndex);

/// Raw 16-byte GUID used as part of the identity matching a PDB to an executable.
///
/// This wrapper does not generate or validate identifiers.
#[derive(Default, Encode, Decode, EncodedSize)]
pub struct Guid(#[declio(with = "codecs::byte_array")] pub [u8; 16]);

impl fmt::Debug for Guid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "\"{:02X}{:02X}{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}\"",
            self.0[3],
            self.0[2],
            self.0[1],
            self.0[0],
            self.0[5],
            self.0[4],
            self.0[7],
            self.0[6],
            self.0[8],
            self.0[9],
            self.0[10],
            self.0[11],
            self.0[12],
            self.0[13],
            self.0[14],
            self.0[15]
        )
    }
}

/// Integer-valued CodeView numeric leaf used in type and constant records.
///
/// Unsigned values below `LF_NUMERIC` encode directly in two bytes; larger
/// values and signed variants use a leaf tag followed by the value. Encoding
/// follows the selected variant rather than minimizing every value.
#[derive(Debug)]
pub enum Integer {
    I16(i16),
    I32(i32),
    I64(i64),
    U8(u8),
    U16(u16),
    U32(u32),
    U64(u64),
}

impl Integer {
    /// Chooses the first fitting unsigned variant among `U16`, `U32`, and `U64`.
    pub fn from_unsigned(val: u64) -> Self {
        if val <= u16::MAX as u64 {
            Integer::U16(val as u16)
        } else if val <= u32::MAX as u64 {
            Integer::U32(val as u32)
        } else {
            Integer::U64(val)
        }
    }

    /// Chooses the first fitting signed variant among `I16`, `I32`, and `I64`.
    pub fn from_signed(val: i64) -> Self {
        if val >= i16::MIN as i64 && val <= i16::MAX as i64 {
            Integer::I16(val as i16)
        } else if val >= i32::MIN as i64 && val <= i32::MAX as i64 {
            Integer::I32(val as i32)
        } else {
            Integer::I64(val)
        }
    }
}

impl From<usize> for Integer {
    fn from(val: usize) -> Self {
        Integer::from_unsigned(val as u64)
    }
}

impl From<u32> for Integer {
    fn from(val: u32) -> Self {
        Integer::from_unsigned(val as u64)
    }
}

impl From<u64> for Integer {
    fn from(val: u64) -> Self {
        Integer::from_unsigned(val)
    }
}

impl From<i64> for Integer {
    fn from(val: i64) -> Self {
        Integer::from_signed(val)
    }
}

impl<Ctx: Copy> Decode<Ctx> for Integer {
    fn decode<R>(_ctx: Ctx, reader: &mut R) -> Result<Self, declio::Error>
    where
        R: io::Read,
    {
        match u16::decode(constants::ENDIANESS, reader)? {
            val if val < constants::LF_NUMERIC => Ok(Integer::U16(val)),
            constants::LF_CHAR => Ok(Integer::U8(u8::decode(constants::ENDIANESS, reader)?)),
            constants::LF_SHORT => Ok(Integer::I16(i16::decode(constants::ENDIANESS, reader)?)),
            constants::LF_USHORT => Ok(Integer::U16(u16::decode(constants::ENDIANESS, reader)?)),
            constants::LF_LONG => Ok(Integer::I32(i32::decode(constants::ENDIANESS, reader)?)),
            constants::LF_ULONG => Ok(Integer::U32(u32::decode(constants::ENDIANESS, reader)?)),
            constants::LF_QUADWORD => Ok(Integer::I64(i64::decode(constants::ENDIANESS, reader)?)),
            constants::LF_UQUADWORD => Ok(Integer::U64(u64::decode(constants::ENDIANESS, reader)?)),
            val => Err(declio::Error::new(format!(
                "unsupported numeric leaf type 0x{:04x}",
                val
            ))),
        }
    }
}

impl<Ctx> Encode<Ctx> for Integer {
    fn encode<W>(&self, _ctx: Ctx, writer: &mut W) -> Result<(), declio::Error>
    where
        W: io::Write,
    {
        match self {
            Integer::I16(i) => {
                constants::LF_SHORT.encode(constants::ENDIANESS, writer)?;
                i.encode(constants::ENDIANESS, writer)
            }
            Integer::I32(i) => {
                constants::LF_LONG.encode(constants::ENDIANESS, writer)?;
                i.encode(constants::ENDIANESS, writer)
            }
            Integer::I64(i) => {
                constants::LF_QUADWORD.encode(constants::ENDIANESS, writer)?;
                i.encode(constants::ENDIANESS, writer)
            }
            Integer::U32(i) => {
                constants::LF_ULONG.encode(constants::ENDIANESS, writer)?;
                i.encode(constants::ENDIANESS, writer)
            }
            Integer::U64(i) => {
                constants::LF_UQUADWORD.encode(constants::ENDIANESS, writer)?;
                i.encode(constants::ENDIANESS, writer)
            }
            Integer::U8(i) => u16::from(*i).encode(constants::ENDIANESS, writer),
            Integer::U16(i) => {
                if *i >= constants::LF_NUMERIC {
                    constants::LF_USHORT.encode(constants::ENDIANESS, writer)?;
                }
                i.encode(constants::ENDIANESS, writer)
            }
        }
    }
}

impl<Ctx> EncodedSize<Ctx> for Integer {
    fn encoded_size(&self, _ctx: Ctx) -> usize {
        match self {
            Integer::I16(_) => 4,
            Integer::U16(i) if *i >= constants::LF_NUMERIC => 4,
            Integer::U8(_) | Integer::U16(_) => 2,
            Integer::I32(_) | Integer::U32(_) => 6,
            Integer::I64(_) | Integer::U64(_) => 10,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    fn value(integer: &Integer) -> i128 {
        match *integer {
            Integer::I16(i) => i.into(),
            Integer::I32(i) => i.into(),
            Integer::I64(i) => i.into(),
            Integer::U8(i) => i.into(),
            Integer::U16(i) => i.into(),
            Integer::U32(i) => i.into(),
            Integer::U64(i) => i.into(),
        }
    }

    #[test]
    fn numeric_leaf_bytes_and_sizes() {
        let cases: &[(Integer, &[u8])] = &[
            (Integer::U8(255), &[0xff, 0x00]),
            (Integer::U16(0), &[0x00, 0x00]),
            (Integer::U16(0x7fff), &[0xff, 0x7f]),
            (Integer::U16(0x8000), &[0x02, 0x80, 0x00, 0x80]),
            (Integer::U16(0xffff), &[0x02, 0x80, 0xff, 0xff]),
            (Integer::I16(-2), &[0x01, 0x80, 0xfe, 0xff]),
            (Integer::I32(-2), &[0x03, 0x80, 0xfe, 0xff, 0xff, 0xff]),
            (Integer::U32(0x10000), &[0x04, 0x80, 0x00, 0x00, 0x01, 0x00]),
            (
                Integer::I64(-2),
                &[0x09, 0x80, 0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
            ),
            (
                Integer::U64(u64::MAX),
                &[0x0a, 0x80, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
            ),
        ];
        for (integer, expected) in cases {
            let mut bytes = Vec::new();
            integer.encode((), &mut bytes).unwrap();
            assert_eq!(bytes, *expected);
            assert_eq!(integer.encoded_size(()), expected.len());
            let mut reader = Cursor::new(bytes);
            let decoded = Integer::decode((), &mut reader).unwrap();
            assert_eq!(value(&decoded), value(integer));
            assert_eq!(reader.position(), expected.len() as u64);
        }
    }

    #[test]
    fn unsigned_constructor_boundaries() {
        for input in [0, 255, 0x7fff, 0x8000, u16::MAX as u64] {
            assert!(
                matches!(Integer::from_unsigned(input), Integer::U16(i) if u64::from(i) == input)
            );
        }
        for input in [u16::MAX as u64 + 1, u32::MAX as u64] {
            assert!(
                matches!(Integer::from_unsigned(input), Integer::U32(i) if u64::from(i) == input)
            );
        }
        for input in [u32::MAX as u64 + 1, u64::MAX] {
            assert!(matches!(Integer::from_unsigned(input), Integer::U64(i) if i == input));
        }
    }

    #[test]
    fn rejects_truncated_and_unsupported_numeric_leaves() {
        for bytes in [
            &[][..],
            &[0x02],
            &[0x02, 0x80],
            &[0x02, 0x80, 0xff],
            &[0xff, 0xff],
        ] {
            assert!(Integer::decode((), &mut Cursor::new(bytes)).is_err());
        }
    }
}
