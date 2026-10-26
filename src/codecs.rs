//! `declio` adapters for PDB record fields and bounded record remainders.
//!
//! Remainder decoders read to EOF, so callers must limit the reader to the
//! containing record or region. PDB numeric fields use little-endian encoding;
//! see LLVM's [PDB documentation](https://llvm.org/docs/PDB/index.html).

use std::io::Read;

pub use declio::util::byte_array;

/// Reads only bytes actually supplied, without reserving an untrusted extent.
pub(crate) fn read_bytes<R: std::io::Read>(
    reader: &mut R,
    size: u64,
) -> Result<Vec<u8>, declio::Error> {
    let mut region = reader.take(size);
    let mut bytes = Vec::new();
    let mut scratch = [0; 8192];
    while region.limit() != 0 {
        let count = match region.read(&mut scratch) {
            Ok(0) => return Err(declio::Error::new("truncated byte region")),
            Ok(count) => count,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error.into()),
        };
        bytes
            .try_reserve(count)
            .map_err(|_| declio::Error::new("byte region allocation failed"))?;
        bytes.extend_from_slice(&scratch[..count]);
    }
    Ok(bytes)
}

/// A byte region whose size is supplied by its containing header.
pub(crate) mod sized_bytes {
    pub fn decode<R: std::io::Read>(size: u64, reader: &mut R) -> Result<Vec<u8>, declio::Error> {
        super::read_bytes(reader, size)
    }

    pub fn encode<W: std::io::Write>(
        bytes: &[u8],
        _: u64,
        writer: &mut W,
    ) -> Result<(), declio::Error> {
        writer.write_all(bytes)?;
        Ok(())
    }
}

/// A u32-length-prefixed byte region, allocated incrementally on decode.
pub(crate) mod prefixed_bytes {
    use declio::{Decode, Encode};

    pub fn decode<Ctx, R: std::io::Read>(_: Ctx, reader: &mut R) -> Result<Vec<u8>, declio::Error> {
        let size = u32::decode(crate::constants::ENDIANESS, reader)?;
        super::read_bytes(reader, u64::from(size))
    }

    pub fn encode<Ctx, W: std::io::Write>(
        bytes: &[u8],
        _: Ctx,
        writer: &mut W,
    ) -> Result<(), declio::Error> {
        let size = u32::try_from(bytes.len())
            .map_err(|_| declio::Error::new("byte region exceeds u32 length"))?;
        size.encode(crate::constants::ENDIANESS, writer)?;
        writer.write_all(bytes)?;
        Ok(())
    }

    pub fn encoded_size<Ctx>(bytes: &[u8], _: Ctx) -> usize {
        4 + bytes.len()
    }
}

/// Fixed-count elements allocated only after each element decodes successfully.
pub(crate) mod fixed_list {
    use declio::ctx::Len;
    use declio::{Decode, Encode};

    pub fn decode<T: Decode<Ctx>, Ctx: Copy, R: std::io::Read>(
        (Len(count), ctx): (Len, Ctx),
        reader: &mut R,
    ) -> Result<Vec<T>, declio::Error> {
        let mut records = Vec::new();
        for _ in 0..count {
            records.push(T::decode(ctx, reader)?);
        }
        Ok(records)
    }

    pub fn encode<T: Encode<Ctx>, Ctx: Copy, W: std::io::Write>(
        records: &[T],
        (_, ctx): (Len, Ctx),
        writer: &mut W,
    ) -> Result<(), declio::Error> {
        for record in records {
            record.encode(ctx, writer)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use declio::{Decode, Encode, EncodedSize};

    use super::*;

    struct NoProgress;

    impl Decode for NoProgress {
        fn decode<R: std::io::Read>((): (), _reader: &mut R) -> Result<Self, declio::Error> {
            Ok(Self)
        }
    }

    #[derive(Debug, PartialEq, Encode, Decode, EncodedSize)]
    struct Byte(u8);

    #[test]
    fn optional_symbol_offsets_roundtrip() {
        use crate::primitives::SymbolOffset;

        for (value, expected) in [
            (None, [0, 0, 0, 0]),
            (
                Some(SymbolOffset::from(0x12345678)),
                [0x78, 0x56, 0x34, 0x12],
            ),
        ] {
            let mut bytes = vec![];
            optional_non_zero::encode(&value, (), &mut bytes).unwrap();
            assert_eq!(bytes, expected);
            bytes.push(0xaa);
            let mut reader = bytes.as_slice();
            assert_eq!(
                optional_non_zero::decode::<SymbolOffset, _, _>((), &mut reader).unwrap(),
                value
            );
            assert_eq!(reader, [0xaa]);
        }

        assert!(optional_non_zero::decode::<SymbolOffset, _, _>((), &mut &[0, 0, 0][..]).is_err());
        // Zero remains valid when an offset is not an optional link.
        assert_eq!(
            SymbolOffset::decode((), &mut &[0; 4][..]).unwrap(),
            SymbolOffset::from(0)
        );
    }

    #[test]
    fn optional_type_indices_decode() {
        use crate::primitives::TypeIndex;

        assert_eq!(
            optional_non_zero::decode::<TypeIndex, _, _>((), &mut &[0; 4][..]).unwrap(),
            None
        );
        assert_eq!(
            optional_non_zero::decode::<TypeIndex, _, _>((), &mut &[1, 0x10, 0, 0][..]).unwrap(),
            Some(TypeIndex::try_from(0x1001).unwrap())
        );
    }

    #[test]
    fn lists_reject_no_progress() {
        assert!(rem_list::decode::<NoProgress, _, _>((), &mut &[1][..]).is_err());
        assert!(padded_rem_list::decode::<NoProgress, _, _>((), &mut &[1, 2, 3, 4][..]).is_err());
        assert!(
            rem_list::decode::<NoProgress, _, _>((), &mut &[][..])
                .unwrap()
                .is_empty()
        );
        assert!(
            padded_rem_list::decode::<NoProgress, _, _>((), &mut &[][..])
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn remaining_lists_roundtrip() {
        let elems = [Byte(1), Byte(2)];
        let mut bytes = vec![];
        rem_list::encode(&elems, (), &mut bytes).unwrap();
        assert_eq!(bytes, [1, 2]);
        assert_eq!(rem_list::encoded_size(&elems, ()), bytes.len());
        assert_eq!(
            rem_list::decode::<Byte, _, _>((), &mut bytes.as_slice()).unwrap(),
            elems
        );
        bytes.clear();
        padded_rem_list::encode(&elems, (), &mut bytes).unwrap();
        assert_eq!(bytes, [1, 0xf3, 0xf2, 0xf1, 2, 0xf3, 0xf2, 0xf1]);
        assert_eq!(padded_rem_list::encoded_size(&elems, ()), bytes.len());
        assert_eq!(
            padded_rem_list::decode::<Byte, _, _>((), &mut bytes.as_slice()).unwrap(),
            elems
        );
        assert!(padded_rem_list::decode::<Byte, _, _>((), &mut &[1, 0xf2, 0xf1][..]).is_err());
    }
}

/// Count-prefixed lists. Decode incrementally rather than reserving an
/// untrusted count before any element has been read.
macro_rules! counted_list {
    ($name:ident, $count:ty) => {
        pub mod $name {
            use declio::{Decode, Encode, EncodedSize};

            use crate::constants;

            pub fn decode<A, Ctx: Copy, R: std::io::Read>(
                ctx: Ctx,
                reader: &mut R,
            ) -> Result<Vec<A>, declio::Error>
            where
                A: Decode<Ctx>,
            {
                let count = <$count>::decode(constants::ENDIANESS, reader)?;
                let mut elems = Vec::new();
                for _ in 0..count {
                    elems.push(A::decode(ctx, reader)?);
                }
                Ok(elems)
            }

            pub fn encode<A, Ctx: Copy, W: std::io::Write>(
                elems: &[A],
                ctx: Ctx,
                writer: &mut W,
            ) -> Result<(), declio::Error>
            where
                A: Encode<Ctx>,
            {
                let count = <$count>::try_from(elems.len())
                    .map_err(|_| declio::Error::new("list count exceeds wire limit"))?;
                count.encode(constants::ENDIANESS, writer)?;
                super::rem_list::encode(elems, ctx, writer)
            }

            pub fn encoded_size<A: EncodedSize<Ctx>, Ctx: Copy>(elems: &[A], ctx: Ctx) -> usize {
                std::mem::size_of::<$count>() + super::rem_list::encoded_size(elems, ctx)
            }
        }
    };
}

counted_list!(counted_u16, u16);
counted_list!(counted_u32, u32);

/// `LF_INDEX` stores a reserved u16 before its continuation type index.
pub mod list_continuation {
    use declio::{Decode, Encode};

    use crate::{TypeIndex, constants};

    pub fn decode<Ctx, R: std::io::Read>(
        _ctx: Ctx,
        reader: &mut R,
    ) -> Result<TypeIndex, declio::Error> {
        let _reserved = u16::decode(constants::ENDIANESS, reader)?;
        TypeIndex::decode((), reader)
    }

    pub fn encode<Ctx, W: std::io::Write>(
        index: &TypeIndex,
        _ctx: Ctx,
        writer: &mut W,
    ) -> Result<(), declio::Error> {
        0u16.encode(constants::ENDIANESS, writer)?;
        index.encode((), writer)
    }

    pub fn encoded_size<Ctx>(_index: &TypeIndex, _ctx: Ctx) -> usize {
        6
    }
}

/// NUL-terminated strings followed by a final empty string, as in LLVM's
/// `mapStringZVectorZ`. An empty vector is encoded as a single NUL.
pub mod string_vector_z {
    use declio::{Decode, Encode, EncodedSize};

    use crate::utils::StrBuf;

    pub fn decode<Ctx: Copy, R: std::io::Read>(
        ctx: Ctx,
        reader: &mut R,
    ) -> Result<Vec<StrBuf>, declio::Error> {
        let mut strings = Vec::new();
        loop {
            let string = StrBuf::decode(ctx, reader)?;
            if string.as_ref().is_empty() {
                return Ok(strings);
            }
            strings.push(string);
        }
    }

    pub fn encode<Ctx: Copy, W: std::io::Write>(
        strings: &[StrBuf],
        ctx: Ctx,
        writer: &mut W,
    ) -> Result<(), declio::Error> {
        // Empty strings would terminate the vector early; embedded NULs would
        // split an element and make the decoded vector differ from the input.
        if strings
            .iter()
            .any(|s| s.as_ref().is_empty() || s.as_ref().contains('\0'))
        {
            return Err(declio::Error::new("invalid string-vector element"));
        }
        super::rem_list::encode(strings, ctx, writer)?;
        0u8.encode((), writer)
    }

    pub fn encoded_size<Ctx: Copy>(strings: &[StrBuf], ctx: Ctx) -> usize {
        1 + strings.iter().map(|s| s.encoded_size(ctx)).sum::<usize>()
    }
}

/// Four-byte little-endian optional non-zero number adapter.
///
/// Encoding writes zero for `None`; decoding maps zero to `None` before
/// converting the index.
pub mod optional_non_zero {
    use declio::{Decode, Encode, Error};

    use crate::constants;

    #[inline]
    pub fn encode<A, Ctx, W>(val: &Option<A>, _ctx: Ctx, writer: &mut W) -> Result<(), Error>
    where
        A: Into<u32> + Copy,
        W: std::io::Write,
    {
        let val = val.map_or(0, Into::into);
        u32::encode(&val, constants::ENDIANESS, writer)
    }

    #[inline]
    pub fn decode<A, Ctx, R>(_ctx: Ctx, reader: &mut R) -> Result<Option<A>, Error>
    where
        A: TryFrom<u32>,
        R: std::io::Read,
    {
        let value = u32::decode(constants::ENDIANESS, reader)?;
        if value == 0 {
            return Ok(None);
        }
        Ok(A::try_from(value).ok())
    }

    #[inline]
    pub fn encoded_size<A, Ctx>(_val: &A, _ctx: Ctx) -> usize {
        std::mem::size_of::<u32>()
    }
}

/// Uncounted list occupying the reader's remaining bytes, without padding.
///
/// Decoding rejects elements that consume no bytes.
pub mod rem_list {
    #[cfg(test)]
    use declio::Decode;
    use declio::{Encode, EncodedSize};

    #[cfg(test)]
    pub fn decode<A, Ctx, R>(ctx: Ctx, reader: &mut R) -> Result<Vec<A>, declio::Error>
    where
        A: Decode<Ctx>,
        R: std::io::Read,
        Ctx: Copy,
    {
        let mut buf = vec![];
        reader.read_to_end(&mut buf)?;
        let mut elems = vec![];
        let mut slice = &buf[..];
        while !slice.is_empty() {
            let before = slice.len();
            let elem = A::decode(ctx, &mut slice)?;
            if slice.len() >= before {
                return Err(declio::Error::new("rem_list: decoder made no progress"));
            }
            elems.push(elem);
        }
        Ok(elems)
    }

    pub fn encode<A, Ctx, W>(elems: &[A], ctx: Ctx, writer: &mut W) -> Result<(), declio::Error>
    where
        A: Encode<Ctx>,
        W: std::io::Write,
        Ctx: Copy,
    {
        for elem in elems {
            elem.encode(ctx, writer)?;
        }
        Ok(())
    }

    #[inline]
    pub fn encoded_size<A, Ctx>(elems: &[A], ctx: Ctx) -> usize
    where
        A: EncodedSize<Ctx>,
        Ctx: Copy,
    {
        elems.iter().map(|el| el.encoded_size(ctx)).sum()
    }
}

/// Raw bytes occupying the reader's remainder, with no length prefix.
pub mod rem_bytes {
    pub fn decode<Ctx, R>(_ctx: Ctx, reader: &mut R) -> Result<Vec<u8>, declio::Error>
    where
        R: std::io::Read,
    {
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf)?;
        Ok(buf)
    }

    pub fn encode<Ctx, W>(val: &[u8], _ctx: Ctx, writer: &mut W) -> Result<(), declio::Error>
    where
        W: std::io::Write,
    {
        writer.write_all(val)?;
        Ok(())
    }

    #[inline]
    pub fn encoded_size<Ctx>(val: &[u8], _ctx: Ctx) -> usize {
        val.len()
    }
}

/// Uncounted list with each element padded to a multiple of four bytes.
///
/// Encoding writes descending `LF_PADn` bytes. Decoding skips the implied
/// padding without checking its contents and rejects missing padding or
/// elements that consume no bytes. No per-element length prefix is added.
pub mod padded_rem_list {
    use declio::{Decode, Encode, EncodedSize};

    use crate::codeview::RECORD_ALIGNMENT;
    use crate::utils::align_to;

    pub fn decode<A, Ctx, R>(ctx: Ctx, reader: &mut R) -> Result<Vec<A>, declio::Error>
    where
        A: Decode<Ctx>,
        R: std::io::Read,
        Ctx: Copy,
    {
        let mut buf = vec![];
        reader.read_to_end(&mut buf)?;

        let mut elems = vec![];
        let mut slice = &buf[..];
        let mut rem = slice.len();
        while !slice.is_empty() {
            let elem = A::decode(ctx, &mut slice)?;
            if slice.len() >= rem {
                return Err(declio::Error::new(
                    "padded_rem_list: decoder made no progress",
                ));
            }
            elems.push(elem);
            let read = rem - slice.len();

            // If the inner decoder under-consumed the on-disk record, the
            // buffer may not hold the full implied padding slot; return a
            // structured error instead of panicking on out-of-range slicing.
            if read % RECORD_ALIGNMENT != 0 {
                let padding = RECORD_ALIGNMENT - (read % RECORD_ALIGNMENT);
                if slice.len() < padding {
                    return Err(declio::Error::new(format!(
                        "padded_rem_list: inner decoder under-consumed (read {read} bytes, needs {padding} pad bytes, only {} remain)",
                        slice.len()
                    )));
                }
                slice = &slice[padding..];
            }
            rem = slice.len();
        }
        Ok(elems)
    }

    pub fn encode<A, Ctx, W>(elems: &[A], ctx: Ctx, writer: &mut W) -> Result<(), declio::Error>
    where
        A: Encode<Ctx> + EncodedSize<Ctx>,
        W: std::io::Write,
        Ctx: Copy,
    {
        for elem in elems {
            elem.encode(ctx, writer)?;

            let size = elem.encoded_size(ctx);
            let padding = align_to(size, RECORD_ALIGNMENT) - size;
            // CodeView padding is a descending run of LF_PADn markers
            for i in (1..=padding).rev() {
                writer.write_all(&[i as u8 | crate::constants::LF_PAD0])?;
            }
        }
        Ok(())
    }

    #[inline]
    pub fn encoded_size<A, Ctx>(elems: &[A], ctx: Ctx) -> usize
    where
        A: EncodedSize<Ctx>,
        Ctx: Copy,
    {
        let mut size = 0;
        for el in elems {
            size += el.encoded_size(ctx);
            size = align_to(size, RECORD_ALIGNMENT);
        }
        size
    }
}

/// Implements `declio` codecs using a bitfield's byte-array conversion methods.
#[macro_export]
macro_rules! impl_bitfield_codecs {
    ($ty:ty) => {
        impl<Ctx: Copy> Decode<Ctx> for $ty {
            #[inline]
            fn decode<R>(ctx: Ctx, reader: &mut R) -> Result<Self, ::declio::Error>
            where
                R: ::std::io::Read,
            {
                let bytes = ::declio::util::byte_array::decode(ctx, reader)?;
                Ok(<$ty>::from_bytes(bytes))
            }
        }

        impl<Ctx> Encode<Ctx> for $ty {
            #[inline]
            fn encode<W>(&self, _ctx: Ctx, writer: &mut W) -> Result<(), ::declio::Error>
            where
                W: ::std::io::Write,
            {
                writer.write_all(&self.into_bytes())?;
                Ok(())
            }
        }

        impl<Ctx> EncodedSize<Ctx> for $ty {
            #[inline]
            fn encoded_size(&self, _ctx: Ctx) -> usize {
                ::std::mem::size_of_val(self)
            }
        }
    };
}

/// Implements little-endian `declio` codecs for a `modular_bitfield` specifier.
///
/// Invalid specifier values are returned as codec errors.
#[macro_export]
macro_rules! impl_bitfield_specifier_codecs {
    ($ty:ty) => {
        impl<Ctx> ::declio::Decode<Ctx> for $ty {
            fn decode<R>(_ctx: Ctx, reader: &mut R) -> Result<Self, ::declio::Error>
            where
                R: ::std::io::Read,
            {
                let val = ::declio::Decode::decode($crate::constants::ENDIANESS, reader)?;
                <$ty as ::modular_bitfield::Specifier>::from_bytes(val)
                    .map_err(::declio::Error::new)
            }
        }

        impl<Ctx> ::declio::Encode<Ctx> for $ty {
            fn encode<W>(&self, _ctx: Ctx, writer: &mut W) -> Result<(), ::declio::Error>
            where
                W: ::std::io::Write,
            {
                <$ty as ::modular_bitfield::Specifier>::into_bytes(*self)
                    .map_err(declio::Error::new)?
                    .encode($crate::constants::ENDIANESS, writer)
            }
        }

        impl<Ctx> EncodedSize<Ctx> for $ty {
            #[inline]
            fn encoded_size(&self, _ctx: Ctx) -> usize {
                ::std::mem::size_of::<<$ty as ::modular_bitfield::Specifier>::Bytes>()
            }
        }
    };
}
