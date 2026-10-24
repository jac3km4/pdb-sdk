pub use declio::util::byte_array;

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

pub mod optional_index {
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
        match A::try_from(u32::decode(constants::ENDIANESS, reader)?) {
            Err(_) => Ok(None),
            Ok(i) => Ok(Some(i)),
        }
    }

    #[inline]
    pub fn encoded_size<A, Ctx>(_val: &A, _ctx: Ctx) -> usize {
        std::mem::size_of::<u32>()
    }
}

pub mod rem_list {
    use declio::{Decode, Encode, EncodedSize};

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
