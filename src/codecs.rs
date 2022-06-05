pub use declio::util::byte_array;

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
            elems.push(A::decode(ctx, &mut slice)?);

            let read = rem - slice.len();
            if read % RECORD_ALIGNMENT != 0 {
                let padding = RECORD_ALIGNMENT - (read % RECORD_ALIGNMENT);
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
            let padding = RECORD_ALIGNMENT - (size % RECORD_ALIGNMENT);
            if padding != 0 {
                let pad_byte = padding as u8 | 0x0F;
                let padding_bytes = [0u8; RECORD_ALIGNMENT];
                writer.write_all(&[pad_byte])?;
                writer.write_all(&padding_bytes[0..padding - 1])?;
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
                <$ty as ::modular_bitfield::Specifier>::from_bytes(val).map_err(::declio::Error::new)
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
