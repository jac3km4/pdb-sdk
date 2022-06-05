use std::cmp::Ordering;
use std::io::{self, Read};

use declio::{Decode, Encode, EncodedSize};
use symbols::{Public, SymbolRecord};

use crate::constants;
use crate::utils::align_to;

pub mod symbols;
pub mod types;

pub(crate) const RECORD_ALIGNMENT: usize = 4;

#[derive(Debug)]
pub(crate) struct PrefixedRecord<A>(pub A);

impl<A> PrefixedRecord<A> {
    pub fn into_inner(self) -> A {
        self.0
    }
}

impl<A> PrefixedRecord<A> {
    pub fn decode<R>(reader: &mut R) -> Result<Self, declio::Error>
    where
        A: Decode,
        R: io::Read,
    {
        let len = u16::decode(constants::ENDIANESS, reader)?;
        let mut slice = reader.take(len.into());
        let res = A::decode((), &mut slice)?;

        let mut padding_buffer = [0; 16];
        while slice.limit() != 0 {
            let byte = u8::decode((), &mut slice)?;
            if (constants::LF_PAD0..=constants::LF_PAD15).contains(&byte) {
                let padding = (byte & 0x0F) - 1;
                slice.read_exact(&mut padding_buffer[..padding as usize])?;
            } else if byte != 0 {
                return Err(declio::Error::new(format!("invalid pading byte {}", byte)));
            }
        }
        Ok(Self(res))
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
        let padding_bytes = [0u8; RECORD_ALIGNMENT];

        let size = self.0.encoded_size(());
        let full_size = align_to(size + PREFIX_SIZE, RECORD_ALIGNMENT) - PREFIX_SIZE;
        (full_size as u16).encode(constants::ENDIANESS, writer)?;
        self.0.encode((), writer)?;

        let padding = full_size - size;
        if padding != 0 {
            let pad_byte = padding as u8 | 0xF0;
            writer.write_all(&[pad_byte])?;
            writer.write_all(&padding_bytes[0..padding - 1])?;
        }
        Ok(())
    }
}

#[derive(Debug, PartialEq, Eq, Encode, Decode, EncodedSize)]
#[declio(ctx_is = "constants::ENDIANESS")]
pub struct DataRegionOffset {
    pub offset: u32,
    pub segment: u16,
}

impl DataRegionOffset {
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
