use std::cmp::Ordering;
use std::io;

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
        let mut buf = vec![0u8; len];
        reader.read_exact(&mut buf)?;
        let mut slice: &[u8] = &buf;
        let res = A::decode((), &mut slice)?;
        Ok((Self(res), (len + 2) as u64))
    }

    /// Like [`Self::decode_with_size`], but returns `Ok(None)` when the next
    /// record's length prefix is `< 2` (no room for the kind tag). Some
    /// PDBs pad the tail of the global symbol stream with `00 00` to align
    /// the stream byte size.
    pub fn decode_or_terminator<R>(reader: &mut R) -> Result<Option<Self>, declio::Error>
    where
        A: Decode,
        R: io::Read,
    {
        let mut len_buf = [0u8; 2];
        match reader.read_exact(&mut len_buf) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(e) => return Err(e.into()),
        }
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
        let padding_bytes = [0u8; RECORD_ALIGNMENT];

        let size = self.0.encoded_size(());
        let full_size = align_to(size + PREFIX_SIZE, RECORD_ALIGNMENT) - PREFIX_SIZE;
        let full_size_u16 = u16::try_from(full_size).map_err(|_| {
            declio::Error::new(format!(
                "type record too large: {full_size} bytes exceeds u16 limit"
            ))
        })?;
        full_size_u16.encode(constants::ENDIANESS, writer)?;
        self.0.encode((), writer)?;

        let padding = full_size - size;
        if padding != 0 {
            let pad_byte = padding as u8 | constants::LF_PAD0;
            writer.write_all(&[pad_byte])?;
            writer.write_all(&padding_bytes[0..padding - 1])?;
        }
        Ok(())
    }
}

#[derive(Debug, PartialEq, Eq, Encode, Decode, EncodedSize)]
#[declio(ctx_is = "constants::ENDIANESS")]
/// Represents an offset into a data region, accompanied by its segment index.
pub struct DataRegionOffset {
    pub offset: u32,
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
/// Represents a hardware register index.
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
