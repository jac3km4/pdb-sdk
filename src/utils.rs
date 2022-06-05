use std::cmp::Ordering;
use std::io;

use declio::{Decode, Encode, EncodedSize};

pub(crate) fn div_ceil(lhs: u32, rhs: u32) -> u32 {
    (lhs + rhs - 1) / rhs
}

pub(crate) const fn align_to(val: usize, align: usize) -> usize {
    (val + align - 1) / align * align
}

#[derive(Debug, Default)]
pub struct StrBuf(Box<str>);

impl StrBuf {
    pub fn new<S: Into<Box<str>>>(str: S) -> Self {
        Self(str.into())
    }
}

impl AsRef<str> for StrBuf {
    #[inline]
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl<Ctx> Decode<Ctx> for StrBuf {
    fn decode<R>(_ctx: Ctx, reader: &mut R) -> Result<Self, declio::Error>
    where
        R: io::Read,
    {
        let mut buf = vec![];
        loop {
            let byte = u8::decode((), reader)?;
            if byte == 0 {
                let str = String::from_utf8(buf).map_err(declio::Error::wrap)?;
                return Ok(StrBuf(str.into_boxed_str()));
            }
            buf.push(byte);
        }
    }
}

impl<Ctx> Encode<Ctx> for StrBuf {
    fn encode<W>(&self, _ctx: Ctx, writer: &mut W) -> Result<(), declio::Error>
    where
        W: io::Write,
    {
        self.0.as_bytes().encode(((),), writer)?;
        0u8.encode((), writer)
    }
}

impl<Ctx> EncodedSize<Ctx> for StrBuf {
    fn encoded_size(&self, _ctx: Ctx) -> usize {
        self.0.len() + 1
    }
}

#[derive(Debug)]
pub(crate) struct CaseInsensitiveStr<'a>(pub &'a str);

impl<'a> Eq for CaseInsensitiveStr<'a> {}

impl<'a> PartialEq for CaseInsensitiveStr<'a> {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.0.eq_ignore_ascii_case(other.0)
    }
}

impl<'a> PartialOrd for CaseInsensitiveStr<'a> {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<'a> Ord for CaseInsensitiveStr<'a> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0
            .chars()
            .map(CaseInsensitiveChar)
            .cmp(other.0.chars().map(CaseInsensitiveChar))
    }
}

#[derive(Debug)]
pub(crate) struct CaseInsensitiveChar(pub char);

impl PartialEq for CaseInsensitiveChar {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.0.eq_ignore_ascii_case(&other.0)
    }
}

impl Eq for CaseInsensitiveChar {}

impl PartialOrd for CaseInsensitiveChar {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for CaseInsensitiveChar {
    #[inline]
    fn cmp(&self, other: &Self) -> Ordering {
        if self.0.eq_ignore_ascii_case(&other.0) {
            Ordering::Equal
        } else {
            self.0.cmp(&other.0)
        }
    }
}
