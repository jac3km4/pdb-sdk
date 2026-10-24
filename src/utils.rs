//! String encoding and internal alignment/comparison helpers.

use std::cmp::Ordering;
use std::{fmt, io};

use declio::{Decode, Encode, EncodedSize};

pub(crate) const fn align_to(val: usize, align: usize) -> usize {
    val.div_ceil(align) * align
}

/// An owned UTF-8 string encoded as NUL-terminated bytes by `declio`.
///
/// Decoding rejects invalid UTF-8. Construction does not reject embedded NULs;
/// such a value will decode only up to its first NUL when read back.
#[derive(Default)]
pub struct StrBuf(Box<str>);

impl StrBuf {
    /// Wraps a string without validating it for the NUL-terminated wire format.
    pub fn new<S: Into<Box<str>>>(str: S) -> Self {
        Self(str.into())
    }
}

impl fmt::Debug for StrBuf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self.0, f)
    }
}

impl From<&str> for StrBuf {
    fn from(s: &str) -> Self {
        Self(s.into())
    }
}

impl From<&String> for StrBuf {
    fn from(s: &String) -> Self {
        Self(s.as_str().into())
    }
}

impl From<String> for StrBuf {
    fn from(s: String) -> Self {
        Self(s.into())
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

/// LLVM GSI ordering: byte length first, then ASCII-insensitive comparison
/// only when both names are ASCII; otherwise compare the original bytes.
#[derive(Debug)]
pub(crate) struct CaseInsensitiveStr<'a>(pub &'a str);

impl<'a> Eq for CaseInsensitiveStr<'a> {}

impl<'a> PartialEq for CaseInsensitiveStr<'a> {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
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
        self.0.len().cmp(&other.0.len()).then_with(|| {
            if self.0.is_ascii() && other.0.is_ascii() {
                self.0
                    .bytes()
                    .map(|byte| byte.to_ascii_lowercase())
                    .cmp(other.0.bytes().map(|byte| byte.to_ascii_lowercase()))
            } else {
                self.0.as_bytes().cmp(other.0.as_bytes())
            }
        })
    }
}
