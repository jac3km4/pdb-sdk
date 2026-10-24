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

    // Byte fixtures follow LLVM release/18.x TypeRecordMapping,
    // SymbolRecordMapping, and CodeViewRecordIO (not encoder-derived fixtures).
    fn exact_record<A: Encode + Decode + EncodedSize>(record: &A, expected: &[u8]) -> A {
        for end in 0..expected.len() {
            assert!(
                A::decode((), &mut &expected[..end]).is_err(),
                "prefix {end}"
            );
        }
        exact_bytes(record, expected)
    }

    fn exact_bytes<A: Encode + Decode + EncodedSize>(record: &A, expected: &[u8]) -> A {
        let mut encoded = Vec::new();
        record.encode((), &mut encoded).unwrap();
        assert_eq!(encoded, expected);
        assert_eq!(record.encoded_size(()), expected.len());
        let mut input = expected;
        let decoded = A::decode((), &mut input).unwrap();
        assert!(input.is_empty());
        let mut reencoded = Vec::new();
        decoded.encode((), &mut reencoded).unwrap();
        assert_eq!(reencoded, expected);
        assert_eq!(decoded.encoded_size(()), expected.len());
        decoded
    }

    fn framed_position<A: Encode + EncodedSize + Decode>(record: A) {
        let size = record.encoded_size(());
        let mut bytes = Vec::new();
        PrefixedRecord(record).encode((), &mut bytes).unwrap();
        let end = align_to(size + 2, 4);
        assert_eq!(bytes.len(), end);
        assert_eq!(&bytes[..2], &((end - 2) as u16).to_le_bytes());
        let padding: Vec<_> = (1..=end - size - 2).rev().map(|n| 0xf0 | n as u8).collect();
        assert_eq!(&bytes[size + 2..], padding);
        bytes.extend_from_slice(&[2, 0, 0x34, 0x12]);
        let mut cursor = io::Cursor::new(bytes);
        let (_, consumed) = PrefixedRecord::<A>::decode_with_size(&mut cursor).unwrap();
        assert_eq!(consumed, end as u64);
        assert_eq!(cursor.position(), end as u64);
        assert_eq!(
            PrefixedRecord::<Kind>::decode_with_size(&mut cursor)
                .unwrap()
                .0
                .into_inner(),
            Kind(0x1234)
        );
    }

    #[test]
    fn review_list_continuation_layout() {
        use types::TypeRecord;
        let record = TypeRecord::ListContinuation(crate::TypeIndex::try_from(0x1234).unwrap());
        let decoded = exact_record(&record, &[0x04, 0x14, 0, 0, 0x34, 0x12, 0, 0]);
        assert!(
            matches!(decoded, TypeRecord::ListContinuation(index) if u32::from(index) == 0x1234)
        );
        // Reserved bytes are required but, like LLVM, need not be zero on read.
        let decoded =
            TypeRecord::decode((), &mut &[4, 0x14, 0xaa, 0xbb, 0x34, 0x12, 0, 0][..]).unwrap();
        assert!(
            matches!(decoded, TypeRecord::ListContinuation(index) if u32::from(index) == 0x1234)
        );
        framed_position(record);

        let record = TypeRecord::FieldList {
            fields: vec![
                TypeRecord::ListContinuation(crate::TypeIndex::try_from(0x1234).unwrap()),
                TypeRecord::Enumerator {
                    properties: types::MemberProperties::new(),
                    value: crate::Integer::from(1u32),
                    name: "x".into(),
                },
            ],
        };
        // A field list can end cleanly at any member boundary.
        let decoded = exact_bytes(
            &record,
            &[
                3, 0x12, 4, 0x14, 0, 0, 0x34, 0x12, 0, 0, 2, 0x15, 0, 0, 1, 0, b'x', 0,
            ],
        );
        assert!(
            matches!(decoded, TypeRecord::FieldList { fields } if fields.len() == 2 && matches!(&fields[0], TypeRecord::ListContinuation(index) if u32::from(*index) == 0x1234) && matches!(&fields[1], TypeRecord::Enumerator { name, .. } if name.as_ref() == "x"))
        );
        framed_position(record);
    }

    #[test]
    fn review_pointer_member_layout() {
        use types::{
            PointerMode, PointerProperties, PointerToMemberRepresentation as Rep, TypeRecord,
        };
        let reps = [
            Rep::Unknown,
            Rep::SingleInheritanceData,
            Rep::MultipleInheritanceData,
            Rep::VirtualInheritanceData,
            Rep::GeneralData,
            Rep::SingleInheritanceFunction,
            Rep::MultipleInheritanceFunction,
            Rep::VirtualInheritanceFunction,
            Rep::GeneralFunction,
        ];
        for (mode, attrs) in [
            (PointerMode::DataMember, 0x40),
            (PointerMode::MemberFunction, 0x60),
        ] {
            for (n, representation) in reps.iter().enumerate() {
                let record = TypeRecord::Pointer {
                    referent: Some(crate::TypeIndex::try_from(0x1234).unwrap()),
                    properties: PointerProperties::new().with_mode(mode),
                    containing_class: Some(crate::TypeIndex::try_from(0x5678).unwrap()),
                    representation: Some(*representation),
                };
                let expected = [
                    2, 0x10, 0x34, 0x12, 0, 0, attrs, 0, 0, 0, 0x78, 0x56, 0, 0, n as u8, 0,
                ];
                let decoded = exact_record(&record, &expected);
                assert!(
                    matches!(decoded, TypeRecord::Pointer { referent: Some(index), properties, containing_class: Some(class), representation: Some(rep) } if u32::from(index) == 0x1234 && properties.into_bytes() == [attrs, 0, 0, 0] && u32::from(class) == 0x5678 && rep == *representation)
                );
                framed_position(record);
            }
        }
        for (mode, attrs) in [
            (PointerMode::Vanilla, 0),
            (PointerMode::LValueReference, 0x20),
            (PointerMode::RValueReference, 0x80),
        ] {
            let record = TypeRecord::Pointer {
                referent: None,
                properties: PointerProperties::new().with_mode(mode),
                containing_class: None,
                representation: None,
            };
            let decoded = exact_record(&record, &[2, 0x10, 0, 0, 0, 0, attrs, 0, 0, 0]);
            assert!(
                matches!(decoded, TypeRecord::Pointer { referent: None, containing_class: None, representation: None, properties } if properties.into_bytes() == [attrs, 0, 0, 0])
            );
            framed_position(record);
        }
        assert!(
            TypeRecord::decode(
                (),
                &mut &[2, 0x10, 0, 0, 0, 0, 0x40, 0, 0, 0, 1, 0x10, 0, 0, 9, 0][..]
            )
            .is_err()
        );
    }

    #[test]
    fn review_counted_reference_symbols() {
        for kind in [0x1168u16, 0x115a, 0x115b] {
            for count in 0..=2 {
                let indices = || {
                    (0..count)
                        .map(|n| crate::TypeIndex::try_from(0x1234 + n).unwrap())
                        .collect()
                };
                let record = match kind {
                    0x1168 => SymbolRecord::Inlinees { types: indices() },
                    0x115a => SymbolRecord::Caller { types: indices() },
                    _ => SymbolRecord::Callee { types: indices() },
                };
                let mut expected = kind.to_le_bytes().to_vec();
                expected.extend_from_slice(&count.to_le_bytes());
                for n in 0..count {
                    expected.extend_from_slice(&(0x1234 + n).to_le_bytes());
                }
                let decoded = exact_record(&record, &expected);
                let types = match decoded {
                    SymbolRecord::Inlinees { types } if kind == 0x1168 => types,
                    SymbolRecord::Caller { types } if kind == 0x115a => types,
                    SymbolRecord::Callee { types } if kind == 0x115b => types,
                    _ => panic!("wrong decoded kind"),
                };
                assert_eq!(
                    types.iter().map(|i| u32::from(*i)).collect::<Vec<_>>(),
                    (0..count).map(|n| 0x1234 + n).collect::<Vec<_>>()
                );
                // A counted decoder must leave record padding/trailing bytes alone.
                let mut padded = expected.clone();
                padded.extend_from_slice(&[0xf2, 0xf1]);
                let mut input = padded.as_slice();
                SymbolRecord::decode((), &mut input).unwrap();
                assert_eq!(input, [0xf2, 0xf1]);
                framed_position(record);
            }
            let mut malformed = kind.to_le_bytes().to_vec();
            malformed.extend_from_slice(&u32::MAX.to_le_bytes());
            assert!(SymbolRecord::decode((), &mut malformed.as_slice()).is_err());
        }
    }

    #[test]
    fn review_annotation_count() {
        for strings in [vec![], vec![""], vec!["a", "bc"]] {
            let record = SymbolRecord::Annotation {
                code_offset: DataRegionOffset::new(0x1234_5678, 2),
                strings: strings.iter().map(|s| (*s).into()).collect(),
            };
            let mut expected = vec![0x19, 0x10, 0x78, 0x56, 0x34, 0x12, 2, 0];
            expected.extend_from_slice(&(strings.len() as u16).to_le_bytes());
            for s in &strings {
                expected.extend_from_slice(s.as_bytes());
                expected.push(0);
            }
            let decoded = exact_record(&record, &expected);
            assert!(
                matches!(decoded, SymbolRecord::Annotation { code_offset, strings: values } if code_offset == DataRegionOffset::new(0x1234_5678, 2) && values.iter().map(AsRef::as_ref).collect::<Vec<_>>() == strings)
            );
            framed_position(record);
        }
        for tail in [&[0xff, 0xff][..], &[2, 0, b'a', 0], &[1, 0, b'a']] {
            let mut bytes = vec![0x19, 0x10, 0, 0, 0, 0, 1, 0];
            bytes.extend_from_slice(tail);
            assert!(SymbolRecord::decode((), &mut bytes.as_slice()).is_err());
        }
        let strings = (0..=u16::MAX).map(|_| "".into()).collect();
        let record = SymbolRecord::Annotation {
            code_offset: DataRegionOffset::new(0, 1),
            strings,
        };
        assert!(record.encode((), &mut Vec::new()).is_err());
    }

    #[test]
    fn review_terminated_string_vectors() {
        use symbols::{CompileProperties, Version};
        for compile in [false, true] {
            for strings in [vec![], vec!["a"], vec!["a", "bc"]] {
                let values = || strings.iter().map(|s| (*s).into()).collect();
                let record = if compile {
                    SymbolRecord::Compile2 {
                        properties: CompileProperties::new(),
                        machine: 0xd0,
                        frontend_version: Version {
                            major: 1,
                            minor: 2,
                            build: 3,
                        },
                        backend_version: Version {
                            major: 4,
                            minor: 5,
                            build: 6,
                        },
                        version: "v".into(),
                        extra_settings: values(),
                    }
                } else {
                    SymbolRecord::EnvBlock {
                        reserved: 0,
                        fields: values(),
                    }
                };
                let mut expected = if compile {
                    vec![
                        0x16, 0x11, 0, 0, 0, 0, 0xd0, 0, 1, 0, 2, 0, 3, 0, 4, 0, 5, 0, 6, 0, b'v',
                        0,
                    ]
                } else {
                    vec![0x3d, 0x11, 0]
                };
                for s in &strings {
                    expected.extend_from_slice(s.as_bytes());
                    expected.push(0);
                }
                expected.push(0);
                let decoded = exact_record(&record, &expected);
                let values = match decoded {
                    SymbolRecord::EnvBlock { reserved, fields } if !compile => {
                        assert_eq!(reserved, 0);
                        fields
                    }
                    SymbolRecord::Compile2 {
                        properties,
                        machine,
                        frontend_version: front,
                        backend_version: back,
                        version,
                        extra_settings,
                    } if compile => {
                        assert_eq!(properties.into_bytes(), [0; 4]);
                        assert_eq!(machine, 0xd0);
                        assert_eq!((front.major, front.minor, front.build), (1, 2, 3));
                        assert_eq!((back.major, back.minor, back.build), (4, 5, 6));
                        assert_eq!(version.as_ref(), "v");
                        extra_settings
                    }
                    _ => panic!("wrong decoded kind"),
                };
                assert_eq!(
                    values.iter().map(AsRef::as_ref).collect::<Vec<_>>(),
                    strings
                );
                let mut padded = expected.clone();
                padded.extend_from_slice(&[0xf3, 0xf2, 0xf1]);
                let mut input = padded.as_slice();
                SymbolRecord::decode((), &mut input).unwrap();
                assert_eq!(input, [0xf3, 0xf2, 0xf1]);
                framed_position(record);
            }
        }
        for invalid in ["", "a\0b"] {
            assert!(
                SymbolRecord::EnvBlock {
                    reserved: 0,
                    fields: vec![invalid.into()]
                }
                .encode((), &mut Vec::new())
                .is_err()
            );
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
