use std::io::{self, Write};

use declio::{Encode, EncodedSize};

use super::StreamAllocator;
use crate::codeview::types::{IdRecord, TypeRecord};
use crate::codeview::{PrefixedRecord, RECORD_ALIGNMENT};
use crate::hash::{Table, hash_v1};
use crate::msf::DefaultMsfStreamWriter;
use crate::result::Result;
use crate::types::{
    FIRST_NON_BUILTIN_TYPE, HASH_BUCKET_NUMBER, IndexOffset, TypeHash, TypeStreamHeader,
};
use crate::utils::align_to;
use crate::{MsfStreamLayout, TypeIndex};

/// Builder for TPI type records (stream 2).
pub type TpiBuilder = TypeStreamBuilder<TypeRecord>;
/// Builder for IPI ID records (stream 4), with its own index sequence.
pub type IpiBuilder = TypeStreamBuilder<IdRecord>;

impl TpiBuilder {
    /// Adds a field list, splitting large lists with `LF_INDEX` continuations.
    ///
    /// Returns the head index; continuation chunks are inserted tail-first.
    /// Hash labels are `name` for the tail, then `name_1`, `name_2`, etc. toward
    /// the head. Fields must be valid field-list members and individually fit
    /// the record-size limit; a single oversized field is not split.
    pub fn add_field_list(&mut self, name: &str, fields: Vec<TypeRecord>) -> TypeIndex {
        const MAX_FIELD_LIST_PAYLOAD: usize = u16::MAX as usize - 4;

        let mut chunks: Vec<Vec<TypeRecord>> = vec![];
        let mut chunk = Vec::new();
        // 2 bytes for the LF_FIELDLIST discriminator
        let mut chunk_size: usize = 2;
        // LF_INDEX: discriminator + reserved word + TypeIndex = 8 bytes.
        const CONTINUATION_SIZE: usize = 8;

        for field in fields {
            let field_size = field.encoded_size(());
            let aligned = align_to(field_size, RECORD_ALIGNMENT);

            if chunk_size + aligned + CONTINUATION_SIZE > MAX_FIELD_LIST_PAYLOAD
                && !chunk.is_empty()
            {
                chunks.push(std::mem::take(&mut chunk));
                chunk_size = 2 + aligned;
            } else {
                chunk_size += aligned;
            }
            chunk.push(field);
        }
        if !chunk.is_empty() || chunks.is_empty() {
            chunks.push(chunk);
        }

        if chunks.len() == 1 {
            return self.add(
                name,
                TypeRecord::FieldList {
                    fields: chunks.pop().unwrap(),
                },
            );
        }

        // Build from last to first so each chunk can reference the next.
        let mut next: Option<TypeIndex> = None;
        for (i, mut chunk) in chunks.into_iter().rev().enumerate() {
            if let Some(continuation) = next {
                chunk.push(TypeRecord::ListContinuation(continuation));
            }
            let label = if i == 0 {
                name.to_string()
            } else {
                format!("{name}_{i}")
            };
            next = Some(self.add(&label, TypeRecord::FieldList { fields: chunk }));
        }
        next.unwrap()
    }
}

/// Collects TPI or IPI records and their name hashes without deduplication.
///
/// Each stream assigns consecutive indices from `0x1000`. References are used
/// verbatim; add dependencies first where possible. Commit emits a separate hash
/// stream with record-data-relative byte offsets.
#[derive(Debug)]
pub struct TypeStreamBuilder<A> {
    records: Vec<A>,
    hashes: Vec<u32>,
    offset: usize,
    index: u32,
}

impl<A> TypeStreamBuilder<A>
where
    A: Encode + EncodedSize,
{
    /// Appends a record and returns its index in this stream, not a byte offset.
    ///
    /// `name` supplies only the name hash; it does not set a name in the record.
    /// The padded record body must fit a `u16` length prefix; oversized records
    /// fail during commit. References and record kinds are not validated here.
    pub fn add(&mut self, name: &str, record: A) -> TypeIndex {
        let size = u16::default_encoded_size(()) + record.encoded_size(());
        self.offset += align_to(size, RECORD_ALIGNMENT);
        self.records.push(record);
        self.hashes
            .push(hash_v1(name.as_bytes()) % HASH_BUCKET_NUMBER);

        let index = TypeIndex::try_from(self.index).unwrap();
        self.index += 1;
        index
    }

    pub(super) fn commit<S>(
        self,
        sink: &mut S,
        allocator: &mut StreamAllocator,
    ) -> Result<MsfStreamLayout>
    where
        S: io::Write + io::Seek,
    {
        let mut writer = DefaultMsfStreamWriter::new(sink)?;
        let mut hash = TypeHash {
            hash_values: self.hashes,
            index_offsets: vec![],
            hash_adjusters: Table::default(),
            bucket_count: HASH_BUCKET_NUMBER,
        };

        let last_index =
            TypeIndex::try_from(FIRST_NON_BUILTIN_TYPE + self.records.len() as u32).unwrap();

        let mut type_buffer = std::io::Cursor::new(vec![]);

        for (index, typ) in self.records.into_iter().enumerate() {
            hash.index_offsets.push(IndexOffset {
                index: (index as u32 + FIRST_NON_BUILTIN_TYPE).try_into().unwrap(),
                offset: type_buffer.position() as u32,
            });
            PrefixedRecord(typ).encode((), &mut type_buffer)?;
        }

        let hash_layout = hash.write(&mut writer)?;
        let hash_stream = allocator.allocate(writer.finish()?);

        let mut writer = DefaultMsfStreamWriter::new(sink)?;
        let header =
            TypeStreamHeader::new(last_index, self.offset as u32, hash_stream, hash_layout);
        header.encode((), &mut writer)?;

        writer.write_all(&type_buffer.into_inner())?;

        Ok(writer.finish()?)
    }
}

impl<A> Default for TypeStreamBuilder<A> {
    fn default() -> Self {
        Self {
            records: vec![],
            hashes: vec![],
            offset: 0,
            index: FIRST_NON_BUILTIN_TYPE,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;
    use crate::PdbFile;
    use crate::builders::PdbBuilder;
    use crate::codeview::types::MemberProperties;
    use crate::utils::StrBuf;

    #[test]
    fn empty_field_list_is_one_record() {
        let mut builder = TpiBuilder::default();
        let index = builder.add_field_list("empty", vec![]);
        assert_eq!(u32::from(index), FIRST_NON_BUILTIN_TYPE);
        assert_eq!(builder.records.len(), 1);
        assert!(matches!(
            &builder.records[0],
            TypeRecord::FieldList { fields } if fields.is_empty()
        ));
    }

    #[test]
    fn field_list_continuations_roundtrip() -> Result<()> {
        const FIELD_COUNT: usize = 200;
        let name = |i| format!("{i:04}_{}", "x".repeat(1000));
        let nested_type = TypeIndex::try_from(FIRST_NON_BUILTIN_TYPE).unwrap();
        let fields = (0..FIELD_COUNT)
            .map(|i| TypeRecord::NestedType {
                properties: MemberProperties::new(),
                nested_type,
                name: StrBuf::new(name(i)),
            })
            .collect();
        let mut builder = PdbBuilder::default();
        let head = builder.tpi().add_field_list("fields", fields);
        let mut sink = Cursor::new(Vec::new());
        builder.commit(&mut sink)?;
        sink.set_position(0);
        let mut pdb = PdbFile::open(sink)?;
        let tpi = pdb.get_tpi()?;
        let record_count = tpi.records().len();
        assert!(record_count > 1);
        assert_eq!(
            u32::from(head),
            FIRST_NON_BUILTIN_TYPE + record_count as u32 - 1
        );

        let mut index = head;
        let mut field_count = 0;
        let mut chain_length = 0;
        loop {
            chain_length += 1;
            assert!(
                chain_length <= record_count,
                "continuation chain must terminate"
            );
            let record = tpi
                .record(index)
                .expect("continuation must reference a record");
            let mut encoded = Vec::new();
            record.encode((), &mut encoded)?;
            assert_eq!(encoded.len(), record.encoded_size(()));
            let prefixed_size = align_to(encoded.len() + 2, RECORD_ALIGNMENT);
            assert!(prefixed_size - 2 <= u16::MAX as usize);
            let TypeRecord::FieldList { fields } = record else {
                panic!("continuation must reference a field list");
            };
            let mut next = None;
            for (i, field) in fields.iter().enumerate() {
                match field {
                    TypeRecord::NestedType {
                        name: actual,
                        nested_type: actual_type,
                        ..
                    } => {
                        assert_eq!(actual.as_ref(), name(field_count));
                        assert_eq!(*actual_type, nested_type);
                        field_count += 1;
                    }
                    TypeRecord::ListContinuation(continuation) => {
                        assert_eq!(i, fields.len() - 1, "continuation must be last");
                        assert!(u32::from(*continuation) < u32::from(index));
                        next = Some(*continuation);
                    }
                    _ => panic!("unexpected field in continuation chain"),
                }
            }
            match next {
                Some(continuation) => index = continuation,
                None => break,
            }
        }
        assert_eq!(field_count, FIELD_COUNT);
        assert_eq!(chain_length, record_count);
        let hash = pdb.get_tpi_hash(&tpi)?;
        assert_eq!(hash.get_index("fields"), Some(index));
        assert_eq!(
            hash.get_index(&format!("fields_{}", record_count - 1)),
            Some(head)
        );
        Ok(())
    }
}
