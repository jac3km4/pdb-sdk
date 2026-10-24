use std::io::Cursor;

use anyhow::{Context, Result};
use assert_matches::assert_matches;
use pdb_sdk::builders::PdbBuilder;
use pdb_sdk::codeview::DataRegionOffset;
use pdb_sdk::codeview::symbols::{Constant, Public, PublicProperties, SymbolRecord};
use pdb_sdk::codeview::types::{BuiltinType, IdRecord, PointerKind, PointerProperties, TypeRecord};
use pdb_sdk::info::{PdbFeature, PdbVersion};
use pdb_sdk::types::TypeStream;
use pdb_sdk::utils::StrBuf;
use pdb_sdk::{Guid, IdIndex, Integer, PdbFile, Publics, SymbolMap, TypeIndex};

mod common;
#[path = "common/llvm.rs"]
mod llvm;

// Every record-alignment residue and both sides of MSF block sizes.
const LENGTHS: [usize; 13] = [0, 1, 2, 3, 4, 255, 256, 511, 512, 513, 4095, 4096, 4097];

fn commit_open(builder: PdbBuilder) -> Result<PdbFile<Cursor<Vec<u8>>>> {
    let mut output = Cursor::new(Vec::new());
    builder.commit(&mut output)?;
    output.set_position(0);
    Ok(PdbFile::open(output)?)
}

fn type_index(i: usize) -> TypeIndex {
    TypeIndex::try_from(0x1000 + i as u32).unwrap()
}

fn assert_index_range<A>(stream: &TypeStream<A>, count: usize) {
    assert_eq!(stream.records().len(), count);
    assert_eq!(stream.header().type_index_begin, type_index(0));
    assert_eq!(stream.header().type_index_end, type_index(count));
}

fn assert_pointer(record: Option<&TypeRecord>, expected: TypeIndex, flags: PointerProperties) {
    assert_matches!(record, Some(TypeRecord::Pointer {
        referent: Some(referent), properties, containing_class: None
    }) if *referent == expected && properties.into_bytes() == flags.into_bytes());
}

fn pointer_flags() -> PointerProperties {
    let flags = PointerProperties::new().with_kind(PointerKind::Near64);
    flags.with_size(8)
}

fn assert_string(stream: &TypeStream<IdRecord>, i: usize, id: Option<TypeIndex>, text: &str) {
    let index = IdIndex::try_from(u32::from(type_index(i))).unwrap();
    assert_matches!(stream.record(index), Some(IdRecord::StringId { id: previous, string })
        if *previous == id && string.as_ref() == text);
}

// SymbolMap has no public iterator. Decode its one-based offsets, ignoring bucket order.
fn symbol_offsets(map: &SymbolMap) -> Result<Vec<u32>> {
    let mut bytes = Vec::new();
    map.write_with_header(&mut bytes)?;
    let size = u32::from_le_bytes(bytes[8..12].try_into()?) as usize;
    let (records, remainder) = bytes[16..16 + size].as_chunks::<8>();
    assert!(remainder.is_empty());
    let mut offsets = Vec::new();
    for record in records {
        let offset = u32::from_le_bytes(record[..4].try_into()?);
        assert_ne!(offset, 0);
        assert_eq!(u32::from_le_bytes(record[4..].try_into()?), 1);
        offsets.push(offset - 1);
    }
    offsets.sort_unstable();
    Ok(offsets)
}

fn assert_public(record: &SymbolRecord, name: &str, offset: u32, segment: u16, flags: [u8; 4]) {
    assert_matches!(record, SymbolRecord::Public32(public) => {
        assert_eq!(public.name.as_ref(), name);
        assert_eq!(public.offset.offset, offset);
        assert_eq!(public.offset.segment, segment);
        assert_eq!(public.properties.into_bytes(), flags);
    });
}

fn address_offsets(publics: &Publics) -> Vec<u32> {
    let offsets = publics.address_map();
    offsets.iter().copied().map(u32::from).collect()
}

fn assert_default_metadata(pdb: &mut PdbFile<Cursor<Vec<u8>>>) -> Result<()> {
    let dbi = pdb.get_dbi()?;
    assert_eq!(dbi.header().age, 1);
    assert!(dbi.modules().is_empty());
    let info = pdb.get_info()?;
    assert_eq!(info.header().version, PdbVersion::Vc70);
    assert_eq!(info.header().age, 1);
    assert_eq!(info.header().signature, 0);
    assert_eq!(info.header().guid.0, [0; 16]);
    assert_eq!(info.features(), &[PdbFeature::Vc140]);
    assert_eq!(info.named_streams().iter().count(), 0);
    Ok(())
}

#[test]
fn roundtrip() -> Result<()> {
    let mut pdb = PdbFile::open(common::write_dummy()?)?;
    let dbi = pdb.get_dbi()?;
    assert_default_metadata(&mut pdb)?;
    let tpi = pdb.get_tpi()?;
    assert_index_range(&tpi, 1);
    let type_hash = pdb.get_tpi_hash(&tpi)?;
    assert_eq!(type_hash.get_index("pointer_type"), Some(type_index(0)));
    let flags = PointerProperties::new()
        .with_is_const(true)
        .with_is_volatile(true)
        .with_kind(PointerKind::Near64);
    assert_pointer(tpi.record(type_index(0)), BuiltinType::I64.into(), flags);
    assert!(tpi.record(BuiltinType::I64.into()).is_none());
    assert!(tpi.record(tpi.header().type_index_end).is_none());
    let ipi = pdb.get_ipi()?;
    assert_index_range(&ipi, 1);
    let hash = pdb.get_tpi_hash(&ipi)?;
    assert_eq!(hash.get_index("string_id"), Some(type_index(0)));
    assert_string(&ipi, 0, None, "test");
    assert!(ipi.record(IdIndex::try_from(0xfff).unwrap()).is_none());
    assert!(ipi.record(IdIndex::try_from(0x1001).unwrap()).is_none());

    let syms = pdb.get_symbols(&dbi)?;
    assert_eq!(syms.records().len(), 3);
    let flags = PublicProperties::new().with_is_msil(true).into_bytes();
    assert_public(&syms.records()[0], "hello", 0, 0, flags);
    // Label flags: frame pointer + no return, all other bits clear.
    assert_matches!(&syms.records()[1], SymbolRecord::Label {
        code_offset: DataRegionOffset { offset: 0, segment: 0 }, properties, name
    } if name.as_ref() == "label" && properties.into_bytes() == [0x09]);
    assert_matches!(&syms.records()[2], SymbolRecord::Constant(Constant {
        name, constant_type, value: Integer::I32(2)
    }) if name.as_ref() == "myconstant" && *constant_type == BuiltinType::I32.into());
    let publics = pdb.get_publics(&dbi)?;
    assert_eq!(symbol_offsets(publics.map())?, [0]);
    assert_eq!(address_offsets(&publics), [0]);
    assert!(publics.thunk_map().is_empty());
    assert_eq!(symbol_offsets(&pdb.get_globals(&dbi)?)?, [20, 40]);
    Ok(())
}

#[test]
fn empty_builder_roundtrip() -> Result<()> {
    let mut pdb = commit_open(PdbBuilder::default())?;
    assert_default_metadata(&mut pdb)?;
    let dbi = pdb.get_dbi()?;
    let tpi = pdb.get_tpi()?;
    let ipi = pdb.get_ipi()?;
    assert_index_range(&tpi, 0);
    assert_index_range(&ipi, 0);
    for header in [tpi.header(), ipi.header()] {
        assert_eq!(header.type_record_bytes, 0);
    }
    assert!(pdb.get_tpi_hash(&tpi)?.get_index("absent").is_none());
    assert!(pdb.get_tpi_hash(&ipi)?.get_index("absent").is_none());
    assert!(pdb.get_symbols(&dbi)?.records().is_empty());
    assert!(symbol_offsets(&pdb.get_globals(&dbi)?)?.is_empty());
    let publics = pdb.get_publics(&dbi)?;
    assert!(symbol_offsets(publics.map())?.is_empty());
    assert!(publics.address_map().is_empty());
    assert!(publics.thunk_map().is_empty());
    Ok(())
}

#[test]
fn metadata_roundtrip() -> Result<()> {
    let guid = [
        0, 1, 2, 3, 0x7f, 0x80, 0xfe, 0xff, 8, 9, 10, 11, 12, 13, 14, 15,
    ];
    let mut builder = PdbBuilder::default();
    builder
        .info()
        .age(u32::MAX)
        .signature(u32::MAX)
        .guid(Guid(guid));
    let mut pdb = commit_open(builder)?;
    let info = pdb.get_info()?;
    assert_eq!(info.header().signature, u32::MAX);
    assert_eq!(info.header().age, u32::MAX);
    assert_eq!(info.header().guid.0, guid);
    assert_eq!(pdb.get_dbi()?.header().age, u32::MAX);
    Ok(())
}

fn chained_types() -> PdbBuilder {
    let mut builder = PdbBuilder::default();
    for (i, length) in LENGTHS.into_iter().enumerate() {
        let previous = i.checked_sub(1).map(type_index);
        let string = IdRecord::StringId {
            id: previous,
            string: StrBuf::new("s".repeat(length)),
        };
        let pointer = TypeRecord::Pointer {
            referent: Some(previous.unwrap_or(BuiltinType::I64.into())),
            properties: pointer_flags(),
            containing_class: None,
        };
        let id = builder.ipi().add(&format!("string_{i}"), string);
        let ty = builder.tpi().add(&format!("pointer_{i}"), pointer);
        assert_eq!(id, type_index(i));
        assert_eq!(ty, id);
    }
    builder
}

#[test]
fn chained_type_and_id_indexes_and_hashes_roundtrip() -> Result<()> {
    let mut pdb = commit_open(chained_types())?;
    let tpi = pdb.get_tpi()?;
    let ipi = pdb.get_ipi()?;
    assert_index_range(&tpi, LENGTHS.len());
    assert_index_range(&ipi, LENGTHS.len());
    let type_hash = pdb.get_tpi_hash(&tpi)?;
    let id_hash = pdb.get_tpi_hash(&ipi)?;
    for (i, length) in LENGTHS.into_iter().enumerate() {
        let index = type_index(i);
        let previous = i.checked_sub(1).map(type_index);
        assert_eq!(type_hash.get_index(&format!("pointer_{i}")), Some(index));
        assert_eq!(id_hash.get_index(&format!("string_{i}")), Some(index));
        let referent = previous.unwrap_or(BuiltinType::I64.into());
        assert_pointer(tpi.record(index), referent, pointer_flags());
        assert_string(&ipi, i, previous, &"s".repeat(length));
    }
    Ok(())
}

#[test]
fn public_and_global_boundary_strings_roundtrip() -> Result<()> {
    let mut builder = chained_types();
    let mut publics = builder.dbi().symbols();
    let mut public_offsets = Vec::new();
    for (i, length) in LENGTHS.into_iter().enumerate() {
        public_offsets.push(u32::from(publics.add(Public {
            properties: PublicProperties::new().with_is_function(true),
            offset: DataRegionOffset::new((LENGTHS.len() - i) as u32, u16::MAX),
            name: StrBuf::new(format!("p{i}_{}", "x".repeat(length))),
        })));
    }
    let globals = publics.finish_publics();
    let mut global_offsets = Vec::new();
    for (i, length) in LENGTHS.into_iter().enumerate() {
        global_offsets.push(u32::from(globals.add(SymbolRecord::Constant(Constant {
            constant_type: type_index(i),
            value: Integer::U64(u64::MAX - i as u64),
            name: StrBuf::new(format!("g{i}_{}", "y".repeat(length))),
        }))));
    }
    let mut pdb = commit_open(builder)?;
    let dbi = pdb.get_dbi()?;
    let syms = pdb.get_symbols(&dbi)?;
    assert_eq!(syms.records().len(), 2 * LENGTHS.len());
    for (i, length) in LENGTHS.into_iter().enumerate() {
        let name = format!("p{i}_{}", "x".repeat(length));
        let offset = (LENGTHS.len() - i) as u32;
        let flags = PublicProperties::new().with_is_function(true).into_bytes();
        assert_public(&syms.records()[i], &name, offset, u16::MAX, flags);
        assert_matches!(&syms.records()[LENGTHS.len() + i], SymbolRecord::Constant(constant) => {
            assert_eq!(constant.name.as_ref(), format!("g{i}_{}", "y".repeat(length)));
            assert_eq!(constant.constant_type, type_index(i));
            assert_matches!(constant.value, Integer::U64(value) if value == u64::MAX - i as u64);
        });
    }
    let publics = pdb.get_publics(&dbi)?;
    assert_eq!(symbol_offsets(publics.map())?, public_offsets);
    public_offsets.reverse();
    assert_eq!(address_offsets(&publics), public_offsets);
    assert!(publics.thunk_map().is_empty());
    assert_eq!(symbol_offsets(&pdb.get_globals(&dbi)?)?, global_offsets);
    Ok(())
}

fn assert_anchors(dump: &str, anchors: &[&str]) {
    for anchor in anchors {
        assert!(
            dump.contains(anchor),
            "missing LLVM anchor {anchor:?}: {dump}"
        );
    }
}

#[test]
#[ignore = "requires llvm-pdbutil; run with --ignored"]
fn llvm_reads_writer_output() -> Result<()> {
    let tool = llvm::require_dump_tool()?;
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("writer output.pdb");
    std::fs::write(&path, common::write_dummy()?.into_inner())?;
    let dump = tool.dump(&path)?;
    // Ignore whitespace, but require decoded values and flags, not just record names.
    let dump = dump.split_whitespace().collect::<Vec<_>>().join(" ");
    #[rustfmt::skip] // Group anchors by decoded record.
    assert_anchors(&dump, &[
        "Age: 1",
        "0x1000 | LF_POINTER", "referent = 0x0076", "mode = pointer",
        "opts = volatile | const", "kind = ptr64",
        "0x1000 | LF_STRING_ID", "ID: <no type>, String: test",
        "S_PUB32", "`hello`", "flags = msil", "addr = 0000:0000",
        "S_LABEL32", "`label`", "flags = has fp | noreturn",
        "S_CONSTANT", "`myconstant`", "type = 0x0074 (int), value = 2",
    ]);
    let (_, globals) = dump
        .split_once("Global Symbols")
        .context("missing globals section")?;
    let (globals, publics) = globals
        .split_once("Public Symbols")
        .context("missing publics section")?;
    assert_anchors(globals, &["S_LABEL32", "`label`"]);
    assert_anchors(globals, &["S_CONSTANT", "`myconstant`", "value = 2"]);
    assert_anchors(publics, &["S_PUB32", "`hello`", "flags = msil"]);
    directory.close()?;
    Ok(())
}
