use std::fs::File;
use std::io;

use assert_matches::assert_matches;
use pdb_sdk::builders::PdbBuilder;
use pdb_sdk::codeview::symbols::{Constant, ProcedureProperties, Public, PublicProperties, SymbolRecord};
use pdb_sdk::codeview::types::{BuiltinType, IdRecord, PointerKind, PointerProperties, TypeRecord};
use pdb_sdk::codeview::DataRegionOffset;
use pdb_sdk::dbi::SectionHeader;
use pdb_sdk::info::PdbFeature;
use pdb_sdk::result::Result;
use pdb_sdk::utils::StrBuf;
use pdb_sdk::{Integer, PdbFile};

#[test]
fn roundtrip() -> Result<()> {
    let dummy = write_dummy()?;
    let mut pdb = PdbFile::open(dummy)?;

    let dbi = pdb.get_dbi()?;
    assert_eq!(dbi.header().age, 1);

    let info = pdb.get_info()?;
    assert_eq!(info.features(), &vec![PdbFeature::Vc140]);

    let tpi = pdb.get_tpi()?;
    assert_matches!(tpi.records().first(), Some(TypeRecord::Pointer { .. }));

    let hash = pdb.get_tpi_hash(&tpi)?;
    assert_matches!(
        tpi.record(hash.get_index("pointer_type").unwrap()),
        Some(TypeRecord::Pointer { .. })
    );

    let ipi = pdb.get_ipi()?;
    assert_matches!(ipi.records().first(), Some(IdRecord::StringId { .. }));

    let syms = pdb.get_symbols(&dbi)?;
    assert_matches!(syms.records().first(), Some(SymbolRecord::Public32(_)));

    Ok(())
}

#[test]
fn read_llvm_pdb() -> Result<()> {
    let mut pdb = PdbFile::open(File::open("tests/llvm.pdb")?)?;

    let dbi = pdb.get_dbi()?;
    assert_eq!(dbi.header().build_number.major(), 14);

    let info = pdb.get_info()?;
    assert_eq!(info.features(), &vec![PdbFeature::None, PdbFeature::Vc140]);

    let tpi = pdb.get_tpi()?;
    assert_matches!(tpi.records().first(), Some(TypeRecord::FieldList { .. }));

    let hash = pdb.get_tpi_hash(&tpi)?;
    assert_matches!(
        tpi.record(hash.get_index("core::fmt::rt::v1::FormatSpec").unwrap()),
        Some(TypeRecord::Struct { .. })
    );

    let ipi = pdb.get_ipi()?;
    assert_matches!(ipi.records().first(), Some(IdRecord::StringId { .. }));

    let syms = pdb.get_symbols(&dbi)?;
    assert_matches!(syms.records().first(), Some(SymbolRecord::Udt(_)));

    let dbg = pdb.get_section_headers(&dbi)?;
    assert_matches!(
        dbg.headers().first(),
        Some(SectionHeader {
            virtual_address: 4096,
            ..
        })
    );

    let module = pdb.get_module(&dbi.modules()[1])?;
    assert_matches!(module.symbols().first(), Some(SymbolRecord::ObjectName { .. }));

    Ok(())
}

fn write_dummy() -> Result<io::Cursor<Vec<u8>>> {
    let mut builder = PdbBuilder::default();
    builder.tpi().add("pointer_type", TypeRecord::Pointer {
        referent: BuiltinType::I64.into(),
        properties: PointerProperties::new()
            .with_is_const(true)
            .with_is_volatile(true)
            .with_kind(PointerKind::Near64),
        containing_class: None,
    });
    builder.ipi().add("string_id", IdRecord::StringId {
        id: None,
        string: StrBuf::new("test"),
    });

    let mut sym_builder = builder.dbi().symbols();
    sym_builder.add(Public {
        properties: PublicProperties::new().with_is_msil(true),
        offset: DataRegionOffset::new(0, 0),
        name: StrBuf::new("hello"),
    });
    let sym_builder = sym_builder.finish_publics();
    sym_builder.add(SymbolRecord::Label {
        code_offset: DataRegionOffset::new(0, 0),
        properties: ProcedureProperties::new()
            .with_has_fp(true)
            .with_is_no_return(true),
        name: StrBuf::new("label"),
    });
    sym_builder.add(SymbolRecord::Constant(Constant {
        constant_type: BuiltinType::I32.into(),
        value: Integer::I32(2),
        name: StrBuf::new("myconstant"),
    }));

    let mut output = io::Cursor::new(vec![]);
    builder.commit(&mut output)?;

    output.set_position(0);
    Ok(output)
}
