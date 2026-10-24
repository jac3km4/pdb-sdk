use std::fs::File;

use anyhow::{Context, Result};
use assert_matches::assert_matches;
use pdb_sdk::PdbFile;
use pdb_sdk::codeview::symbols::SymbolRecord;
use pdb_sdk::codeview::types::{IdRecord, TypeRecord};
use pdb_sdk::dbi::SectionHeader;
use pdb_sdk::info::PdbFeature;

#[test]
fn read_llvm_pdb() -> Result<()> {
    let mut pdb = PdbFile::open(File::open(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/llvm.pdb"
    ))?)?;

    let dbi = pdb.get_dbi()?;
    assert_eq!(dbi.header().build_number.major(), 14);

    let info = pdb.get_info()?;
    assert_eq!(info.features(), &vec![PdbFeature::None, PdbFeature::Vc140]);

    let tpi = pdb.get_tpi()?;
    assert_matches!(tpi.records().first(), Some(TypeRecord::FieldList { .. }));

    let hash = pdb.get_tpi_hash(&tpi)?;
    assert_matches!(
        tpi.record(
            hash.get_index("core::fmt::rt::v1::FormatSpec")
                .context("missing FormatSpec")?
        ),
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
    assert_matches!(
        module.symbols().first(),
        Some(SymbolRecord::ObjectName { .. })
    );

    Ok(())
}
