use anyhow::{Context, Result};
use assert_matches::assert_matches;
use pdb_sdk::PdbFile;
use pdb_sdk::codeview::symbols::SymbolRecord;
use pdb_sdk::codeview::types::{IdRecord, TypeRecord};
use pdb_sdk::info::PdbFeature;

mod common;

#[test]
fn roundtrip() -> Result<()> {
    let mut pdb = PdbFile::open(common::write_dummy()?)?;

    let dbi = pdb.get_dbi()?;
    assert_eq!(dbi.header().age, 1);

    let info = pdb.get_info()?;
    assert_eq!(info.features(), &vec![PdbFeature::Vc140]);

    let tpi = pdb.get_tpi()?;
    assert_matches!(tpi.records().first(), Some(TypeRecord::Pointer { .. }));

    let hash = pdb.get_tpi_hash(&tpi)?;
    assert_matches!(
        tpi.record(
            hash.get_index("pointer_type")
                .context("missing pointer_type")?
        ),
        Some(TypeRecord::Pointer { .. })
    );

    let ipi = pdb.get_ipi()?;
    assert_matches!(ipi.records().first(), Some(IdRecord::StringId { .. }));

    let syms = pdb.get_symbols(&dbi)?;
    assert_matches!(syms.records().first(), Some(SymbolRecord::Public32(_)));

    Ok(())
}
