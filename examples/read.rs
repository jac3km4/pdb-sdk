use std::fs::File;

use pdb_sdk::result::Result;
use pdb_sdk::PdbFile;

fn main() -> Result<()> {
    let mut reader = PdbFile::open(File::open("./tests/llvm.pdb")?)?;
    let dbi = reader.get_dbi()?;

    let first_module = dbi.modules().first();
    // retrieve the name of a module
    dbg!(first_module.map(|m| &m.module_name));

    let info = reader.get_info()?;
    // list pdb features
    dbg!(info.features());

    let tpi = reader.get_tpi()?;
    // show the first type record
    dbg!(tpi.records().first());

    let hash = reader.get_tpi_hash(&tpi)?;
    // look up a record by hashed name
    dbg!(tpi.record(hash.get_index("core::fmt::rt::v1::FormatSpec").unwrap()));

    let ipi = reader.get_ipi()?;
    // show the first ID record
    dbg!(ipi.records().first());

    let syms = reader.get_symbols(&dbi)?;
    // show the first symbol
    dbg!(syms.records().first());

    let headers = reader.get_section_headers(&dbi)?;
    dbg!(headers.headers().first());
    // show the first section header
    dbg!(ipi.records().first());

    for dbi_mod in dbi.modules().iter().skip(1).take(1) {
        let module = reader.get_module(dbi_mod)?;

        // show a c13 record of a module
        dbg!(module.c13_records().first());

        // show a symbol from a module
        dbg!(module.symbols().first());
    }

    Ok(())
}
