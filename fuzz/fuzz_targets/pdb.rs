#![no_main]

use std::hint::black_box;
use std::io::Cursor;

use libfuzzer_sys::fuzz_target;
use pdb_sdk::PdbFile;

const MAX_INPUT_BYTES: usize = 16 * 1024 * 1024;
const MAX_MODULES: usize = 128;
const MAX_RECORDS: usize = 256;

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_BYTES {
        return;
    }
    let Ok(mut pdb) = PdbFile::open(Cursor::new(data)) else {
        return;
    };

    // Failure of one built-in stream must not skip unrelated built-in streams.
    if let Ok(info) = pdb.get_info() {
        let _ = pdb.get_strings(&info);
    }
    if let Ok(tpi) = pdb.get_tpi() {
        let _ = pdb.get_tpi_hash(&tpi);
        for record in tpi.records().iter().take(MAX_RECORDS) {
            black_box(record);
        }
    }
    if let Ok(ipi) = pdb.get_ipi() {
        let _ = pdb.get_tpi_hash(&ipi);
        for record in ipi.records().iter().take(MAX_RECORDS) {
            black_box(record);
        }
    }
    if let Ok(dbi) = pdb.get_dbi() {
        let _ = pdb.get_publics(&dbi);
        let _ = pdb.get_globals(&dbi);
        let _ = pdb.get_section_headers(&dbi);
        let _ = pdb.get_frame_data(&dbi);
        let _ = pdb.get_fpo(&dbi);
        if let Ok(symbols) = pdb.get_symbols(&dbi) {
            for record in symbols.records().iter().take(MAX_RECORDS) {
                black_box(record.name());
            }
        }
        // Walk all modules in ordinary small PDBs, rather than just the first.
        for module in dbi.modules().iter().take(MAX_MODULES) {
            if let Ok(module) = pdb.get_module(module) {
                for record in module.symbols().iter().take(MAX_RECORDS) {
                    black_box(record.name());
                }
                for subsection in module.c13_records().iter().take(MAX_RECORDS) {
                    let _ = subsection.decoded();
                }
            }
        }
    }
});
