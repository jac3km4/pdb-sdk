use std::fs::File;

use anyhow::Result;
use pdb_sdk::PdbFile;

#[path = "common/llvm.rs"]
mod llvm;

#[test]
fn generate_and_read_pdb_from_yaml() -> Result<()> {
    let Some(pdbutil) = llvm::find_pdbutil()? else {
        assert!(
            std::env::var_os("REQUIRE_LLVM").is_none_or(|value| value != "1"),
            "REQUIRE_LLVM=1 but no working llvm-pdbutil or yaml2pdb was found on PATH"
        );
        println!("Skipping yaml2pdb test because no suitable LLVM tool was found.");
        return Ok(());
    };

    insta::glob!("fixtures/*.yaml", |path| {
        let temp_dir = tempfile::tempdir().expect("failed to create temporary directory");
        let temp_pdb = temp_dir.path().join("generated.pdb");
        pdbutil
            .yaml2pdb(path, &temp_pdb)
            .expect("failed to convert yaml to pdb");

        let mut pdb = PdbFile::open(File::open(&temp_pdb).expect("failed to open pdb"))
            .expect("failed to parse pdb");

        insta::assert_debug_snapshot!("info", pdb.get_info().unwrap());
        insta::assert_debug_snapshot!("dbi", pdb.get_dbi().expect("failed to get dbi"));
        insta::assert_debug_snapshot!("tpi", pdb.get_tpi().expect("failed to get tpi").records());
        insta::assert_debug_snapshot!("ipi", pdb.get_ipi().expect("failed to get ipi").records());

        drop(pdb);
        temp_dir
            .close()
            .expect("failed to remove temporary directory");
    });
    Ok(())
}
