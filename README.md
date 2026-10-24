# pdb-sdk

A pure Rust library for reading and writing Microsoft PDB (Program Database)
files, with per-stream access.

**Alpha-quality. Requires Rust 1.93+.**

## Quick start

For a checkout of this repository, add a path dependency to your application's
`Cargo.toml` (adjust the path to your checkout):

```toml
[dependencies]
pdb-sdk = { path = "../pdb-sdk" }
```

```rust,no_run
use std::fs::File;
use pdb_sdk::PdbFile;

fn main() -> pdb_sdk::result::Result<()> {
    let mut pdb = PdbFile::open(File::open("application.pdb")?)?;
    let info = pdb.get_info()?;
    println!("Features: {:?}", info.features());

    let dbi = pdb.get_dbi()?;
    for module in dbi.modules() {
        println!("Module: {:?}", module.module_name);
    }
    println!("First type: {:?}", pdb.get_tpi()?.records().first());
    Ok(())
}
```

For a fixture-free builder/readback example, see the executable example in the
[crate documentation](https://github.com/jac3km4/pdb-sdk/blob/master/src/lib.rs).

## Examples

Run `cargo run --locked --example <name>` from the repository root:

- [`read`](examples/read.rs): inspect `tests/llvm.pdb`.
- [`write`](examples/write.rs): create or overwrite `custom.pdb`.
- [`fake_pdb`](examples/fake_pdb.rs): run with `-- <exe_path>`. Copies a PE's PDB
  identity and section headers, but uses hard-coded demonstration symbols and
  addresses; it does not recover real symbols. Creates or overwrites the `.pdb`
  beside the executable with the same base name.

## Development

CI tests stable Rust on Linux and Windows, plus Rust 1.93.0 on Linux.

```sh
cargo +stable test --locked --all-targets --all-features
cargo +stable test --locked --doc --all-features
cargo +stable clippy --locked --all-targets --all-features -- -D warnings
cargo +stable check --locked --manifest-path fuzz/Cargo.toml
RUSTDOCFLAGS="-D warnings" cargo +stable doc --locked --no-deps --all-features
```

Doctests run separately. Repeat both test commands with `+1.93.0` for MSRV checks.

Use [Conventional Commits](https://www.conventionalcommits.org/) with concise,
imperative descriptions and `!` for breaking changes.

### Tests and LLVM

Default tests are offline. The [corpus guide](tests/corpus/README.md) describes
five frozen MSVC/Clang and Microsoft-linker/LLD fixtures, LLVM-derived reference
facts, and regeneration. The [fuzzing guide](fuzz/README.md) covers bounded
campaigns and regression retention.

LLVM writer-interoperability tests are ignored by default and run separately in
Linux stable CI with LLVM 18:

```sh
# Ubuntu 24.04
sudo apt-get update && sudo apt-get install --no-install-recommends -y llvm-18
cargo +stable test --locked --test roundtrip -- --ignored
```

Discovery uses `llvm-pdbutil` or `llvm-pdbutil-18` on `PATH`. `LLVM_PDBUTIL`
overrides it with an executable path; relative paths use the working directory,
and spaces are supported. An invalid override or failing `--version` is an error,
not a fallback. Inspection failures report status, stdout, and stderr.

In PowerShell, set `$env:LLVM_PDBUTIL` to the executable path when needed and
`$env:RUSTDOCFLAGS = '-D warnings'` before `cargo doc`. Remove session overrides
with `Remove-Item Env:LLVM_PDBUTIL` and `Remove-Item Env:RUSTDOCFLAGS` afterward.

### Formatting

Use the CI-pinned nightly for unstable rustfmt options and LF line endings:

```sh
rustup toolchain install nightly-2026-10-15 --profile minimal --component rustfmt --no-self-update
cargo +nightly-2026-10-15 fmt --all -- --check
cargo +nightly-2026-10-15 fmt --manifest-path fuzz/Cargo.toml --all -- --check
```
