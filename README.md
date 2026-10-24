# pdb-sdk

A pure Rust library for reading and writing Microsoft PDB (Program Database)
files, with per-stream access.

**Alpha-quality. Requires Rust 1.93+.**

## Capabilities and limits

- Read the MSF 7.0 container directory, then decode individual PDB streams on
  demand through `PdbFile<R>` where `R: Read + Seek`; opening a file does not load
  every stream. Requested streams and record collections can still allocate memory.
- Read PDB Info and named-stream metadata, `/names` strings, DBI modules, TPI
  types, IPI IDs, type hashes, symbol records, public/global symbol indexes,
  section headers, FPO/frame data, and module symbols/C13 subsections.
- Build PDBs with `builders::PdbBuilder`, including supported type/ID records,
  symbols, modules, and section data, and write them to a `Write + Seek` sink.
- No LLVM installation is needed to use the library or run the offline corpus.
  LLVM is used by explicitly selected interoperability tests and fixture generation.

This is not a complete implementation of every PDB/CodeView variant. Supported
records are described by the enums in `codeview::types` and
`codeview::symbols`; unsupported formats or missing streams can return errors.
The builder is not a lossless editor for arbitrary existing PDBs. There is no
high-level address-to-source symbolication API, symbol-server client, or
embedded/portable PDB reader. C13 subsection access is not a complete source-line
resolver. Alpha status also means API stability and robust handling of every
malformed or hostile input are not guaranteed; use resource limits/isolation
when processing untrusted files.

## Quick start

For a checkout of this repository, add a path dependency to your application's
`Cargo.toml` (adjust the path to your checkout):

```toml
[dependencies]
pdb-sdk = { path = "../pdb-sdk" }
```

Then read only the streams you need:

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

    let tpi = pdb.get_tpi()?;
    println!("First type: {:?}", tpi.records().first());
    Ok(())
}
```

For a fixture-free builder/readback example, see the executable example in the
[crate documentation](https://github.com/jac3km4/pdb-sdk/blob/master/src/lib.rs).

## Release readiness

The manifest declares MIT licensing and Rust 1.93 as the MSRV. The pinned Git
revision of `declio` is still a crates.io publication blocker: a compatible
registry release must be selected before publishing. Do not assume this checkout
is available as a registry release. Fixture provenance limits are documented in
`tests/fixtures/README.md` and must be resolved before redistributing those inputs.

Before release, inspect `cargo package --list`, verify the package contents, and
run `cargo package` after resolving the Git dependency. Package verification is
not replaced by a successful local build.

## Architecture

`PdbFile` owns the seekable reader and MSF stream layouts. Its getters select a
stream and decode an owned representation; dependent getters take metadata from
an earlier read (for example, DBI for module/symbol streams, or TPI for its hash
stream). Stream reads borrow the same reader mutably, rather than loading the
entire file up front.

The `codeview` modules define binary type, ID, and symbol records; `info`, `dbi`,
`types`, `symbols`, and `module` provide decoded stream views. `builders`
assembles supported records and commits their streams and MSF directory to an
output sink. Parsing and writing are fallible; callers should propagate errors
and handle absent records rather than assuming a particular PDB layout.

## Examples

Run from the repository root with `cargo run --locked --example <name>`:

- [`read`](examples/read.rs): reads `tests/llvm.pdb`.
- [`write`](examples/write.rs): creates or overwrites `custom.pdb`.

## Development

Use [Conventional Commits](https://www.conventionalcommits.org/), e.g.
`build: improve Cargo checks`. Keep descriptions concise and imperative; mark
breaking changes with `!`.

CI tests stable Rust on Linux and Windows, plus Rust 1.93.0 on Linux.

```sh
cargo +stable test --locked --all-targets --all-features
cargo +stable test --locked --doc --all-features
cargo +stable clippy --locked --all-targets --all-features -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo +stable doc --locked --no-deps --all-features
```

Doctests need a separate command. To check MSRV compatibility, rerun both test
commands with `+1.93.0`. The declared MSRV remains Rust 1.93; contributor tools
such as Clippy and rustfmt use the toolchains specified in CI.

### Test layers

The default test run is offline: it reads a frozen, SHA-256-verified corpus from
five MSVC/Clang and Microsoft-linker/LLD pipelines, checks independent LLVM-derived
facts and source-level anchors, and exercises stream boundaries, malformed
metadata, and semantic builder roundtrips. See the
[corpus guide](tests/corpus/README.md) for coverage, provenance, and regeneration.
The existing undocumented binary remains a regression test.

LLVM-dependent tests are explicitly **ignored** by default, rather than silently
reporting success without a tool. Linux stable CI runs them separately with LLVM
18; invoking them without the required tool fails. They include independent LLVM
inspection of builder output. Fuzz targets and bounded campaign instructions are
in the [fuzzing guide](fuzz/README.md).

### LLVM interoperability

Writer inspection requires `llvm-pdbutil` (or `llvm-pdbutil-18`) on `PATH`.

Set `LLVM_PDBUTIL` to an explicit executable path to override discovery, for
example `LLVM_PDBUTIL=/usr/bin/llvm-pdbutil-18`. Relative paths are resolved from
the working directory. An invalid path, non-executable file, or failing
`--version` is an error, **not** a reason to fall back to `PATH`, even when LLVM
tests are explicitly selected. Paths containing spaces are supported.
Inspection errors include the exit status, stdout, and stderr.

```sh
# Ubuntu 24.04
sudo apt-get update && sudo apt-get install --no-install-recommends -y llvm-18
cargo +stable test --locked --test roundtrip -- --ignored
```

`roundtrip` tests builder output and validates that LLVM can inspect it; `real_pdb`
reads the checked-in binary without LLVM. See [fixture notes](tests/fixtures/README.md)
for provenance limits on `tests/llvm.pdb`.

In PowerShell, set variables before running Cargo:

```powershell

# Optional: $env:LLVM_PDBUTIL = 'C:\Program Files\LLVM\bin\llvm-pdbutil.exe'
$env:RUSTDOCFLAGS = '-D warnings' # For cargo doc
```

If set, remove session variables afterward with `Remove-Item Env:LLVM_PDBUTIL`
and `Remove-Item Env:RUSTDOCFLAGS`.

### Formatting

Unstable rustfmt options require a pinned nightly:

```sh
rustup toolchain install nightly-2026-10-15 --profile minimal --component rustfmt --no-self-update
cargo +nightly-2026-10-15 fmt --all -- --check
```

Keep the formatter version synchronized with CI. Formatting expects LF line
endings, including on Windows.
