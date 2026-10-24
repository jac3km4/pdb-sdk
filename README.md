# pdb-sdk

A pure Rust library for reading and writing Microsoft PDB (Program Database)
files, with per-stream access.

**Alpha-quality. Requires Rust 1.93+.**

## Capabilities and limits

- Read the MSF container directory, then decode individual PDB streams on demand
  through `PdbFile<R>` where `R: Read + Seek`; opening a file does not load every
  stream. Requested streams and record collections can still allocate memory.
- Read PDB Info and named-stream metadata, `/names` strings, DBI modules, TPI
  types, IPI IDs, type hashes, symbol records, public/global symbol indexes,
  section headers, FPO/frame data, and module symbols/C13 subsections.
- Build PDBs with `builders::PdbBuilder`, including supported type/ID records,
  symbols, modules, and section data, and write them to a `Write + Seek` sink.
- No LLVM installation is needed to use the library. LLVM is only used by the
  YAML integration tests.

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

- [Read a PDB](examples/read.rs)
- [Build and write a PDB](examples/write.rs)

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

### LLVM fixtures

YAML fixture tests **skip without LLVM**, unless `REQUIRE_LLVM=1` makes its
absence a failure. They look for a working `llvm-pdbutil-18`, `llvm-pdbutil`, or
`yaml2pdb` on `PATH`, in that order. Linux stable CI requires LLVM 18.

Set `LLVM_PDBUTIL` to an explicit executable path to override discovery, for
example `LLVM_PDBUTIL=/usr/bin/llvm-pdbutil-18`. Relative paths are resolved from
the working directory. An invalid path, non-executable file, or failing
`--version` is an error, **not** a reason to fall back to `PATH`, even when LLVM
is optional. A tool named `yaml2pdb` (or `yaml2pdb.exe`) is invoked directly;
other executable names use the `yaml2pdb` subcommand. Paths containing spaces
are supported. Conversion errors include the exit status, stdout, and stderr.

```sh
# Ubuntu 24.04
sudo apt-get update && sudo apt-get install --no-install-recommends -y llvm-18
REQUIRE_LLVM=1 cargo +stable test --locked --all-targets --all-features
```

To run only the fixtures or intentionally update their snapshots:

```sh
REQUIRE_LLVM=1 cargo +stable test --locked --test llvm_snapshots generate_and_read_pdb_from_yaml
REQUIRE_LLVM=1 INSTA_UPDATE=always cargo +stable test --locked --test llvm_snapshots generate_and_read_pdb_from_yaml
```

Inputs are in `tests/fixtures/`; snapshots are in `tests/snapshots/`. Review
snapshot diffs before accepting changes. Prefer LLVM 18 when reproducing CI.
See [fixture notes](tests/fixtures/README.md) for coverage and provenance limits.
`roundtrip` tests builder output; `real_pdb` reads the checked-in binary without
LLVM; `llvm_snapshots` tests generated fixtures and the LLVM helper.

In PowerShell, set variables before running Cargo:

```powershell
$env:REQUIRE_LLVM = '1'
# Optional: $env:LLVM_PDBUTIL = 'C:\Program Files\LLVM\bin\llvm-pdbutil.exe'
$env:RUSTDOCFLAGS = '-D warnings' # For cargo doc
$env:INSTA_UPDATE = 'always' # Only when updating snapshots
```

Remove session variables afterward with `Remove-Item Env:INSTA_UPDATE` and
`Remove-Item Env:REQUIRE_LLVM`. If set, also remove `Env:LLVM_PDBUTIL` and
`Env:RUSTDOCFLAGS`.

### Formatting

Unstable rustfmt options require a pinned nightly:

```sh
rustup toolchain install nightly-2026-10-15 --profile minimal --component rustfmt --no-self-update
cargo +nightly-2026-10-15 fmt --all -- --check
```

Keep the formatter version synchronized with CI. Formatting expects LF line
endings, including on Windows.
