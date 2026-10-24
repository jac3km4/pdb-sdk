# pdb-sdk

A pure Rust library for reading and writing Microsoft PDB (Program Database)
files, with per-stream access instead of loading the whole file into memory.
Tested against LLVM; generated PDBs can be read by `llvm-pdbutil`.

**Alpha-quality. Requires Rust 1.93+.**

## Examples

- [Read a PDB](examples/read.rs)
- [Build and write a PDB](examples/write.rs)

## Development

CI tests stable Rust on Linux and Windows, plus Rust 1.93.0 on Linux.

```sh
cargo +stable test --locked --all-targets --all-features
cargo +stable test --locked --doc --all-features
cargo +stable clippy --locked --all-targets --all-features -- -D warnings
```

Doctests need a separate command. To check MSRV compatibility, rerun both test
commands with `+1.93.0`.

### LLVM fixtures

YAML fixture tests **skip without LLVM**. They look for `llvm-pdbutil-18`,
`llvm-pdbutil`, or `yaml2pdb` on `PATH`. Linux stable CI requires LLVM 18.

```sh
# Ubuntu 24.04
sudo apt-get update && sudo apt-get install --no-install-recommends -y llvm-18
REQUIRE_LLVM=1 cargo +stable test --locked --all-targets --all-features
```

To run only the fixtures or intentionally update their snapshots:

```sh
REQUIRE_LLVM=1 cargo +stable test --locked --test test generate_and_read_pdb_from_yaml
REQUIRE_LLVM=1 INSTA_UPDATE=always cargo +stable test --locked --test test generate_and_read_pdb_from_yaml
```

Inputs are in `tests/fixtures/`; snapshots are in `tests/snapshots/`. Review
snapshot diffs before accepting changes. Prefer LLVM 18 when reproducing CI.

In PowerShell, set variables before running Cargo:

```powershell
$env:REQUIRE_LLVM = '1'
$env:INSTA_UPDATE = 'always' # Only when updating snapshots
```

Remove session variables afterward with `Remove-Item Env:INSTA_UPDATE` and
`Remove-Item Env:REQUIRE_LLVM`.

### Formatting

Unstable rustfmt options require a pinned nightly:

```sh
rustup toolchain install nightly-2026-10-15 --profile minimal --component rustfmt --no-self-update
cargo +nightly-2026-10-15 fmt --all -- --check
```

Keep the formatter version synchronized with CI. Formatting expects LF line
endings, including on Windows.
