# pdb-sdk
**pdb-sdk** is a Rust library for reading and writing Microsoft PDB (Program Database) files.

*this project is alpha-quality*

## features
- implemented purely in Rust
- can read and write almost all data types stored in PDB files produced by modern compilers (tested against LLVM)
- produces valid PDB files that can be parsed by tools like `llvm-pdbutil`
- can stream parts of the PDB without having to load contents of the file into memory
- lightweight, only 4 dependencies

## development

Rust 1.93 or newer is required. CI tests stable Rust on Linux and Windows,
plus Rust 1.93 on Linux.

```sh
cargo +stable test --locked --all-targets --all-features
cargo +stable test --locked --doc --all-features
cargo +stable clippy --locked --all-targets --all-features -- -D warnings
```

The YAML snapshot tests use `llvm-pdbutil-18`, `llvm-pdbutil`, or `yaml2pdb`
from `PATH`. They skip locally when no working tool is available. To require
LLVM coverage, as the Linux stable CI job does:

```sh
# Ubuntu 24.04
sudo apt-get update && sudo apt-get install --no-install-recommends -y llvm-18
REQUIRE_LLVM=1 cargo +stable test --locked --all-targets --all-features
```

Formatting uses a pinned nightly because `.rustfmt.toml` enables unstable options:

```sh
rustup toolchain install nightly-2026-10-15 --profile minimal --component rustfmt --no-self-update
cargo +nightly-2026-10-15 fmt --all -- --check
```

Update the formatter toolchain in this document and CI together.

## examples
- [reading a PDB file](/examples/read.rs)
- [assembling and writing a custom PDB file](/examples/write.rs)
