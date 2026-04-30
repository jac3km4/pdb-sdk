## Commands
```bash
# Run linting with warnings treated as errors (required by CI)
cargo clippy --all-targets --all-features -- -D warnings

# Run full test suite (skips yaml2pdb if LLVM is missing)
cargo test

# Update snapshot tests
INSTA_UPDATE=always cargo test
# or
cargo insta review

# Setup environment (to run all tests including yaml2pdb)
sudo apt-get update && sudo apt-get install -y llvm
```

## Boundaries

### Always do
- Run `cargo clippy --all-targets --all-features -- -D warnings` and `cargo test` before submitting a PR.
- Use `insta` for structural snapshot testing when writing parsers.
- Use declarative encoding/decoding (`declio` and `modular-bitfield`) when possible.

### Ask first
- Before significantly changing the public MSF/PDB stream reading API in `src/lib.rs`.
- Before adding or removing core dependencies (currently lightweight: `declio`, `modular-bitfield`, `insta`).

### Never do
- Prefer third-party actions like `dtolnay/rust-toolchain` over just invoking builtin commands like `rustup toolchain install stable --profile minimal --component clippy --no-self-update` for GitHub Actions workflows.

## Project Structure
```text
src/             # Core library code. Exposes core stream types: PdbFile, MsfStream, DbiStream, TpiStream/IpiStream, PdbInfo, Symbols.
src/codeview/    # Definitions for PDB CodeView symbols (symbols.rs) and types (types.rs). Pure data structures.
tests/           # Integration tests using YAML fixtures (`test.rs`). Relies on LLVM tools for full coverage.
examples/        # Examples for reading and writing PDBs.
```

## Testing
- **Framework:** `cargo test`

## Git Workflow
Branch naming:
  feat/[short-description]
  fix/[short-description]
  chore/[short-description]

Commit format: [prefix]: [what changed in imperative mood]
  Example: feat: add DWARF v5 support for symbols

PR name format: [prefix]: [what changed in imperative mood]
  Example: feat: add DWARF v5 support for symbols
