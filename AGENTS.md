# AGENTS.md

## Commands
```bash
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
- Use `insta` for structural snapshot testing when writing parsers.
- Use declarative encoding/decoding (`declio` and `modular-bitfield`) when possible.

### Ask first
- Before significantly changing the public MSF/PDB stream reading API in `src/lib.rs`.
- Before adding or removing core dependencies (currently lightweight: `declio`, `modular-bitfield`, `insta`).

### Never do
- Never attempt to fix warnings related to deprecated hidden lifetime parameters (e.g., elided lifetimes in paths); ignore them.
- Never force tests to fail if external CLI tools like `yaml2pdb` are missing; they must gracefully skip to avoid breaking CI environments without LLVM.

## Project Structure
```
src/             # Core library code. Exposes core stream types: PdbFile, MsfStream, DbiStream, TpiStream/IpiStream, PdbInfo, Symbols.
src/codeview/    # Definitions for PDB CodeView symbols (symbols.rs) and types (types.rs). Pure data structures.
tests/           # Integration tests using YAML fixtures (`test.rs`). Relies on LLVM tools for full coverage.
examples/        # Examples for reading and writing PDBs.
```

## Code Style
```rust
// Preferred: declarative encoding using declio
#[derive(Debug, Encode, Decode, EncodedSize)]
#[declio(ctx_is = "constants::ENDIANESS", id_type = "LittleEndian<u16>")]
pub enum SymbolRecord {
    #[declio(id = "constants::S_END.into()")]
    ScopeEnd,

    #[declio(id = "constants::S_THUNK32.into()")]
    Thunk32 {
        #[declio(with = "codecs::optional_index")]
        parent: Option<SymbolOffset>,
        end: SymbolOffset,
    }
}
```

## Testing
Framework: Cargo test and `insta`
Snapshot Strategy: Use `insta` macro snapshots for parsed structures.
Fixtures: Test suite dynamically generates PDB files from YAML fixtures using `llvm-pdbutil` (`yaml2pdb`).

## Git Workflow
Branch naming: Descriptive and short.
Commit format: Short subject line (50 chars max), a blank line, and a more detailed body if necessary.
