# Agent guide

See [README.md](README.md#development) for development workflows and
`.github/workflows/ci.yml` for CI.

Edit this file, not the `GEMINI.md` symlink. Windows checkouts may show only
its target filename, `AGENTS.md`.

## Design

- Preserve per-stream access without loading the whole PDB.
- Prefer `declio` and `modular-bitfield` for binary records.
- Validate input sizes, offsets, and arithmetic before allocating or indexing;
  malformed PDBs must return errors, not panic.
- MSF alignment, padding, and seeking changes need tests asserting stream
  positions and decoded values.
- Ask before significant public stream API changes, runtime dependency changes,
  encoding/snapshot library replacements, or MSRV increases.

## Navigation

- `src/lib.rs`: public facade; `src/pdb.rs`: PDB access; `src/msf.rs`: container and streams.
- `src/primitives.rs`: shared indices and numeric codecs; `src/builders/`: builder implementations.
- `src/codeview/`: records; `src/codecs.rs`: encoding helpers.
- `tests/roundtrip.rs`, `tests/real_pdb.rs`, `tests/llvm_snapshots.rs`: integration tests.
- `tests/common/llvm.rs`: LLVM discovery and fixture generation.

## CI

- Install Rust via `rustup toolchain install` with `--profile minimal` and
  `--no-self-update`, not an action.
- Use action version tags; Dependabot handles updates.
- Separate caches by job, OS, and toolchain; write only on `master`.
- Retain read-only permissions and superseded-run cancellation.
