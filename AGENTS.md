# Agent guide

See [README.md](README.md#development) for development workflows and
`.github/workflows/ci.yml` for CI.

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

- `src/lib.rs`: PDB access; `src/msf.rs`: container and streams.
- `src/codeview/`: records; `src/codecs.rs`: encoding helpers.
- `tests/test.rs`: round trips, real PDBs, LLVM fixtures.

## CI

- Install Rust via `rustup toolchain install` with `--profile minimal
  --no-self-update`, not an action.
- Use action version tags; Dependabot handles updates.
- Separate caches by job, OS, and toolchain; write only on `master`.
- Retain read-only permissions and superseded-run cancellation.
