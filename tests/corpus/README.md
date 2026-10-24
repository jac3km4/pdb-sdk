# Offline compatibility corpus

Run `cargo test --locked --test corpus`; no compiler, LLVM, network, or environment
variables are needed. Tests verify fixture hashes and recorded provenance, compare
LLVM-derived facts and source anchors, reread modules with short reads/reversed
order, and check truncated containers and per-stream access.

## Coverage

All five fixtures use the repository-owned MIT-licensed `program.c`, without
third-party headers, libraries, or CRT. `manifest.json` records versions and flags.

| Fixture | CodeView producer | PDB linker | Architecture |
| --- | --- | --- | --- |
| `msvc-link-x64` | MSVC | Microsoft link | x64 |
| `clang-link-x64` | Clang | Microsoft link | x64 |
| `msvc-lld-x64` | MSVC | LLD | x64 |
| `clang-lld-x64` | Clang | LLD | x64 |
| `clang-lld-x86` | Clang | LLD | x86 |

These unoptimized full native PDBs use `/Z7` CodeView input. They exercise
structs/forward declarations, enums, unions, arrays, modifiers, pointers,
procedures, globals/publics, type/ID hashes, strings, modules, and C13 line/checksum
subsections. They do **not** establish support for C++ templates/inheritance,
Rust, historical formats, FASTLINK, type servers, ARM64, or stripped PDBs.
The historical `tests/llvm.pdb` is separate, not provenance-verified coverage.

## Reference data

`manifest.json` freezes:

- PDB/source SHA-256, producer identity, exact arguments, license, and reference tool.
- TPI/IPI record-kind histograms from LLVM `pdb2yaml`.
- Public names from `dump --publics` and module count from `dump --modules`.
- A source-level struct anchor: name, size, member names, and offsets.

Tests reject duplicate IDs, missing/unregistered binaries, and unknown manifest
fields. They also check architecture, Info/DBI ages, record indexing, rereads,
hash candidates, public address counts, and optional FPO/frame streams. These are
focused semantic checks, not field-by-field differential validation. Valid
fixtures have no blanket ignore/expected-failure mechanism: fix parser errors or
explicitly review and model unsupported operations.

## Regeneration

Requires Python 3.9+, `clang-cl`, `lld-link`, and `llvm-pdbutil`. Microsoft
pipelines also require MSVC on Windows. Tests never regenerate fixtures.

```sh
# Regenerate LLVM-only fixtures, retaining Microsoft entries.
python tests/corpus/generate.py

# Regenerate all five; substitute installed executable paths.
python tests/corpus/generate.py --cl /path/to/cl.exe --link /path/to/link.exe

# Optional LLVM executable overrides; paths with spaces are supported.
python tests/corpus/generate.py --clang /path/to/clang-cl --lld /path/to/lld-link --pdbutil /path/to/llvm-pdbutil
cargo test --locked --test corpus
```

The generator requires canonical LF source bytes and stages replacements until
all tools succeed. References come from external tools, never pdb-sdk. `/Brepro`
reduces nondeterminism, but paths and tool versions remain embedded: this is a
semantic recipe, not byte-identical regeneration across machines. The committed
binary/hash is the frozen test input. Review embedded paths before redistribution.

Review every binary/manifest change; do not regenerate expectations to hide a
parser regression. LLVM output changes require extractor review. Source changes
require deliberate anchor updates. Add toolchains through generator pipelines;
new source programs may need new anchor schemas. Keep fixtures small and
feature-driven.

See [LLVM's PDB guide](https://llvm.org/docs/PDB/index.html) for format background,
[fixture notes](../fixtures/README.md) for the historical binary, and the
[fuzzing guide](../../fuzz/README.md) for adversarial testing.
