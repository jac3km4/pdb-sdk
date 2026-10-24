# Offline compatibility corpus

`cargo test --locked --test corpus` requires no compiler, LLVM, network access,
or environment variables. It verifies hashes and provenance, compares independently
extracted facts, and reads every module twice (including decoded C13 subsections),
once through a short-read adapter with reversed module order. It also checks
truncated containers and that opening does not read the entire PDB.

## Current coverage

All five binaries are generated from the repository-owned MIT-licensed
`program.c`, without third-party headers, libraries, or CRT:

| Fixture | CodeView producer | PDB linker | Architecture |
| --- | --- | --- | --- |
| `msvc-link-x64` | MSVC | Microsoft link | x64 |
| `clang-link-x64` | Clang | Microsoft link | x64 |
| `msvc-lld-x64` | MSVC | LLD | x64 |
| `clang-lld-x64` | Clang | LLD | x64 |
| `clang-lld-x86` | Clang | LLD | x86 |

Exact versions and flags are recorded in `manifest.json`. These small fixtures
exercise forward/complete structs, enums, unions, arrays, modifiers, pointers,
procedures, globals/publics, type/ID hashes, named strings, modules, and line/checksum
subsections. They are unoptimized full native PDBs with embedded CodeView (`/Z7`).
They are not evidence of C++ template/inheritance, Rust, historical toolchain,
FASTLINK, type-server, ARM64, or stripped-PDB compatibility. Those remain useful
future additions. The old `tests/llvm.pdb` regression is retained unchanged and is
not counted as a provenance-verified producer fixture.

## Expectations and maintenance

`manifest.json` is the inventory and frozen reference data:

- SHA-256 for each PDB and source; duplicate IDs, missing/unregistered binaries,
  and unknown manifest fields fail tests.
- Compiler/linker identity, exact argument lists, source license, and reference tool.
- Top-level TPI/IPI record-kind histograms extracted by LLVM `pdb2yaml`.
- Public symbol names extracted by LLVM `dump --publics` and module count from
  `dump --modules`.
- A source-level struct anchor (name, size, member names/offsets), independent of
  both parsers. Record counts alone would miss wrong field values.

The runner also checks architecture, Info/DBI age agreement, record indexing,
stream rereads, hash lookup, public address counts, and present/absent FPO/frame
streams. These are focused semantic checks, not complete differential validation
of every decoded field. No blanket expected-failure/ignore mechanism exists for
valid fixtures: a parser error must be fixed or the unsupported operation must be
explicitly modeled and reviewed before adding that format.

To add another toolchain for this source, normally add a pipeline to the generator,
generate it, and review the manifest and binary changes; no new Rust test is needed.
New source programs may require additional semantic anchor schemas. Keep fixtures
small and feature-driven rather than multiplying every option combination.

## Explicit regeneration

Requires Python 3.9+, `clang-cl`, `lld-link`, and `llvm-pdbutil`. Microsoft pipelines
also require installed MSVC tools on Windows. Nothing regenerates during tests.

```sh
# Regenerate the two LLVM-only fixtures; retain existing Microsoft entries.
python tests/corpus/generate.py

# Regenerate all five (use literal paths appropriate to your installation).
python tests/corpus/generate.py --cl /path/to/cl.exe --link /path/to/link.exe

# Executable overrides, including paths containing spaces, are supported.
python tests/corpus/generate.py --clang /path/to/clang-cl --lld /path/to/lld-link --pdbutil /path/to/llvm-pdbutil
cargo test --locked --test corpus
```

The generator requires canonical LF source bytes (enforced by `.gitattributes`)
and stages replacements until all tools succeed. It compiles in temporary
directories and extracts references directly
from the external tools, never from pdb-sdk. `/Brepro` reduces nondeterminism but
absolute build paths/tool versions are still embedded: regeneration is a semantic
recipe, not a promise of byte-for-byte identity across machines. The committed
binary and its hash are the reproducible test input. PDBs contain local build/tool
paths; review them before redistribution if path privacy matters.

Review every update. Do not simply regenerate reference expectations to make a
parser regression pass. In particular, reference extraction supports the recorded
LLVM format; an upstream output-format change requires reviewing the extractor.
Source anchors must be updated deliberately when the source program changes.

For adversarial testing and minimized failure retention, see
[`fuzz/README.md`](../../fuzz/README.md).
