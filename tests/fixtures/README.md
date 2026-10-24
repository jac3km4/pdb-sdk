# Test fixtures

## YAML inputs

`dummy.yaml` and `dummy2.yaml` are checked-in LLVM PDB YAML inputs. Their
original authoring commands and tool versions are not recorded here; do not
infer them from the filenames. They exercise small PDB Info, DBI, TPI, and IPI
streams:

- `dummy.yaml`: AMD64, DBI age 1, an argument-list type, and a string ID.
- `dummy2.yaml`: x86, DBI age 2, a pointer type, and a function ID.

`tests/llvm_snapshots.rs` converts each input with LLVM's `yaml2pdb` command into
an isolated temporary directory, reads it with pdb-sdk, and compares decoded
values with `tests/snapshots/llvm_snapshots__*.snap`. Generated PDBs are not
checked in. Temporary directories are removed after the reader is dropped,
including on Windows. LLVM 18 is the CI reference version; other versions may
produce different output.

From the repository root:

```sh
REQUIRE_LLVM=1 cargo test --locked --test llvm_snapshots
REQUIRE_LLVM=1 INSTA_UPDATE=always cargo test --locked --test llvm_snapshots
```

Review every snapshot diff. Snapshot bodies were preserved when the integration
target was renamed from `test` to `llvm_snapshots`; only snapshot filenames and
source-path metadata changed.

See the [development guide](../../README.md#llvm-fixtures) for tool discovery,
explicit executable paths, and Windows environment-variable examples.

## Binary PDB

`tests/llvm.pdb` is a checked-in binary regression fixture used by
`tests/real_pdb.rs` and `examples/read.rs`. Its original source project, compiler
and linker versions, build command, and upstream provenance are unknown from
the repository's recorded fixture documentation. The filename is not evidence
that LLVM produced it. It contains Rust-looking type names, including
`core::fmt::rt::v1::FormatSpec`, but that does not establish its origin.

There is no documented reproducible regeneration recipe for this binary. Do
not replace it with a YAML-generated PDB or claim a toolchain or license origin
without evidence. Keep it unchanged when updating YAML snapshots.
