# Test fixtures

For the provenance-verified, offline multi-producer corpus, see
[`tests/corpus/README.md`](../corpus/README.md). The input below is a retained
historical regression, not the primary interoperability oracle.

## Binary PDB

`tests/llvm.pdb` is a checked-in binary regression fixture used by
`tests/real_pdb.rs` and `examples/read.rs`. Its original source project, compiler
and linker versions, build command, and upstream provenance are unknown from
the repository's recorded fixture documentation. The filename is not evidence
that LLVM produced it. It contains Rust-looking type names, including
`core::fmt::rt::v1::FormatSpec`, but that does not establish its origin.

There is no documented reproducible regeneration recipe for this binary. Do
not replace it with a synthetic PDB or claim a toolchain or license origin
without evidence.
