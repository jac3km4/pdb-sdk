# Differences between this Rust implementation and LLVM

While this crate is heavily inspired by LLVM's `llvm-pdbutil` and related `DebugInfo/PDB` libraries, it takes some different design choices that are more idiomatic for Rust:

- **Eager Parsing vs. Lazy Streams:** LLVM often takes a lazy approach using continuous stream readers (e.g., lazily iterating `CVSymbolArray` or evaluating `GSIHashTable` buckets directly from disk bytes). This crate generally prefers eager parsing into structured types in memory (`Vec`s, `HashMap`s) via the `declio` crate. This allows safer mutations and an easier-to-explore memory representation at the cost of initial overhead.
- **Declarative Binary IO:** Rather than manual pointer arithmetic and bit-twiddling seen in LLVM's `support::ulittle32_t` and `BinaryStreamReader`, this codebase relies heavily on declarative binary serialization using `declio` and `modular-bitfield`.
- **Builder Pattern for Writing:** To compose and construct PDB files, we use a builder pattern `PdbBuilder`, `DbiBuilder`, etc., managing the stream allocations and directories under the hood rather than writing raw bytes dynamically like `MSFBuilder`.
- **Stream Discovery:** In LLVM, discovering streams is handled via lazy queries. In this library, the `PdbInfo` and `DbiStream` eagerly load structures like `NamedStreams` or `SectionContrib`s into standard Rust collections.
