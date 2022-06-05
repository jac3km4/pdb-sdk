# pdb-sdk
**pdb-sdk** is a Rust library for reading and writing Microsoft PDB (Program Database) files.

*this project is alpha-quality*

## features
- implemented purely in Rust
- can read and write almost all data types stored in PDB files produced by modern compilers (tested against LLVM)
- produces valid PDB files that can be parsed by tools like `llvm-pdbutil`
- can stream parts of the PDB without having to load contents of the file into memory
- lightweight, only 4 dependencies

## examples
- [reading a PDB file](/examples/read.rs)
- [assembling and writing a custom PDB file](/examples/write.rs)
