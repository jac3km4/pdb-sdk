//! Read and write native Microsoft PDB files with per-stream access.
//!
//! [`PdbFile`] reads the MSF 7.0 directory at open and decodes requested streams
//! through a shared `Read + Seek` reader. Directory metadata and decoded records
//! allocate memory; opening does not load the whole file.
//!
//! # Format and API map
//!
//! MSF supplies the block-based container; CodeView supplies type, ID, and symbol
//! records. Numeric fields are little-endian unless specified otherwise.
//!
//! - [`info`]: PDB identity, features, and named-stream locations.
//! - [`types`]: TPI type records, IPI ID records, and hash candidates.
//! - [`dbi`]: module/section metadata and references to other debug streams.
//! - [`module`]: per-module symbols and C13 subsections.
//! - [`symbols`]: shared symbol records; [`Publics`] and [`SymbolMap`] index them.
//! - [`codeview`]: supported binary records; [`builders`]: stream construction.
//!
//! Stream indices, type/ID indices, string/symbol byte offsets, and section-relative
//! addresses use different coordinate systems. Public symbols are not necessarily
//! PE exports, and type hash candidates require checking the record's name.
//!
//! See the [LLVM PDB guide](https://llvm.org/docs/PDB/index.html) and
//! [native structures](https://llvm.org/doxygen/RawTypes_8h.html) for format
//! documentation and an independent open-source implementation.
//!
//! # In-memory roundtrip
//!
//! ```
//! use std::io::Cursor;
//! use pdb_sdk::{PdbFile, builders::PdbBuilder};
//!
//! let mut builder = PdbBuilder::default();
//! builder.info().signature(42).age(2);
//! let mut bytes = Cursor::new(Vec::new());
//! builder.commit(&mut bytes)?;
//! // Commit rewrites the superblock; rewind before reading the container.
//! bytes.set_position(0);
//! let mut pdb = PdbFile::open(bytes)?;
//! let info = pdb.get_info()?;
//! assert_eq!(info.header().signature, 42);
//! assert_eq!(info.header().age, 2);
//! assert_eq!(pdb.get_dbi()?.header().age, 2);
//! assert!(pdb.get_tpi()?.records().is_empty());
//! # Ok::<(), pdb_sdk::result::Error>(())
//! ```
//!
//! # Status and limits
//!
//! Alpha-quality: APIs may change, and missing streams or unsupported records can
//! return errors. The builder is not a lossless editor. There is no high-level
//! address-to-source resolver or Portable PDB reader. C13 access is not complete
//! line resolution. Use resource limits or isolation for untrusted input; robust
//! handling of every hostile file is not guaranteed.

pub(crate) use msf::MsfStreamLayout;
pub use msf::StreamIndex;
pub use pdb::PdbFile;
pub(crate) use pdb::{BufMsfStream, BuiltinStream};
pub use primitives::{Guid, IdIndex, IndexIsZero, Integer, StringOffset, SymbolOffset, TypeIndex};
pub use publics::Publics;
pub use strings::Strings;
pub use symbol_map::SymbolMap;
pub use utils::StrBuf;

pub mod builders;
mod codecs;
pub mod codeview;
mod constants;
pub mod dbi;
mod hash;
pub mod info;
pub mod module;
mod msf;
mod pdb;
mod primitives;
mod publics;
pub mod result;
mod strings;
mod symbol_map;
pub mod symbols;
pub mod types;
pub mod utils;
