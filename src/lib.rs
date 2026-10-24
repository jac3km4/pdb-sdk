//! Read and write Microsoft PDB (Program Database) files with per-stream access.
//!
//! [`PdbFile`] reads the MSF directory when opened, then decodes only the streams
//! requested by its getters through a shared `Read + Seek` reader. It does not
//! load the entire file up front. Directory metadata, requested streams, and
//! decoded record collections can still allocate memory; this is not a
//! constant-memory parser.
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
//! This library is alpha-quality: APIs may change, and not every PDB/CodeView
//! variant is supported. Missing streams and unsupported records can return
//! errors. The builder writes supported records, not lossless edits of arbitrary
//! PDBs. There is no high-level address-to-source symbolication API. Robust
//! handling of every hostile input is not guaranteed; apply resource limits or
//! isolation when processing untrusted files.

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
