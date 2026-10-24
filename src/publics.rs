//! Public-symbol indexes and address/thunk maps, separate from symbol records.

use std::collections::BTreeMap;
use std::io;

use declio::ctx::Len;
use declio::{Decode, Encode, EncodedSize};
use derive_getters::Getters;

use crate::codeview::symbols::Public;
use crate::result::Result;
use crate::symbol_map::SymbolMap;
use crate::{SymbolOffset, constants};

/// The public-symbol hash index with address and thunk maps.
///
/// Public records reside in the separate shared symbol record stream. A PDB
/// public symbol is not necessarily a PE export. This type exposes the parsed
/// maps, but does not implement name or nearest-address lookup.
#[derive(Debug, Getters)]
pub struct Publics {
    /// Hash index referring to records in the shared symbol record stream.
    map: SymbolMap,
    /// Symbol-record byte offsets ordered by the public symbols' addresses.
    address_map: Vec<SymbolOffset>,
    /// Raw thunk-map entries; no thunk resolution is performed.
    thunk_map: Vec<u32>,
}

impl Publics {
    pub(crate) fn from_publics(publics: &BTreeMap<SymbolOffset, Public>) -> Self {
        let index = SymbolMap::from_symbols(publics);

        let mut address_map: Vec<_> = publics.keys().copied().collect();
        address_map.sort_by_key(|off| publics.get(off).map(|sym| &sym.offset));

        Self {
            map: index,
            address_map,
            thunk_map: vec![],
        }
    }

    pub(crate) fn read_with_header<R>(mut input: R) -> Result<Self>
    where
        R: io::Read,
    {
        let header = PublicsHeader::decode((), &mut input)?;
        let globals = SymbolMap::read_with_header(&mut input)?;
        let address_count = header.addr_map / 4;
        let address_map = Decode::decode(
            (Len(address_count as usize), constants::ENDIANESS),
            &mut input,
        )?;
        let thunk_map = Decode::decode(
            (Len(header.num_thunks as usize), constants::ENDIANESS),
            &mut input,
        )?;

        Ok(Self {
            map: globals,
            address_map,
            thunk_map,
        })
    }

    pub(crate) fn write_with_header<S>(&self, sink: &mut S) -> Result<()>
    where
        S: io::Write,
    {
        let gsi_header = self.map.get_header();
        let header = PublicsHeader {
            sym_hash: (gsi_header.encoded_size(()) + self.map.encoded_size(())) as u32,
            addr_map: self.address_map.encoded_size(()) as u32,
            num_thunks: 0,
            size_of_thunk: 0,
            i_sect_thunk_table: 0,
            reserved: [0; 2],
            off_thunk_table: 0,
            num_sections: 0,
        };
        header.encode((), sink)?;
        gsi_header.encode((), sink)?;
        self.map.encode((), sink)?;
        self.address_map.encode(((),), sink)?;

        Ok(())
    }
}

#[derive(Debug, Encode, Decode)]
#[declio(ctx_is = "constants::ENDIANESS")]
struct PublicsHeader {
    sym_hash: u32,
    addr_map: u32,
    num_thunks: u32,
    size_of_thunk: u32,
    i_sect_thunk_table: u16,
    reserved: [u8; 2],
    off_thunk_table: u32,
    num_sections: u32,
}
