use std::fs::File;
use std::io;

use pdb_sdk::builders::PdbBuilder;
use pdb_sdk::codeview::symbols::{Constant, ProcedureProperties, Public, PublicProperties, SymbolRecord};
use pdb_sdk::codeview::types::{BuiltinType, IdRecord, PointerKind, PointerProperties, TypeRecord};
use pdb_sdk::codeview::DataRegionOffset;
use pdb_sdk::result::Result;
use pdb_sdk::utils::StrBuf;
use pdb_sdk::Integer;

fn main() -> Result<()> {
    let mut builder = PdbBuilder::default();
    builder.tpi().add("pointer_type", TypeRecord::Pointer {
        referent: BuiltinType::I64.into(),
        properties: PointerProperties::new()
            .with_is_const(true)
            .with_is_volatile(true)
            .with_kind(PointerKind::Near64),
        containing_class: None,
    });
    builder.ipi().add("string_id", IdRecord::StringId {
        id: None,
        string: StrBuf::new("test"),
    });

    let mut sym_builder = builder.dbi().symbols();
    sym_builder.add(Public {
        properties: PublicProperties::new().with_is_msil(true),
        offset: DataRegionOffset::new(0, 0),
        name: StrBuf::new("hello"),
    });
    let sym_builder = sym_builder.finish_publics();
    sym_builder.add(SymbolRecord::Label {
        code_offset: DataRegionOffset::new(0, 0),
        properties: ProcedureProperties::new()
            .with_has_fp(true)
            .with_is_no_return(true),
        name: StrBuf::new("label"),
    });
    sym_builder.add(SymbolRecord::Constant(Constant {
        constant_type: BuiltinType::I32.into(),
        value: Integer::I32(2),
        name: StrBuf::new("myconstant"),
    }));

    builder.commit(io::BufWriter::new(File::create("custom.pdb")?))
}
