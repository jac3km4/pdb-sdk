use std::fs;
use std::path::PathBuf;

use anyhow::{bail, Context as _, Result};
use object::{LittleEndian as LE, Object, ObjectSection};
use pdb_sdk::builders::{ModuleBuilder, PdbBuilder};
use pdb_sdk::codeview::symbols::{Procedure, ProcedureProperties, Public, PublicProperties, SymbolRecord};
use pdb_sdk::codeview::types::{
    CallingConvention, FunctionProperties, ModifierProperties, PointerProperties, TypeRecord
};
use pdb_sdk::codeview::DataRegionOffset;
use pdb_sdk::dbi::{SectionContrib, SectionHeader};
use pdb_sdk::utils::StrBuf;
use pdb_sdk::Guid;

fn main() -> Result<()> {
    let exe_path = PathBuf::from(std::env::args().nth(1).context("usage: fake_pdb [exe_path]")?);
    let exe_data = fs::read(&exe_path)?;
    let obj = object::File::parse(&*exe_data)?;

    let pdb_info = obj.pdb_info()?.context("exe has no PDB info")?;

    let timestamp = match &obj {
        object::File::Coff(f) => f.coff_header().time_date_stamp.get(LE),
        object::File::Pe32(f) => f.nt_headers().file_header.time_date_stamp.get(LE),
        object::File::Pe64(f) => f.nt_headers().file_header.time_date_stamp.get(LE),
        _ => bail!("unsupported object type"),
    };

    let mut builder = PdbBuilder::default();
    builder.info().guid(Guid(pdb_info.guid()));
    builder.info().age(pdb_info.age());
    builder.info().signature(timestamp);

    let base_address = obj.relative_address_base();
    for section in obj.sections() {
        let mut name = [0; 8];
        let name_bytes = section.name_bytes()?;
        let len = name_bytes.len().min(8);
        name[0..len].copy_from_slice(&name_bytes[0..len]);

        let range = section
            .file_range()
            .context("section does not have a file range")?;

        let characteristics = match section.flags() {
            object::SectionFlags::Coff { characteristics } => characteristics,
            _ => bail!("expected Coff section"),
        };

        builder.dbi().add_section_header(SectionHeader {
            name,
            virtual_size: section.size() as u32,
            virtual_address: (section.address() - base_address) as u32,
            size_of_raw_data: range.1 as u32,
            pointer_to_raw_data: range.0 as u32, // TODO doesn't always match existing pdb, not sure where it comes from
            pointer_to_relocations: 0,
            pointer_to_line_numbers: 0,
            number_of_relocations: 0,
            number_of_line_numbers: 0,
            characteristics,
        });
    }

    let fn_type = {
        let tpi = builder.tpi();
        // 0x1005 | LF_MODIFIER [size = 12]
        //          referent = 0x0071 (wchar_t), modifiers = const
        // 0x1007 | LF_POINTER [size = 12]
        //          referent = 0x1005, mode = pointer, opts = None, kind = ptr64
        // 0x15E2 | LF_ARGLIST [size = 12]
        //          0x1007: `const wchar_t*`
        // 0xABE1 | LF_PROCEDURE [size = 16]
        //          return type = 0x0074 (int), # args = 1, param list = 0x15E2
        //          calling conv = cdecl, options = None

        let referent = tpi.add("idk", TypeRecord::Modifier {
            modified_type: 0x71.try_into().unwrap(), // wchar_t
            properties: ModifierProperties::new().with_is_const(true),
        });

        let arg = tpi.add("idk2", TypeRecord::Pointer {
            referent,
            properties: PointerProperties::new(),
            containing_class: None,
        });

        let arg_list = tpi.add("idk3", TypeRecord::ArgList {
            count: 1,
            arg_list: vec![arg.into()],
        });

        let fn_type = tpi.add("func", TypeRecord::Procedure {
            return_type: Some(0x74.try_into().unwrap()), // int
            calling_conv: CallingConvention::NearC,
            properties: FunctionProperties::new(),
            arg_count: 1,
            arg_list,
        });

        fn_type
    };

    let mut sym_builder = builder.dbi().symbols();

    sym_builder.add(Public {
        properties: PublicProperties::new().with_is_function(true),
        offset: DataRegionOffset::new(0x3e78800, 1),
        name: StrBuf::new("My_Function"),
    });

    let sym_builder = sym_builder.finish_publics();
    let proc = sym_builder.add(SymbolRecord::GlobalProc(Procedure {
        parent: None,
        end: 0.into(),
        next: None,
        code_size: 0xc,
        dbg_start_offset: 0,
        dbg_end_offset: 0xc,
        function_type: fn_type,
        code_offset: DataRegionOffset::new(0x20, 1),
        properties: ProcedureProperties::new(),
        name: StrBuf::new("My_Function2"),
    }));
    let end = sym_builder.add(SymbolRecord::ProcEnd);
    match sym_builder.globals.get_mut(&proc).unwrap() {
        SymbolRecord::GlobalProc(proc) => proc.end = end,
        _ => unreachable!(),
    }

    let text_base: u64 = 0x140001000;

    let sec_contrib = SectionContrib {
        i_sect: 1,
        pad1: [0, 0],
        offset: 0,
        size: 0x0624fcec,
        characteristics: 0,
        i_mod: 0,
        pad2: [0, 0],
        data_crc: 0,
        reloc_crc: 0,
    };

    let mut module = ModuleBuilder::new("main_module".into(), "/fake/path".into(), sec_contrib);

    // module.add_source_file("/afsd/fdsa/fds/af".into());

    // module.add_symbol(SymbolRecord::GlobalProc(Procedure {
    //     parent: None,
    //     end: 0.into(),
    //     next: None,
    //     code_size: 0x1000,
    //     dbg_start_offset: 0,
    //     dbg_end_offset: 0,
    //     function_type: fn_type,
    //     code_offset: DataRegionOffset::new((0x143e75ac9 - text_base) as u32, 1),
    //     properties: ProcedureProperties::new(),
    //     name: StrBuf::new("Holy_FUCK_this_was_annoying_to_get_working"),
    // }));
    // let end = module.add_symbol(SymbolRecord::ProcEnd);
    // match &mut module.symbols[0] {
    //     SymbolRecord::GlobalProc(proc) => proc.end = end,
    //     _ => unreachable!(),
    // }

    let mut add_func = |addr: u64, len: u32, name: &str| {
        let index = module.symbols.len();
        module.add_symbol(SymbolRecord::GlobalProc(Procedure {
            parent: None,
            end: 0.into(),
            next: None,
            code_size: len,
            dbg_start_offset: 0,
            dbg_end_offset: 0,
            function_type: fn_type,
            code_offset: DataRegionOffset::new((addr - text_base) as u32, 1),
            properties: ProcedureProperties::new(),
            name: StrBuf::new(name),
        }));
        let end = module.add_symbol(SymbolRecord::ProcEnd);
        match &mut module.symbols[index] {
            SymbolRecord::GlobalProc(proc) => proc.end = end,
            _ => unreachable!(),
        }
    };

    // 0x0000000141aea826 FSD-Win64-Shipping.exe!UnknownFunction []
    // 0x0000000141aecae6 FSD-Win64-Shipping.exe!UnknownFunction []
    // 0x0000000141aaa0fd FSD-Win64-Shipping.exe!UnknownFunction []
    // 0x000000014315f0bf FSD-Win64-Shipping.exe!UnknownFunction []
    // 0x0000000143154b1d FSD-Win64-Shipping.exe!UnknownFunction []

    // add_func(0x0000000141aea826, 0x10, "some_fake");

    add_func(0x0000000141aea826, 0x10, "Some");
    add_func(0x0000000141aecae6, 0x10, "Obviously");
    add_func(0x0000000141aaa0fd, 0x10, "Fake");
    add_func(0x000000014315f0bf, 0x10, "Function");
    add_func(0x0000000143154b1d, 0x10, "Names");

    builder.dbi().add_module(module);

    // func @ 143E79800
    // 194296 | S_GPROC32 [size = 60] `GuardedMainWrapper`
    //          parent = 0, end = 194572, addr = 0001:65505280, code size = 52
    //          type = `0xABE1 (int (const wchar_t*))`, debug start = 4, debug end = 47, flags = opt debuginfo
    // 194356 | S_LOCAL [size = 20] `CmdLine`
    //          type=0x1007 (const wchar_t*), flags = param
    // 194376 | S_DEFRANGE_REGISTER [size = 20]
    //          register = RCX, may have no name = false, range start = 0001:65505280, length = 47
    //          gaps = [(26,12)]
    // 194396 | S_DEFRANGE_FRAMEPOINTER_REL_FULL_SCOPE [size = 8] offset = 64
    // 194404 | S_LOCAL [size = 24] `ErrorLevel`
    //          type=0x0074 (int), flags = none
    // 194428 | S_DEFRANGE_REGISTER [size = 16]
    //          register = EAX, may have no name = false, range start = 0001:65505316, length = 2
    //          gaps = []
    // 194444 | S_DEFRANGE_FRAMEPOINTER_REL_FULL_SCOPE [size = 8] offset = 32
    // 194452 | S_CALLEES [size = 16]
    //          callee: 0x131AEE (GuardedMain)
    //          callee: 0x131AEE (GuardedMain)
    // 194468 | S_FRAMEPROC [size = 32]
    //          size = 56, padding size = 0, offset to padding = 0
    //          bytes of callee saved registers = 0, exception handler addr = 0000:0000
    //          local fp reg = RSP, param fp reg = RSP
    //          flags = has seh | has async eh | opt speed
    // 194500 | S_LABEL32 [size = 20] `$LN10` (addr = 0001:65505312)
    //          flags = none
    // 194520 | S_REGREL32 [size = 24] `CmdLine`
    //          type = 0x1007 (const wchar_t*), register = RSP, offset = 64
    // 194544 | S_REGREL32 [size = 28] `ErrorLevel`
    //          type = 0x0074 (int), register = RSP, offset = 32
    // 194572 | S_END [size = 4]

    let mut output = std::io::BufWriter::new(fs::File::create(exe_path.with_extension("pdb"))?);
    builder.commit(&mut output)?;

    Ok(())
}
