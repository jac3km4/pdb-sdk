//! Opt-in writer regressions checked by an independent CodeView consumer.

use std::io::Cursor;
use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result, bail};
use pdb_sdk::builders::{ModuleBuilder, PdbBuilder};
use pdb_sdk::codeview::DataRegionOffset;
use pdb_sdk::codeview::symbols::{
    CompileProperties, Constant, Public, PublicProperties, SymbolRecord, Version,
};
use pdb_sdk::codeview::types::{
    BuiltinType, CallingConvention, ClassProperties, FunctionProperties, IdRecord, MemberAccess,
    MemberProperties, PointerKind, PointerMode, PointerProperties, PointerToMemberRepresentation,
    StructRecord, TypeRecord,
};
use pdb_sdk::dbi::SectionContrib;
use pdb_sdk::module::{DebugSubsectionEntry, DebugSubsectionRecordType};
use pdb_sdk::utils::StrBuf;
use pdb_sdk::{Integer, TypeIndex};

#[path = "common/llvm.rs"]
mod llvm;

fn write_pdb(builder: PdbBuilder, path: &Path) -> Result<()> {
    let mut output = Cursor::new(Vec::new());
    builder.commit(&mut output)?;
    std::fs::write(path, output.into_inner())?;
    Ok(())
}

fn normalized(dump: &str) -> String {
    dump.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn assert_anchors(dump: &str, anchors: &[&str]) {
    for anchor in anchors {
        assert!(
            dump.contains(anchor),
            "missing LLVM anchor {anchor:?}: {dump}"
        );
    }
}

// The shared helper deliberately has a fixed set of dump flags. Keep discovery
// and error reporting equivalent here for focused type/module inspections.
fn dump_with_flags(path: &Path, flags: &[&str]) -> Result<String> {
    llvm::require_dump_tool()?;
    let executable = if let Some(path) = std::env::var_os("LLVM_PDBUTIL") {
        std::path::PathBuf::from(path).canonicalize()?
    } else {
        ["llvm-pdbutil-18", "llvm-pdbutil"]
            .into_iter()
            .find(|name| {
                Command::new(name)
                    .arg("--version")
                    .output()
                    .is_ok_and(|output| output.status.success())
            })
            .context("no working llvm-pdbutil")?
            .into()
    };
    let output = Command::new(&executable)
        .arg("dump")
        .args(flags)
        .arg(path)
        .output()
        .with_context(|| format!("failed to execute {}", executable.display()))?;
    if !output.status.success() {
        bail!(
            "{} failed to dump {}: {}\nstdout: {}\nstderr: {}",
            executable.display(),
            path.display(),
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
    }
    Ok(normalized(&String::from_utf8(output.stdout)?))
}

fn module(name: &str, index: u16) -> ModuleBuilder {
    ModuleBuilder::new(
        name.into(),
        format!("object{index}.obj"),
        SectionContrib {
            i_sect: 1,
            pad1: [0; 2],
            offset: i32::from(index) * 0x100,
            size: 0x80,
            characteristics: 0x6000_0020,
            i_mod: index,
            pad2: [0; 2],
            data_crc: 0,
            reloc_crc: 0,
        },
    )
}

fn procedure(builder: &mut PdbBuilder, name: &str) -> TypeIndex {
    let args = builder.tpi().add(
        "args",
        TypeRecord::ArgList {
            count: 0,
            arg_list: vec![],
        },
    );
    let ty = builder.tpi().add(
        name,
        TypeRecord::Procedure {
            return_type: Some(BuiltinType::I32.into()),
            calling_conv: CallingConvention::NearC,
            properties: FunctionProperties::new(),
            arg_count: 0,
            arg_list: args,
        },
    );
    builder.ipi().add(
        name,
        IdRecord::FuncId {
            parent_scope: None,
            function_type: ty,
            name: StrBuf::new(name),
        },
    )
}

#[test]
#[ignore = "requires llvm-pdbutil; run with --ignored"]
fn llvm_modules_source_names_and_unaligned_c13_successor() -> Result<()> {
    let directory = tempfile::tempdir()?;
    // Cross every module-info alignment residue with every file-info residue.
    for (module_residue, source_residue) in (0..4).flat_map(|m| (0..4).map(move |s| (m, s))) {
        let mut builder = PdbBuilder::default();
        let function_id = procedure(&mut builder, "exported_function");
        let first_name = format!("unit{}", "x".repeat(module_residue));
        let source = format!("src{}.cpp", "x".repeat(source_residue));
        let mut first = module(&first_name, 0);
        first.add_source_file(source.clone());
        // A valid string table with a non-aligned payload, not arbitrary bytes.
        first.add_debug_entry(DebugSubsectionEntry {
            record_type: DebugSubsectionRecordType::StringTable,
            data: format!("\0{}\0", "a".repeat(source_residue)).into_bytes(),
        });
        // Nonempty exports force LLVM to find and decode the following header.
        let mut exports = Vec::new();
        exports.extend_from_slice(&u32::from(function_id).to_le_bytes());
        exports.extend_from_slice(&u32::from(function_id).to_le_bytes());
        first.add_debug_entry(DebugSubsectionEntry {
            record_type: DebugSubsectionRecordType::CrossScopeExports,
            data: exports,
        });
        let mut second = module("following_module", 1);
        second.add_source_file("second.cpp".into());
        second.add_source_file("shared.h".into());
        second.add_symbol(SymbolRecord::ObjectName {
            signature: 0,
            name: StrBuf::new("following.obj"),
        });
        builder.dbi().add_module(first).add_module(second);
        let path = directory
            .path()
            .join(format!("modules {module_residue} {source_residue}.pdb"));
        write_pdb(builder, &path)?;
        let dump = dump_with_flags(&path, &["--modules", "--files", "--symbols", "--xme"])?;

        assert_anchors(
            &dump,
            &[
                &first_name,
                &source,
                "following_module",
                "second.cpp",
                "shared.h",
                "S_OBJNAME",
                "following.obj",
            ],
        );
        assert_anchors(&dump, &["# files: 1", "# files: 2", "Cross Module Exports"]);
        let exports = dump
            .split_once("Cross Module Exports")
            .context("missing exports")?
            .1;
        assert_anchors(exports, &["Local ID | Global ID 0x1000 | 0x1000"]);
    }
    directory.close()?;
    Ok(())
}

#[test]
#[ignore = "requires llvm-pdbutil; run with --ignored"]
fn llvm_member_pointer_representation_and_split_field_list() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let mut builder = PdbBuilder::default();
    let member = |name: &str, offset| TypeRecord::DataMember {
        properties: MemberProperties::new().with_access(MemberAccess::Public),
        field_type: Some(BuiltinType::I32.into()),
        offset: Integer::U16(offset),
        name: StrBuf::new(name),
    };
    let tail = builder.tpi().add(
        "tail",
        TypeRecord::FieldList {
            fields: vec![member("second", 4)],
        },
    );
    let head = builder.tpi().add(
        "head",
        TypeRecord::FieldList {
            fields: vec![member("first", 0), TypeRecord::ListContinuation(tail)],
        },
    );
    let class = builder.tpi().add(
        "Widget",
        TypeRecord::Struct(StructRecord {
            member_count: 2,
            properties: ClassProperties::new(),
            field_list: Some(head),
            derivation_list: None,
            vtable_shape: None,
            size: Integer::U16(8),
            name: StrBuf::new("Widget"),
            unique_name: StrBuf::new(""),
        }),
    );
    builder.tpi().add(
        "member_pointer",
        TypeRecord::Pointer {
            referent: Some(BuiltinType::I32.into()),
            properties: PointerProperties::new()
                .with_kind(PointerKind::Near64)
                .with_mode(PointerMode::DataMember)
                .with_size(4),
            containing_class: Some(class),
            representation: Some(PointerToMemberRepresentation::SingleInheritanceData),
        },
    );
    builder.tpi().add(
        "ordinary_pointer",
        TypeRecord::Pointer {
            referent: Some(class),
            properties: PointerProperties::new()
                .with_kind(PointerKind::Near64)
                .with_size(8),
            containing_class: None,
            representation: None,
        },
    );
    let path = directory.path().join("member types.pdb");
    write_pdb(builder, &path)?;
    let dump = dump_with_flags(&path, &["--types", "--type-data"])?;

    assert_anchors(
        &dump,
        &[
            "LF_INDEX",
            "continuation = 0x1000",
            "`first`",
            "`second`",
            "offset = 4",
            "`Widget`",
            "field list: 0x1001",
            "0x1003 | LF_POINTER [size = 20]",
            "mode = data member pointer",
            // LLVM's text dumper omits these fields. Its raw bytes must contain
            // class 0x1002, representation 1, then LF_PAD2/LF_PAD1.
            "02100000 0100F2F1",
            "0x1004 | LF_POINTER [size = 12]",
            "referent = 0x1002",
            "mode = pointer",
        ],
    );
    directory.close()?;
    Ok(())
}

#[test]
#[ignore = "requires llvm-pdbutil; run with --ignored"]
fn llvm_counted_symbols_and_string_vectors() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let mut builder = PdbBuilder::default();
    let first = procedure(&mut builder, "inline_first");
    let second = procedure(&mut builder, "inline_second");
    let mut module = module("symbols", 0);
    module.add_symbol(SymbolRecord::Compile2 {
        properties: CompileProperties::new(),
        machine: 0xd0,
        frontend_version: Version {
            major: 19,
            minor: 11,
            build: 1234,
        },
        backend_version: Version {
            major: 19,
            minor: 12,
            build: 5678,
        },
        version: StrBuf::new("interop compiler"),
        extra_settings: vec![StrBuf::new("/O2"), StrBuf::new("/Zi")],
    });
    module.add_symbol(SymbolRecord::EnvBlock {
        reserved: 0,
        fields: vec![
            StrBuf::new("cwd"),
            StrBuf::new("C:\\interop"),
            StrBuf::new("cmd"),
            StrBuf::new("cl /c input.cpp"),
        ],
    });
    module.add_symbol(SymbolRecord::Annotation {
        code_offset: DataRegionOffset {
            offset: 0x24,
            segment: 1,
        },
        strings: vec![
            StrBuf::new("first annotation"),
            StrBuf::new("second annotation"),
        ],
    });
    for types in [vec![first, second], vec![]] {
        module.add_symbol(SymbolRecord::Inlinees {
            types: types.clone(),
        });
        module.add_symbol(SymbolRecord::Caller {
            types: types.clone(),
        });
        module.add_symbol(SymbolRecord::Callee { types });
    }
    module.add_symbol(SymbolRecord::ObjectName {
        signature: 0x1234,
        name: StrBuf::new("after_vectors.obj"),
    });
    builder.dbi().add_module(module);
    let path = directory.path().join("counted symbols.pdb");
    write_pdb(builder, &path)?;
    let dump = dump_with_flags(&path, &["--symbols"])?;

    assert_anchors(
        &dump,
        &[
            "S_COMPILE2",
            "19.11.1234",
            "19.12.5678",
            "interop compiler",
            "/O2",
            "/Zi",
            "S_ENVBLOCK",
            "cwd",
            "C:\\interop",
            "cmd",
            "cl /c input.cpp",
            "S_ANNOTATION",
            "first annotation",
            "second annotation",
            "S_INLINEES",
            "S_CALLEES",
            "S_CALLERS",
            "0x1000",
            "0x1001",
            "S_OBJNAME",
            "after_vectors.obj",
            "extra strings = [ /O2 /Zi]",
            "addr = 0001:0036 strings = [ first annotation second annotation]",
            "inlinee: 0x1000 (inline_first) inlinee: 0x1001 (inline_second)",
            "callee: 0x1000 (inline_first) callee: 0x1001 (inline_second)",
            "caller: 0x1000 (inline_first) caller: 0x1001 (inline_second)",
            "192 | S_INLINEES [size = 8]",
            "200 | S_CALLEES [size = 8]",
            "208 | S_CALLERS [size = 8]",
            "216 | S_OBJNAME [size = 28] sig=4660",
        ],
    );
    for kind in ["S_INLINEES", "S_CALLEES", "S_CALLERS"] {
        assert_eq!(dump.matches(kind).count(), 2, "{dump}");
    }
    directory.close()?;
    Ok(())
}

#[test]
#[ignore = "requires llvm-pdbutil; run with --ignored"]
fn llvm_interleaved_public_and_global_indexes() -> Result<()> {
    let tool = llvm::require_dump_tool()?;
    let directory = tempfile::tempdir()?;
    let mut builder = PdbBuilder::default();
    for (name, value, address) in [
        ("first", 17, 0x30),
        ("second_longer", 29, 0x10),
        ("third", 43, 0x20),
    ] {
        // Start with a global, then reopen the public view on every iteration.
        builder
            .dbi()
            .symbols()
            .finish_publics()
            .add(SymbolRecord::Constant(Constant {
                constant_type: BuiltinType::I32.into(),
                value: Integer::I32(value),
                name: StrBuf::new(format!("global_{name}")),
            }));
        builder.dbi().symbols().add(Public {
            properties: PublicProperties::new().with_is_function(true),
            offset: DataRegionOffset {
                offset: address,
                segment: 1,
            },
            name: StrBuf::new(format!("public_{name}")),
        });
    }
    let path = directory.path().join("interleaved indexes.pdb");
    write_pdb(builder, &path)?;
    let dump = normalized(&tool.dump(&path)?);
    let (_, globals) = dump
        .split_once("Global Symbols")
        .context("missing globals section")?;
    let (globals, publics) = globals
        .split_once("Public Symbols")
        .context("missing publics section")?;
    for (name, value, address) in [
        ("first", 17, "0001:0048"),
        ("second_longer", 29, "0001:0016"),
        ("third", 43, "0001:0032"),
    ] {
        assert_anchors(
            globals,
            &[&format!("`global_{name}`"), &format!("value = {value}")],
        );
        assert!(!globals.contains(&format!("`public_{name}`")), "{globals}");
        assert_anchors(publics, &[&format!("`public_{name}`"), address]);
        assert!(!publics.contains(&format!("`global_{name}`")), "{publics}");
    }
    assert_eq!(globals.matches("S_CONSTANT").count(), 3, "{globals}");
    assert_eq!(publics.matches("S_PUB32").count(), 3, "{publics}");
    directory.close()?;
    Ok(())
}
