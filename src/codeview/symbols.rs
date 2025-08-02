use std::fmt::Debug;

use declio::util::LittleEndian;
use declio::{Decode, Encode, EncodedSize};
use modular_bitfield::prelude::*;

use super::{DataRegionOffset, Register};
use crate::utils::StrBuf;
use crate::{
    codecs, constants, impl_bitfield_codecs, impl_bitfield_specifier_codecs, IdIndex, Integer, SymbolOffset, TypeIndex
};

#[derive(Debug, Encode, Decode, EncodedSize)]
#[declio(ctx_is = "constants::ENDIANESS", id_type = "LittleEndian<u16>")]
pub enum SymbolRecord {
    #[declio(id = "constants::S_INLINEES.into()")]
    Inlinees,
    #[declio(id = "constants::S_END.into()")]
    ScopeEnd,
    #[declio(id = "constants::S_INLINESITE_END.into()")]
    InlineSiteEnd,
    #[declio(id = "constants::S_PROC_ID_END.into()")]
    ProcEnd,
    #[declio(id = "constants::S_THUNK32.into()")]
    Thunk32 {
        #[declio(with = "codecs::optional_index")]
        parent: Option<SymbolOffset>,
        end: SymbolOffset,
        #[declio(with = "codecs::optional_index")]
        next: Option<SymbolOffset>,
        offset: DataRegionOffset,
        size: u16,
        ordinal: ThunkOrdinal,
        name: StrBuf,
    },
    #[declio(id = "constants::S_TRAMPOLINE.into()")]
    Trampoline {
        trampoline_type: TrampolineType,
        size: u16,
        thunk_offset: u32,
        target_offset: u32,
        thunk_section: u16,
        target_section: u16,
    },
    #[declio(id = "constants::S_SECTION.into()")]
    Section {
        section_number: u16,
        alignment: u8,
        rva: u32,
        size: u32,
        characteristics: u32,
        name: StrBuf,
    },
    #[declio(id = "constants::S_COFFGROUP.into()")]
    CoffGroup {
        size: u32,
        characteristics: u32,
        offset: DataRegionOffset,
        name: StrBuf,
    },
    #[declio(id = "constants::S_EXPORT.into()")]
    Export {
        ordinal: u16,
        properties: ExportProperties,
        name: StrBuf,
    },
    #[declio(id = "constants::S_LPROC32.into()")]
    Proc(Procedure),
    #[declio(id = "constants::S_GPROC32.into()")]
    GlobalProc(Procedure),
    #[declio(id = "constants::S_LPROC32_ID.into()")]
    ProcId(Procedure),
    #[declio(id = "constants::S_GPROC32_ID.into()")]
    GlobalProcId(Procedure),
    #[declio(id = "constants::S_LPROC32_DPC.into()")]
    DPCProc(Procedure),
    #[declio(id = "constants::S_LPROC32_DPC_ID.into()")]
    DPCProcId(Procedure),
    #[declio(id = "constants::S_REGISTER.into()")]
    Register {
        contained_type: TypeIndex,
        register: Register,
        name: StrBuf,
    },
    #[declio(id = "constants::S_PUB32.into()")]
    Public32(Public),
    #[declio(id = "constants::S_PROCREF.into()")]
    ProcedureRef(ProcedureRef),
    #[declio(id = "constants::S_LPROCREF.into()")]
    LocalProcedureRef(ProcedureRef),
    #[declio(id = "constants::S_ENVBLOCK.into()")]
    EnvBlock {
        reserved: u8,
        #[declio(with = "codecs::padded_rem_list")]
        fields: Vec<StrBuf>,
    },
    #[declio(id = "constants::S_INLINESITE.into()")]
    InlineSite {
        #[declio(with = "codecs::optional_index")]
        parent: Option<SymbolOffset>,
        end: SymbolOffset,
        inlinee: IdIndex,
        annotations: (), // TODO
    },
    #[declio(id = "constants::S_LOCAL.into()")]
    Local {
        local_type: TypeIndex,
        properties: LocalProperties,
        name: StrBuf,
    },
    #[declio(id = "constants::S_DEFRANGE.into()")]
    DefRange {
        program: u32,
        range: LocalVariableRange,
        #[declio(with = "codecs::padded_rem_list")]
        gaps: Vec<LocalVariableGap>,
    },
    #[declio(id = "constants::S_DEFRANGE_SUBFIELD.into()")]
    DefRangeSubfield {
        program: u32,
        offset_in_parent: u16,
        range: LocalVariableRange,
        #[declio(with = "codecs::padded_rem_list")]
        gaps: Vec<LocalVariableGap>,
    },
    #[declio(id = "constants::S_DEFRANGE_REGISTER.into()")]
    DefRangeRegister {
        register: Register,
        may_have_no_name: u16,
        range: LocalVariableRange,
        #[declio(with = "codecs::padded_rem_list")]
        gaps: Vec<LocalVariableGap>,
    },
    #[declio(id = "constants::S_DEFRANGE_FRAMEPOINTER_REL.into()")]
    DefRangeFramePointerRel {
        offset: i32,
        range: LocalVariableRange,
        #[declio(with = "codecs::padded_rem_list")]
        gaps: Vec<LocalVariableGap>,
    },
    #[declio(id = "constants::S_DEFRANGE_SUBFIELD_REGISTER.into()")]
    DefRangeSubfieldRegister {
        register: Register,
        may_have_no_name: u16,
        offset_in_parent: u32,
        range: LocalVariableRange,
        #[declio(with = "codecs::padded_rem_list")]
        gaps: Vec<LocalVariableGap>,
    },
    #[declio(id = "constants::S_DEFRANGE_FRAMEPOINTER_REL_FULL_SCOPE.into()")]
    DefRangeFramePointerRelFullScope { offset: i32 },
    #[declio(id = "constants::S_DEFRANGE_REGISTER_REL.into()")]
    DefRangeRegisterRel {
        register: Register,
        properties: DefRangeRegisterRelProperties,
        base_pointer_offset: i32,
        range: LocalVariableRange,
        #[declio(with = "codecs::padded_rem_list")]
        gaps: Vec<LocalVariableGap>,
    },
    #[declio(id = "constants::S_BLOCK32.into()")]
    Block {
        parent: SymbolOffset,
        end: SymbolOffset,
        code_size: u32,
        code_offset: DataRegionOffset,
        name: StrBuf,
    },
    #[declio(id = "constants::S_LABEL32.into()")]
    Label {
        code_offset: DataRegionOffset,
        properties: ProcedureProperties,
        name: StrBuf,
    },
    #[declio(id = "constants::S_OBJNAME.into()")]
    ObjectName { signature: u32, name: StrBuf },
    #[declio(id = "constants::S_COMPILE2.into()")]
    Compile2 {
        properties: CompileProperties,
        machine: u16,
        frontend_version: Version,
        backend_version: Version,
        version: StrBuf,
        #[declio(with = "codecs::padded_rem_list")]
        extra_settings: Vec<StrBuf>,
    },
    #[declio(id = "constants::S_COMPILE3.into()")]
    Compile3 {
        properties: CompileProperties,
        machine: u16,
        frontend_version: Version,
        frontend_qfe: u16,
        backend_version: Version,
        backend_qfe: u16,
        version: StrBuf,
    },
    #[declio(id = "constants::S_FRAMEPROC.into()")]
    FrameProcedure {
        total_frame_bytes: u32,
        padding_frame_bytes: u32,
        offset_to_padding: u32,
        bytes_of_callee_saved_registers: u32,
        offset_of_exception_handler: u32,
        section_id_of_exception_handler: u16,
        properties: FrameProcedureProperties,
    },
    #[declio(id = "constants::S_CALLSITEINFO.into()")]
    CallSiteInfo {
        code_offset: DataRegionOffset,
        call_type: TypeIndex,
    },
    #[declio(id = "constants::S_FILESTATIC.into()")]
    FileStatic {
        index: TypeIndex,
        mod_filename_offset: u32,
        properties: LocalProperties,
        name: StrBuf,
    },
    #[declio(id = "constants::S_HEAPALLOCSITE.into()")]
    HeapAllocationSite {
        code_offset: DataRegionOffset,
        call_instruction_size: u16,
        call_type: TypeIndex,
    },
    #[declio(id = "constants::S_FRAMECOOKIE.into()")]
    FrameCookie {
        code_offset: u32,
        register: Register,
        kind: FrameCookie,
        flags: u8,
    },
    #[declio(id = "constants::S_CALLEES.into()")]
    Caller {
        #[declio(with = "codecs::padded_rem_list")]
        types: Vec<TypeIndex>,
    },
    #[declio(id = "constants::S_CALLERS.into()")]
    Callee,
    #[declio(id = "constants::S_UDT.into()")]
    Udt(UserDefinedType),
    #[declio(id = "constants::S_COBOLUDT.into()")]
    CobolUdt(UserDefinedType),
    #[declio(id = "constants::S_BUILDINFO.into()")]
    BuildInfo { build_record: IdIndex },
    #[declio(id = "constants::S_BPREL32.into()")]
    BasePointerRelative {
        offset: i32,
        value_type: TypeIndex,
        name: StrBuf,
    },
    #[declio(id = "constants::S_REGREL32.into()")]
    RegisterRelative {
        offset: u32,
        value_type: TypeIndex,
        register: Register,
        name: StrBuf,
    },
    #[declio(id = "constants::S_CONSTANT.into()")]
    Constant(Constant),
    #[declio(id = "constants::S_MANCONSTANT.into()")]
    ManagedConstant(Constant),
    #[declio(id = "constants::S_LDATA32.into()")]
    Data(Data),
    #[declio(id = "constants::S_GDATA32.into()")]
    GlobalData(Data),
    #[declio(id = "constants::S_LMANDATA.into()")]
    ManagedLocalData(Data),
    #[declio(id = "constants::S_GMANDATA.into()")]
    ManagedGlobalData(Data),
    #[declio(id = "constants::S_LTHREAD32.into()")]
    ThreadLocalStorage(ThreadLocalStorage),
    #[declio(id = "constants::S_GTHREAD32.into()")]
    GlobalThreadLocalStorage(ThreadLocalStorage),
    #[declio(id = "constants::S_UNAMESPACE.into()")]
    UsingNamespace { name: StrBuf },
    #[declio(id = "constants::S_ANNOTATION.into()")]
    Annotation {
        code_offset: DataRegionOffset,
        #[declio(with = "codecs::padded_rem_list")]
        strings: Vec<StrBuf>,
    },
}

impl SymbolRecord {
    pub fn name(&self) -> Option<&str> {
        match self {
            SymbolRecord::Thunk32 { name, .. } => Some(name.as_ref()),
            SymbolRecord::Section { name, .. } => Some(name.as_ref()),
            SymbolRecord::CoffGroup { name, .. } => Some(name.as_ref()),
            SymbolRecord::Export { name, .. } => Some(name.as_ref()),
            SymbolRecord::Proc(proc) => Some(proc.name.as_ref()),
            SymbolRecord::GlobalProc(proc) => Some(proc.name.as_ref()),
            SymbolRecord::ProcId(proc) => Some(proc.name.as_ref()),
            SymbolRecord::GlobalProcId(proc) => Some(proc.name.as_ref()),
            SymbolRecord::DPCProc(proc) => Some(proc.name.as_ref()),
            SymbolRecord::DPCProcId(proc) => Some(proc.name.as_ref()),
            SymbolRecord::Register { name, .. } => Some(name.as_ref()),
            SymbolRecord::Public32(public) => Some(public.name.as_ref()),
            SymbolRecord::ProcedureRef(proc) => Some(proc.name.as_ref()),
            SymbolRecord::LocalProcedureRef(proc) => Some(proc.name.as_ref()),
            SymbolRecord::Local { name, .. } => Some(name.as_ref()),
            SymbolRecord::Block { name, .. } => Some(name.as_ref()),
            SymbolRecord::Label { name, .. } => Some(name.as_ref()),
            SymbolRecord::ObjectName { name, .. } => Some(name.as_ref()),
            SymbolRecord::FileStatic { name, .. } => Some(name.as_ref()),
            SymbolRecord::Udt(udt) => Some(udt.name.as_ref()),
            SymbolRecord::CobolUdt(udt) => Some(udt.name.as_ref()),
            SymbolRecord::BasePointerRelative { name, .. } => Some(name.as_ref()),
            SymbolRecord::RegisterRelative { name, .. } => Some(name.as_ref()),
            SymbolRecord::Constant(constant) => Some(constant.name.as_ref()),
            SymbolRecord::ManagedConstant(constant) => Some(constant.name.as_ref()),
            SymbolRecord::Data(data) => Some(data.name.as_ref()),
            SymbolRecord::GlobalData(data) => Some(data.name.as_ref()),
            SymbolRecord::ManagedLocalData(data) => Some(data.name.as_ref()),
            SymbolRecord::ManagedGlobalData(data) => Some(data.name.as_ref()),
            SymbolRecord::ThreadLocalStorage(tls) => Some(tls.name.as_ref()),
            SymbolRecord::GlobalThreadLocalStorage(tls) => Some(tls.name.as_ref()),
            SymbolRecord::UsingNamespace { name } => Some(name.as_ref()),
            _ => None,
        }
    }
}

#[derive(Debug, Encode, Decode, EncodedSize)]
#[declio(ctx_is = "constants::ENDIANESS")]
pub struct LocalVariableRange {
    pub offset_start: u32,
    pub i_sect_start: u16,
    pub range: u16,
}

#[derive(Debug, Encode, Decode, EncodedSize)]
#[declio(ctx_is = "constants::ENDIANESS")]
pub struct LocalVariableGap {
    pub gap_start_offset: u16,
    pub range: u16,
}

#[derive(Debug, Encode, Decode, EncodedSize)]
#[declio(ctx_is = "constants::ENDIANESS")]
pub struct Version {
    pub major: u16,
    pub minor: u16,
    pub build: u16,
}

#[derive(Debug, Encode, Decode, EncodedSize)]
#[declio(ctx_is = "constants::ENDIANESS")]
pub struct Public {
    pub properties: PublicProperties,
    pub offset: DataRegionOffset,
    pub name: StrBuf,
}

#[derive(Debug, Encode, Decode, EncodedSize)]
#[declio(ctx_is = "constants::ENDIANESS")]
pub struct UserDefinedType {
    pub udt_type: TypeIndex,
    pub name: StrBuf,
}

#[derive(Debug, Encode, Decode, EncodedSize)]
#[declio(ctx_is = "constants::ENDIANESS")]
pub struct Constant {
    pub constant_type: TypeIndex,
    pub value: Integer,
    pub name: StrBuf,
}

#[derive(Debug, Encode, Decode, EncodedSize)]
#[declio(ctx_is = "constants::ENDIANESS")]
pub struct Data {
    pub data_type: TypeIndex,
    pub offset: DataRegionOffset,
    pub name: StrBuf,
}

#[derive(Debug, Encode, Decode, EncodedSize)]
#[declio(ctx_is = "constants::ENDIANESS")]
pub struct ThreadLocalStorage {
    pub data_type: TypeIndex,
    pub offset: DataRegionOffset,
    pub name: StrBuf,
}

#[derive(Debug, Encode, Decode, EncodedSize)]
#[declio(ctx_is = "constants::ENDIANESS")]
pub struct ProcedureRef {
    pub sum_name: u32,
    pub referent: SymbolOffset,
    pub module: u16,
    pub name: StrBuf,
}

#[derive(Debug, Encode, Decode, EncodedSize)]
#[declio(ctx_is = "constants::ENDIANESS")]
pub struct Procedure {
    #[declio(with = "codecs::optional_index")]
    pub parent: Option<SymbolOffset>,
    pub end: SymbolOffset,
    #[declio(with = "codecs::optional_index")]
    pub next: Option<SymbolOffset>,
    pub code_size: u32,
    pub dbg_start_offset: u32,
    pub dbg_end_offset: u32,
    pub function_type: TypeIndex,
    pub code_offset: DataRegionOffset,
    pub properties: ProcedureProperties,
    pub name: StrBuf,
}

#[derive(Debug, Clone, Copy, BitfieldSpecifier)]
#[bits = 8]
pub enum ThunkOrdinal {
    Standard,
    ThisAdjustor,
    Vcall,
    Pcode,
    UnknownLoad,
    TrampIncremental,
    BranchIsland,
}

impl_bitfield_specifier_codecs!(ThunkOrdinal);

#[derive(Debug, Clone, Copy, BitfieldSpecifier)]
#[bits = 16]
pub enum TrampolineType {
    TrampIncremental,
    BranchIsland,
}

impl_bitfield_specifier_codecs!(TrampolineType);

#[derive(Debug, Clone, Copy, BitfieldSpecifier)]
#[bits = 8]
pub enum FrameCookie {
    Copy,
    XorStackPointer,
    XorFramePointer,
    XorR13,
}

impl_bitfield_specifier_codecs!(FrameCookie);

#[derive(Debug, Clone, Copy, BitfieldSpecifier)]
#[bits = 8]
pub enum SourceLanguage {
    C = 0x00,
    Cpp = 0x01,
    Fortran = 0x02,
    Masm = 0x03,
    Pascal = 0x04,
    Basic = 0x05,
    Cobol = 0x06,
    Link = 0x07,
    Cvtres = 0x08,
    Cvtpgd = 0x09,
    CSharp = 0x0a,
    VisualBasic = 0x0b,
    ILAsm = 0x0c,
    Java = 0x0d,
    JScript = 0x0e,
    Msil = 0x0f,
    Hlsl = 0x10,
    Rust = 0x15,
    DLang = 0x44,
    Swift = 0x53,
}

impl_bitfield_specifier_codecs!(SourceLanguage);

#[bitfield(bits = 16)]
#[derive(Debug, Clone, Copy)]
pub struct LocalProperties {
    pub is_parameter: bool,
    pub is_address_taken: bool,
    pub is_compiler_generated: bool,
    pub is_aggregate: bool,
    pub is_aggregated: bool,
    pub is_aliased: bool,
    pub is_alias: bool,
    pub is_return_value: bool,
    pub is_optimized_out: bool,
    pub is_registered_global: bool,
    pub is_registered_static: bool,
    #[skip]
    unused: B5,
}

impl_bitfield_codecs!(LocalProperties);

#[bitfield(bits = 32)]
#[derive(Debug, Clone, Copy)]
pub struct PublicProperties {
    pub is_code: bool,
    pub is_function: bool,
    pub is_managed: bool,
    pub is_msil: bool,
    #[skip]
    unused: B28,
}

impl_bitfield_codecs!(PublicProperties);

#[bitfield(bits = 8)]
#[derive(Debug, Clone, Copy)]
pub struct ProcedureProperties {
    pub has_fp: bool,
    pub has_iret: bool,
    pub has_fret: bool,
    pub is_no_return: bool,
    pub is_unreachable: bool,
    pub has_custom_calling_conv: bool,
    pub is_no_inline: bool,
    pub has_optimized_debug_info: bool,
}

impl_bitfield_codecs!(ProcedureProperties);

#[bitfield(bits = 32)]
#[derive(Debug, Clone, Copy)]
pub struct CompileProperties {
    pub source_language: SourceLanguage,
    pub is_ec: bool,
    pub is_no_dbg_info: bool,
    pub is_ltcg: bool,
    pub is_no_data_align: bool,
    pub is_managed_present: bool,
    pub has_security_checks: bool,
    pub is_hot_patch: bool,
    pub is_cvtcil: bool,
    pub is_msil_module: bool,
    pub is_sdl: bool,
    pub is_pgo: bool,
    pub is_exp: bool,
    #[skip]
    unused: B12,
}

impl_bitfield_codecs!(CompileProperties);

#[bitfield(bits = 16)]
#[derive(Debug, Clone, Copy)]
pub struct ExportProperties {
    pub is_constant: bool,
    pub is_data: bool,
    pub is_private: bool,
    pub has_no_name: bool,
    pub has_explicit_ordinal: bool,
    pub is_forwarder: bool,
    #[skip]
    unused: B10,
}

impl_bitfield_codecs!(ExportProperties);

#[bitfield(bits = 16)]
#[derive(Debug, Clone, Copy)]
pub struct DefRangeRegisterRelProperties {
    pub is_subfield: bool,
    #[skip]
    unused: B3,
    pub offset_in_parent: B12,
}

impl_bitfield_codecs!(DefRangeRegisterRelProperties);

#[bitfield(bits = 32)]
#[derive(Debug, Clone, Copy)]
pub struct FrameProcedureProperties {
    pub has_alloca: bool,
    pub has_set_jmp: bool,
    pub has_long_jmp: bool,
    pub has_inline_assembly: bool,
    pub has_exception_handling: bool,
    pub marked_inline: bool,
    pub has_structured_exception_handling: bool,
    pub is_naked: bool,
    pub has_security_checks: bool,
    pub has_async_exception_handling: bool,
    pub has_no_stack_ordering_for_security_checks: bool,
    pub is_inlined: bool,
    pub has_strict_security_checks: bool,
    pub has_safe_buffers: bool,
    pub encoded_local_base_pointer: B2,
    pub encoded_param_base_pointer: B2,
    pub has_profile_guided_optimizations: bool,
    pub has_valid_profile_counts: bool,
    pub is_optimized_for_speed: bool,
    pub has_guard_cfg: bool,
    pub has_guard_cfw: bool,
    #[skip]
    unused: B9,
}

impl_bitfield_codecs!(FrameProcedureProperties);
