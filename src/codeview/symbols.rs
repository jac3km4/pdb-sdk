use std::fmt::Debug;

use declio::util::LittleEndian;
use declio::{Decode, Encode, EncodedSize};
use modular_bitfield::prelude::*;

use super::{DataRegionOffset, Register};
use crate::utils::StrBuf;
use crate::{
    IdIndex, Integer, SymbolOffset, TypeIndex, codecs, constants, impl_bitfield_codecs,
    impl_bitfield_specifier_codecs,
};

#[derive(Debug, Encode, Decode, EncodedSize)]
#[declio(ctx_is = "constants::ENDIANESS", id_type = "LittleEndian<u16>")]
/// CodeView Symbol Record, representing various symbols (e.g., procedures, locals, labels).
pub enum SymbolRecord {
    /// List of inlinees.
    #[declio(id = "constants::S_INLINEES.into()")]
    Inlinees,
    /// End of a scope (e.g., procedure, block).
    #[declio(id = "constants::S_END.into()")]
    ScopeEnd,
    /// Legacy `S_SKIP` placeholder.
    #[declio(id = "constants::S_SKIP.into()")]
    Skip,
    /// End of an inline site.
    #[declio(id = "constants::S_INLINESITE_END.into()")]
    InlineSiteEnd,
    /// End of a procedure.
    #[declio(id = "constants::S_PROC_ID_END.into()")]
    ProcEnd,
    /// A thunk symbol.
    #[declio(id = "constants::S_THUNK32.into()")]
    Thunk32 {
        /// Optional offset of the parent symbol.
        #[declio(with = "codecs::optional_index")]
        parent: Option<SymbolOffset>,
        /// Offset of the end of the scope.
        end: SymbolOffset,
        /// Optional offset of the next symbol.
        #[declio(with = "codecs::optional_index")]
        next: Option<SymbolOffset>,
        /// Offset within the data region.
        offset: DataRegionOffset,
        /// Size in bytes.
        size: u16,
        /// Thunk ordinal.
        ordinal: ThunkOrdinal,
        /// Name of the symbol.
        name: StrBuf,
    },
    /// A trampoline symbol.
    #[declio(id = "constants::S_TRAMPOLINE.into()")]
    Trampoline {
        /// Type of trampoline.
        trampoline_type: TrampolineType,
        /// Size in bytes.
        size: u16,
        /// Offset of the thunk.
        thunk_offset: u32,
        /// Offset of the target.
        target_offset: u32,
        /// Section of the thunk.
        thunk_section: u16,
        /// Section of the target.
        target_section: u16,
    },
    /// A section symbol.
    #[declio(id = "constants::S_SECTION.into()")]
    Section {
        /// Section number.
        section_number: u16,
        /// Alignment requirement.
        alignment: u8,
        /// Reserved padding byte.
        reserved: u8,
        /// Relative virtual address.
        rva: u32,
        /// Size in bytes.
        size: u32,
        /// Section characteristics.
        characteristics: u32,
        /// Name of the symbol.
        name: StrBuf,
    },
    /// A COFF group symbol.
    #[declio(id = "constants::S_COFFGROUP.into()")]
    CoffGroup {
        /// Size in bytes.
        size: u32,
        /// Section characteristics.
        characteristics: u32,
        /// Offset within the data region.
        offset: DataRegionOffset,
        /// Name of the symbol.
        name: StrBuf,
    },
    /// An exported symbol.
    #[declio(id = "constants::S_EXPORT.into()")]
    Export {
        /// Export ordinal.
        ordinal: u16,
        /// Export properties.
        properties: ExportProperties,
        /// Name of the symbol.
        name: StrBuf,
    },
    /// A local procedure.
    #[declio(id = "constants::S_LPROC32.into()")]
    Proc(Procedure),
    /// A global procedure.
    #[declio(id = "constants::S_GPROC32.into()")]
    GlobalProc(Procedure),
    /// A local procedure ID.
    #[declio(id = "constants::S_LPROC32_ID.into()")]
    ProcId(Procedure),
    /// A global procedure ID.
    #[declio(id = "constants::S_GPROC32_ID.into()")]
    GlobalProcId(Procedure),
    /// A DPC procedure.
    #[declio(id = "constants::S_LPROC32_DPC.into()")]
    DPCProc(Procedure),
    /// A DPC procedure ID.
    #[declio(id = "constants::S_LPROC32_DPC_ID.into()")]
    DPCProcId(Procedure),
    /// A variable stored in a register.
    #[declio(id = "constants::S_REGISTER.into()")]
    Register {
        /// Type index of the register contents.
        contained_type: TypeIndex,
        /// The register containing the value.
        register: Register,
        /// Name of the symbol.
        name: StrBuf,
    },
    /// A public symbol (often maps to a mangled name).
    #[declio(id = "constants::S_PUB32.into()")]
    Public32(Public),
    /// A reference to a global procedure.
    #[declio(id = "constants::S_PROCREF.into()")]
    ProcedureRef(ProcedureRef),
    /// A reference to a local procedure.
    #[declio(id = "constants::S_LPROCREF.into()")]
    LocalProcedureRef(ProcedureRef),
    /// An environment block.
    #[declio(id = "constants::S_ENVBLOCK.into()")]
    EnvBlock {
        /// Reserved byte.
        reserved: u8,
        /// List of fields.
        #[declio(with = "codecs::rem_list")]
        fields: Vec<StrBuf>,
    },
    /// An inline site.
    #[declio(id = "constants::S_INLINESITE.into()")]
    InlineSite {
        /// Optional offset of the parent symbol.
        #[declio(with = "codecs::optional_index")]
        parent: Option<SymbolOffset>,
        /// Offset of the end of the scope.
        end: SymbolOffset,
        /// ID index of the inlinee.
        inlinee: IdIndex,
        annotations: (), // TODO
    },
    /// V2 inline-site record.
    #[declio(id = "constants::S_INLINESITE2.into()")]
    InlineSite2 {
        /// Offset of the parent symbol.
        #[declio(with = "codecs::optional_index")]
        parent: Option<SymbolOffset>,
        /// Offset of the end of the scope.
        end: SymbolOffset,
        /// ID index of the inlinee function.
        inlinee: IdIndex,
        /// Number of times the inlinee was called.
        invocation_count: u32,
        annotations: (), // TODO: decode BinaryAnnotation stream
    },
    /// Profile-guided optimization stats.
    #[declio(id = "constants::S_POGODATA.into()")]
    PogoData {
        /// Number of times the function ran during profiling.
        invocation_count: u32,
        /// Dynamic instruction count (sum across all invocations).
        dynamic_instruction_count: i64,
        /// Number of static instructions in the function.
        static_instruction_count: u32,
        /// Number of instructions actually executed.
        live_instruction_count: u32,
    },
    /// Separated-code block.
    #[declio(id = "constants::S_SEPCODE.into()")]
    SepCode {
        /// Offset of the parent procedure's symbol.
        #[declio(with = "codecs::optional_index")]
        parent: Option<SymbolOffset>,
        /// Offset of the block-end sentinel.
        end: SymbolOffset,
        /// Length in bytes of the separated code.
        length: u32,
        /// Flags (`CV_SEPCODEFLAGS`).
        flags: u32,
        /// Section-relative offset of this block.
        offset: u32,
        /// Section-relative offset of the enclosing scope.
        parent_offset: u32,
        /// Section index of this block.
        section: u16,
        /// Section index of the enclosing scope.
        parent_section: u16,
    },
    /// A local variable or parameter.
    #[declio(id = "constants::S_LOCAL.into()")]
    Local {
        /// Type of the local variable.
        #[declio(with = "codecs::optional_index")]
        local_type: Option<TypeIndex>,
        /// Properties of the local variable.
        properties: LocalProperties,
        /// Name of the symbol.
        name: StrBuf,
    },
    /// A definition range for a local variable.
    #[declio(id = "constants::S_DEFRANGE.into()")]
    DefRange {
        /// Program counter/address.
        program: u32,
        /// Range where the variable is valid.
        range: LocalVariableRange,
        /// Gaps in the variable's validity.
        #[declio(with = "codecs::padded_rem_list")]
        gaps: Vec<LocalVariableGap>,
    },
    /// A definition range for a subfield.
    #[declio(id = "constants::S_DEFRANGE_SUBFIELD.into()")]
    DefRangeSubfield {
        /// Program counter/address.
        program: u32,
        /// Offset within the parent structure.
        offset_in_parent: u16,
        /// Range where the variable is valid.
        range: LocalVariableRange,
        /// Gaps in the variable's validity.
        #[declio(with = "codecs::padded_rem_list")]
        gaps: Vec<LocalVariableGap>,
    },
    /// A definition range using a register.
    #[declio(id = "constants::S_DEFRANGE_REGISTER.into()")]
    DefRangeRegister {
        /// The register containing the value.
        register: Register,
        /// Indicates if the variable may lack a name.
        may_have_no_name: u16,
        /// Range where the variable is valid.
        range: LocalVariableRange,
        /// Gaps in the variable's validity.
        #[declio(with = "codecs::padded_rem_list")]
        gaps: Vec<LocalVariableGap>,
    },
    /// A frame-pointer-relative definition range.
    #[declio(id = "constants::S_DEFRANGE_FRAMEPOINTER_REL.into()")]
    DefRangeFramePointerRel {
        /// Offset relative to the frame pointer.
        offset: i32,
        /// Range where the variable is valid.
        range: LocalVariableRange,
        /// Gaps in the variable's validity.
        #[declio(with = "codecs::padded_rem_list")]
        gaps: Vec<LocalVariableGap>,
    },
    /// A register definition range for a subfield.
    #[declio(id = "constants::S_DEFRANGE_SUBFIELD_REGISTER.into()")]
    DefRangeSubfieldRegister {
        /// The register containing the value.
        register: Register,
        /// Indicates if the variable may lack a name.
        may_have_no_name: u16,
        /// Offset within the parent structure.
        offset_in_parent: u32,
        /// Range where the variable is valid.
        range: LocalVariableRange,
        /// Gaps in the variable's validity.
        #[declio(with = "codecs::padded_rem_list")]
        gaps: Vec<LocalVariableGap>,
    },
    /// A frame-pointer-relative definition range spanning the full scope.
    #[declio(id = "constants::S_DEFRANGE_FRAMEPOINTER_REL_FULL_SCOPE.into()")]
    DefRangeFramePointerRelFullScope {
        /// Offset relative to the frame pointer.
        offset: i32,
    },
    /// A register-relative definition range.
    #[declio(id = "constants::S_DEFRANGE_REGISTER_REL.into()")]
    DefRangeRegisterRel {
        /// The register containing the value.
        register: Register,
        /// Properties of a register-relative definition range.
        properties: DefRangeRegisterRelProperties,
        /// Base pointer offset.
        base_pointer_offset: i32,
        /// Range where the variable is valid.
        range: LocalVariableRange,
        /// Gaps in the variable's validity.
        #[declio(with = "codecs::padded_rem_list")]
        gaps: Vec<LocalVariableGap>,
    },
    /// Indirected register-relative definition range.
    #[declio(id = "constants::S_DEFRANGE_REGISTER_REL_INDIR.into()")]
    DefRangeRegisterRelIndirect {
        /// The register containing the indirect pointer.
        register: Register,
        /// Properties of the definition range.
        properties: DefRangeRegisterRelProperties,
        /// Base pointer offset.
        base_pointer_offset: i32,
        /// Range where the variable is valid.
        range: LocalVariableRange,
        /// Gaps in the variable's validity.
        #[declio(with = "codecs::padded_rem_list")]
        gaps: Vec<LocalVariableGap>,
    },
    /// A block scope.
    #[declio(id = "constants::S_BLOCK32.into()")]
    Block {
        /// Offset of the parent symbol.
        parent: SymbolOffset,
        /// Offset of the end of the scope.
        end: SymbolOffset,
        /// Size of the code.
        code_size: u32,
        /// Offset of the code region.
        code_offset: DataRegionOffset,
        /// Name of the symbol.
        name: StrBuf,
    },
    /// A label symbol.
    #[declio(id = "constants::S_LABEL32.into()")]
    Label {
        /// Offset of the code region.
        code_offset: DataRegionOffset,
        /// Procedure properties.
        properties: ProcedureProperties,
        /// Name of the symbol.
        name: StrBuf,
    },
    /// The name of an object file.
    #[declio(id = "constants::S_OBJNAME.into()")]
    ObjectName {
        /// Signature of the object file.
        signature: u32,
        /// Name of the object file.
        name: StrBuf,
    },
    /// Compiler version information (older format).
    #[declio(id = "constants::S_COMPILE2.into()")]
    Compile2 {
        /// Compiler properties.
        properties: CompileProperties,
        /// Target machine type.
        machine: u16,
        /// Frontend version.
        frontend_version: Version,
        /// Backend version.
        backend_version: Version,
        /// Version string.
        version: StrBuf,
        /// Extra compiler settings.
        #[declio(with = "codecs::rem_list")]
        extra_settings: Vec<StrBuf>,
    },
    /// Compiler version information (newer format).
    #[declio(id = "constants::S_COMPILE3.into()")]
    Compile3 {
        /// Compiler properties.
        properties: CompileProperties,
        /// Target machine type.
        machine: u16,
        /// Frontend version.
        frontend_version: Version,
        /// Frontend QFE version.
        frontend_qfe: u16,
        /// Backend version.
        backend_version: Version,
        /// Backend QFE version.
        backend_qfe: u16,
        /// Version string.
        version: StrBuf,
    },
    /// Extra frame and procedure information.
    #[declio(id = "constants::S_FRAMEPROC.into()")]
    FrameProcedure {
        /// Total bytes in the frame.
        total_frame_bytes: u32,
        /// Bytes of padding in the frame.
        padding_frame_bytes: u32,
        /// Offset to the padding.
        offset_to_padding: u32,
        /// Bytes of callee-saved registers.
        bytes_of_callee_saved_registers: u32,
        /// Offset of the exception handler.
        offset_of_exception_handler: u32,
        /// Section ID of the exception handler.
        section_id_of_exception_handler: u16,
        /// Frame procedure properties.
        properties: FrameProcedureProperties,
    },
    /// Information about a call site.
    #[declio(id = "constants::S_CALLSITEINFO.into()")]
    CallSiteInfo {
        /// Offset of the code region.
        code_offset: DataRegionOffset,
        /// Reserved padding word.
        reserved: u16,
        /// Type of the call.
        #[declio(with = "codecs::optional_index")]
        call_type: Option<TypeIndex>,
    },
    /// A file-static variable.
    #[declio(id = "constants::S_FILESTATIC.into()")]
    FileStatic {
        /// Type index of the file static variable.
        index: TypeIndex,
        /// Offset to the module filename.
        mod_filename_offset: u32,
        /// Properties of the local variable.
        properties: LocalProperties,
        /// Name of the symbol.
        name: StrBuf,
    },
    /// Information about a heap allocation site.
    #[declio(id = "constants::S_HEAPALLOCSITE.into()")]
    HeapAllocationSite {
        /// Offset of the code region.
        code_offset: DataRegionOffset,
        /// Size of the call instruction.
        call_instruction_size: u16,
        /// Type of the call.
        call_type: TypeIndex,
    },
    /// A frame cookie.
    #[declio(id = "constants::S_FRAMECOOKIE.into()")]
    FrameCookie {
        /// Offset of the code.
        code_offset: u32,
        /// The register containing the value.
        register: Register,
        /// Kind of frame cookie.
        kind: FrameCookie,
        /// Cookie flags.
        flags: u8,
    },
    /// Lists the callers of a procedure.
    #[declio(id = "constants::S_CALLEES.into()")]
    Caller {
        /// List of type indices.
        #[declio(with = "codecs::padded_rem_list")]
        types: Vec<TypeIndex>,
    },
    /// Lists the callees of a procedure.
    #[declio(id = "constants::S_CALLERS.into()")]
    Callee,
    /// A user-defined type (UDT) symbol.
    #[declio(id = "constants::S_UDT.into()")]
    Udt(UserDefinedType),
    /// A COBOL user-defined type symbol.
    #[declio(id = "constants::S_COBOLUDT.into()")]
    CobolUdt(UserDefinedType),
    /// Build information symbol.
    #[declio(id = "constants::S_BUILDINFO.into()")]
    BuildInfo {
        /// ID index of the build record.
        build_record: IdIndex,
    },
    /// A variable located relative to the base pointer.
    #[declio(id = "constants::S_BPREL32.into()")]
    BasePointerRelative {
        /// Offset relative to the frame pointer.
        offset: i32,
        /// Type of the value.
        value_type: TypeIndex,
        /// Name of the symbol.
        name: StrBuf,
    },
    /// A variable located relative to a register.
    #[declio(id = "constants::S_REGREL32.into()")]
    RegisterRelative {
        /// Offset relative to the register.
        offset: u32,
        /// Type of the value.
        #[declio(with = "codecs::optional_index")]
        value_type: Option<TypeIndex>,
        /// The register containing the value.
        register: Register,
        /// Name of the symbol.
        name: StrBuf,
    },
    /// A constant symbol.
    #[declio(id = "constants::S_CONSTANT.into()")]
    Constant(Constant),
    /// A managed constant symbol.
    #[declio(id = "constants::S_MANCONSTANT.into()")]
    ManagedConstant(Constant),
    /// Local data symbol.
    #[declio(id = "constants::S_LDATA32.into()")]
    Data(Data),
    /// Global data symbol.
    #[declio(id = "constants::S_GDATA32.into()")]
    GlobalData(Data),
    /// Managed local data symbol.
    #[declio(id = "constants::S_LMANDATA.into()")]
    ManagedLocalData(Data),
    /// Managed global data symbol.
    #[declio(id = "constants::S_GMANDATA.into()")]
    ManagedGlobalData(Data),
    /// Thread local storage symbol.
    #[declio(id = "constants::S_LTHREAD32.into()")]
    ThreadLocalStorage(ThreadLocalStorage),
    /// Global thread local storage symbol.
    #[declio(id = "constants::S_GTHREAD32.into()")]
    GlobalThreadLocalStorage(ThreadLocalStorage),
    /// A using namespace symbol.
    #[declio(id = "constants::S_UNAMESPACE.into()")]
    UsingNamespace {
        /// Name of the namespace.
        name: StrBuf,
    },
    /// An annotation symbol.
    #[declio(id = "constants::S_ANNOTATION.into()")]
    Annotation {
        /// Offset of the code region.
        code_offset: DataRegionOffset,
        /// List of strings.
        #[declio(with = "codecs::rem_list")]
        strings: Vec<StrBuf>,
    },
    /// Reference to an `S_ANNOTATION` symbol.
    #[declio(id = "constants::S_ANNOTATIONREF.into()")]
    AnnotationRef(ProcedureRef),
    /// v2 mini-PDB reference.
    #[declio(id = "constants::S_REF_MINIPDB2.into()")]
    RefMiniPdb2 {
        /// Section index or type
        index_or_isect: u32,
        /// 1-based index into the module list.
        imod: u16,
        /// Packed flag bits.
        flags: u16,
    },
    /// `S_REGREL32_INDIR`: indirected variant of `S_REGREL32`.
    #[declio(id = "constants::S_REGREL32_INDIR.into()")]
    RegisterRelativeIndirect {
        /// Offset relative to the register.
        offset: u32,
        /// Type of the value.
        #[declio(with = "codecs::optional_index")]
        value_type: Option<TypeIndex>,
        /// Indirection flags.
        flags: u32,
        /// The register containing the indirect pointer.
        register: Register,
        /// Name of the symbol.
        name: StrBuf,
    },
    /// ARM jump-table descriptor.
    #[declio(id = "constants::S_ARMSWITCHTABLE.into()")]
    ArmSwitchTable(ArmSwitchTable),
    /// Association between a local and another value.
    #[declio(id = "constants::S_ASSOCIATION.into()")]
    Association {
        /// Association flags.
        flags: u16,
        /// Associated data (interpretation is producer-specific).
        data: u32,
    },
    /// Constant value live at function entry.
    #[declio(id = "constants::S_DEFRANGE_CONSTVAL_ON_ENTRY.into()")]
    DefRangeConstValOnEntry {
        /// The constant value.
        value: u32,
    },
    /// Global symbol live at function entry.
    #[declio(id = "constants::S_DEFRANGE_GLOBALSYM_ON_ENTRY.into()")]
    DefRangeGlobalSymOnEntry {
        /// Type index of the global.
        type_index: u32,
        /// Local properties / flags.
        flags: u16,
    },
}

impl SymbolRecord {
    /// Gets the name of the symbol if it has one.
    pub fn name(&self) -> Option<&str> {
        match self {
            SymbolRecord::Thunk32 { name, .. }
            | SymbolRecord::Section { name, .. }
            | SymbolRecord::CoffGroup { name, .. }
            | SymbolRecord::Export { name, .. }
            | SymbolRecord::Register { name, .. }
            | SymbolRecord::Local { name, .. }
            | SymbolRecord::Block { name, .. }
            | SymbolRecord::Label { name, .. }
            | SymbolRecord::ObjectName { name, .. }
            | SymbolRecord::FileStatic { name, .. }
            | SymbolRecord::BasePointerRelative { name, .. }
            | SymbolRecord::RegisterRelative { name, .. }
            | SymbolRecord::UsingNamespace { name } => Some(name.as_ref()),
            SymbolRecord::Proc(proc)
            | SymbolRecord::GlobalProc(proc)
            | SymbolRecord::ProcId(proc)
            | SymbolRecord::GlobalProcId(proc)
            | SymbolRecord::DPCProc(proc)
            | SymbolRecord::DPCProcId(proc) => Some(proc.name.as_ref()),
            SymbolRecord::Public32(public) => Some(public.name.as_ref()),
            SymbolRecord::ProcedureRef(proc)
            | SymbolRecord::LocalProcedureRef(proc)
            | SymbolRecord::AnnotationRef(proc) => Some(proc.name.as_ref()),
            SymbolRecord::Udt(udt) | SymbolRecord::CobolUdt(udt) => Some(udt.name.as_ref()),
            SymbolRecord::Constant(constant) | SymbolRecord::ManagedConstant(constant) => {
                Some(constant.name.as_ref())
            }
            SymbolRecord::Data(data)
            | SymbolRecord::GlobalData(data)
            | SymbolRecord::ManagedLocalData(data)
            | SymbolRecord::ManagedGlobalData(data) => Some(data.name.as_ref()),
            SymbolRecord::ThreadLocalStorage(tls) | SymbolRecord::GlobalThreadLocalStorage(tls) => {
                Some(tls.name.as_ref())
            }
            _ => None,
        }
    }
}

#[derive(Debug, Encode, Decode, EncodedSize)]
#[declio(ctx_is = "constants::ENDIANESS")]
/// Range where a local variable is valid.
pub struct LocalVariableRange {
    /// Start offset.
    pub offset_start: u32,
    /// Start section index.
    pub i_sect_start: u16,
    /// Length of the range.
    pub range: u16,
}

#[derive(Debug, Encode, Decode, EncodedSize)]
#[declio(ctx_is = "constants::ENDIANESS")]
/// Gap in a local variable's valid range.
pub struct LocalVariableGap {
    /// Start offset of the gap.
    pub gap_start_offset: u16,
    /// Length of the gap.
    pub range: u16,
}

#[derive(Debug, Encode, Decode, EncodedSize)]
#[declio(ctx_is = "constants::ENDIANESS")]
/// Version information (major, minor, build).
pub struct Version {
    /// Major version number.
    pub major: u16,
    /// Minor version number.
    pub minor: u16,
    /// Build version number.
    pub build: u16,
}

#[derive(Debug, Encode, Decode, EncodedSize)]
#[declio(ctx_is = "constants::ENDIANESS")]
/// Record describing a public symbol.
pub struct Public {
    /// Public properties.
    pub properties: PublicProperties,
    /// Offset in the data region.
    pub offset: DataRegionOffset,
    /// Name of the public symbol.
    pub name: StrBuf,
}

#[derive(Debug, Encode, Decode, EncodedSize)]
#[declio(ctx_is = "constants::ENDIANESS")]
/// Record describing a user-defined type (UDT).
pub struct UserDefinedType {
    /// Type index of the user-defined type.
    pub udt_type: TypeIndex,
    /// Name of the user-defined type.
    pub name: StrBuf,
}

#[derive(Debug, Encode, Decode, EncodedSize)]
#[declio(ctx_is = "constants::ENDIANESS")]
/// Record describing a constant value.
pub struct Constant {
    /// Type index of the constant.
    pub constant_type: TypeIndex,
    /// Value of the constant.
    pub value: Integer,
    /// Name of the constant.
    pub name: StrBuf,
}

#[derive(Debug, Encode, Decode, EncodedSize)]
#[declio(ctx_is = "constants::ENDIANESS")]
/// Record describing a data symbol.
pub struct Data {
    /// Type index of the data.
    #[declio(with = "codecs::optional_index")]
    pub data_type: Option<TypeIndex>,
    /// Offset in the data region.
    pub offset: DataRegionOffset,
    /// Name of the data symbol.
    pub name: StrBuf,
}

#[derive(Debug, Encode, Decode, EncodedSize)]
#[declio(ctx_is = "constants::ENDIANESS")]
/// Record describing thread-local storage.
pub struct ThreadLocalStorage {
    /// Type index of the thread local storage data.
    pub data_type: TypeIndex,
    /// Offset in the data region.
    pub offset: DataRegionOffset,
    /// Name of the TLS symbol.
    pub name: StrBuf,
}

#[derive(Debug, Encode, Decode, EncodedSize)]
#[declio(ctx_is = "constants::ENDIANESS")]
/// `S_ARMSWITCHTABLE` body.
pub struct ArmSwitchTable {
    /// Base offset within the section.
    pub offset_base: u32,
    /// Segment index for `offset_base`.
    pub base_segment: u16,
    /// Type discriminator for the switch table entries.
    pub switch_type: u16,
    /// Offset of the dispatch branch.
    pub branch_offset: u32,
    /// Offset of the table itself.
    pub table_offset: u32,
    /// Segment of the dispatch branch.
    pub branch_segment: u16,
    /// Segment of the table.
    pub table_segment: u16,
    /// Number of entries in the table.
    pub entries_count: u32,
}

#[derive(Debug, Encode, Decode, EncodedSize)]
#[declio(ctx_is = "constants::ENDIANESS")]
/// Reference to a procedure in another module.
pub struct ProcedureRef {
    /// Sum name for the procedure ref.
    pub sum_name: u32,
    /// Offset of the referent symbol.
    pub referent: SymbolOffset,
    /// Module number.
    pub module: u16,
    /// Name of the procedure.
    pub name: StrBuf,
}

#[derive(Debug, Encode, Decode, EncodedSize)]
#[declio(ctx_is = "constants::ENDIANESS")]
/// Record describing a procedure.
pub struct Procedure {
    /// Optional offset of the parent symbol.
    #[declio(with = "codecs::optional_index")]
    pub parent: Option<SymbolOffset>,
    /// Offset of the end of the scope.
    pub end: SymbolOffset,
    /// Optional offset of the next symbol.
    #[declio(with = "codecs::optional_index")]
    pub next: Option<SymbolOffset>,
    /// Size of the code.
    pub code_size: u32,
    /// Debug start offset.
    pub dbg_start_offset: u32,
    /// Debug end offset.
    pub dbg_end_offset: u32,
    /// Type index of the function.
    #[declio(with = "codecs::optional_index")]
    pub function_type: Option<TypeIndex>,
    /// Offset of the code region.
    pub code_offset: DataRegionOffset,
    /// Procedure properties.
    pub properties: ProcedureProperties,
    /// Name of the procedure.
    pub name: StrBuf,
}

#[derive(Debug, Clone, Copy, Specifier)]
#[bits = 8]
/// Types of thunks.
pub enum ThunkOrdinal {
    /// Standard thunk.
    Standard,
    /// This adjustor thunk.
    ThisAdjustor,
    /// Virtual call thunk.
    Vcall,
    /// P-code thunk.
    Pcode,
    /// Unknown load thunk.
    UnknownLoad,
    /// Incremental trampoline thunk.
    TrampIncremental,
    /// Branch island thunk.
    BranchIsland,
}

impl_bitfield_specifier_codecs!(ThunkOrdinal);

#[derive(Debug, Clone, Copy, Specifier)]
#[bits = 16]
/// Types of trampolines.
pub enum TrampolineType {
    /// Incremental trampoline.
    TrampIncremental,
    /// Branch island.
    BranchIsland,
}

impl_bitfield_specifier_codecs!(TrampolineType);

#[derive(Debug, Clone, Copy, Specifier)]
#[bits = 8]
/// Types of frame cookies.
pub enum FrameCookie {
    /// Copy cookie.
    Copy,
    /// XOR stack pointer cookie.
    XorStackPointer,
    /// XOR frame pointer cookie.
    XorFramePointer,
    /// XOR R13 cookie.
    XorR13,
}

impl_bitfield_specifier_codecs!(FrameCookie);

#[derive(Debug, Clone, Copy, Specifier)]
#[bits = 8]
/// Source language of the module.
pub enum SourceLanguage {
    /// C.
    C = 0x00,
    /// C++.
    Cpp = 0x01,
    /// Fortran.
    Fortran = 0x02,
    /// MASM.
    Masm = 0x03,
    /// Pascal.
    Pascal = 0x04,
    /// Basic.
    Basic = 0x05,
    /// COBOL.
    Cobol = 0x06,
    /// Linker-generated.
    Link = 0x07,
    /// CVTRES.
    Cvtres = 0x08,
    /// CVTPGD.
    Cvtpgd = 0x09,
    /// C#.
    CSharp = 0x0a,
    /// Visual Basic.
    VisualBasic = 0x0b,
    /// IL assembler.
    ILAsm = 0x0c,
    /// Java.
    Java = 0x0d,
    /// JScript.
    JScript = 0x0e,
    /// MSIL.
    Msil = 0x0f,
    /// HLSL.
    Hlsl = 0x10,
    /// Rust.
    Rust = 0x15,
    /// D.
    DLang = 0x44,
    /// Swift.
    Swift = 0x53,
}

impl_bitfield_specifier_codecs!(SourceLanguage);

#[bitfield(bits = 16)]
#[derive(Debug, Clone, Copy)]
/// Properties of a local variable.
pub struct LocalProperties {
    /// Is a parameter.
    pub is_parameter: bool,
    /// Has its address taken.
    pub is_address_taken: bool,
    /// Is compiler-generated.
    pub is_compiler_generated: bool,
    /// Is an aggregate.
    pub is_aggregate: bool,
    /// Is aggregated.
    pub is_aggregated: bool,
    /// Is aliased.
    pub is_aliased: bool,
    /// Is an alias.
    pub is_alias: bool,
    /// Is a return value.
    pub is_return_value: bool,
    /// Has been optimized out.
    pub is_optimized_out: bool,
    /// Is a registered global.
    pub is_registered_global: bool,
    /// Is a registered static.
    pub is_registered_static: bool,
    #[skip]
    unused: B5,
}

impl_bitfield_codecs!(LocalProperties);

#[bitfield(bits = 32)]
#[derive(Debug, Clone, Copy)]
/// Properties of a public symbol.
pub struct PublicProperties {
    /// Is code.
    pub is_code: bool,
    /// Is a function.
    pub is_function: bool,
    /// Is managed code.
    pub is_managed: bool,
    /// Is MSIL.
    pub is_msil: bool,
    #[skip]
    unused: B28,
}

impl_bitfield_codecs!(PublicProperties);

#[bitfield(bits = 8)]
#[derive(Debug, Clone, Copy)]
/// Properties of a procedure.
pub struct ProcedureProperties {
    /// Has a frame pointer.
    pub has_fp: bool,
    /// Has an interrupt return.
    pub has_iret: bool,
    /// Has a far return.
    pub has_fret: bool,
    /// Does not return.
    pub is_no_return: bool,
    /// Is unreachable.
    pub is_unreachable: bool,
    /// Has a custom calling convention.
    pub has_custom_calling_conv: bool,
    /// Is not inlinable.
    pub is_no_inline: bool,
    /// Has optimized debug information.
    pub has_optimized_debug_info: bool,
}

impl_bitfield_codecs!(ProcedureProperties);

#[bitfield(bits = 32)]
#[derive(Debug, Clone, Copy)]
/// Properties of the compilation.
pub struct CompileProperties {
    /// Source language.
    pub source_language: SourceLanguage,
    /// Is edit-and-continue.
    pub is_ec: bool,
    /// Has no debug information.
    pub is_no_dbg_info: bool,
    /// Is link-time code generation.
    pub is_ltcg: bool,
    /// Has no data alignment.
    pub is_no_data_align: bool,
    /// Has managed code present.
    pub is_managed_present: bool,
    /// Has security checks.
    pub has_security_checks: bool,
    /// Is hot patchable.
    pub is_hot_patch: bool,
    /// Is CVTCIL.
    pub is_cvtcil: bool,
    /// Is an MSIL module.
    pub is_msil_module: bool,
    /// Is compiled with SDL.
    pub is_sdl: bool,
    /// Is compiled with PGO.
    pub is_pgo: bool,
    /// Is an EXP module.
    pub is_exp: bool,
    #[skip]
    unused: B12,
}

impl_bitfield_codecs!(CompileProperties);

#[bitfield(bits = 16)]
#[derive(Debug, Clone, Copy)]
/// Properties of an exported symbol.
pub struct ExportProperties {
    /// Is a constant.
    pub is_constant: bool,
    /// Is data.
    pub is_data: bool,
    /// Is private.
    pub is_private: bool,
    /// Has no name.
    pub has_no_name: bool,
    /// Has an explicit ordinal.
    pub has_explicit_ordinal: bool,
    /// Is a forwarder.
    pub is_forwarder: bool,
    #[skip]
    unused: B10,
}

impl_bitfield_codecs!(ExportProperties);

#[bitfield(bits = 16)]
#[derive(Debug, Clone, Copy)]
/// Properties of a register-relative definition range.
pub struct DefRangeRegisterRelProperties {
    /// Is a subfield.
    pub is_subfield: bool,
    #[skip]
    unused: B3,
    /// Offset in the parent structure.
    pub offset_in_parent: B12,
}

impl_bitfield_codecs!(DefRangeRegisterRelProperties);

#[bitfield(bits = 32)]
#[derive(Debug, Clone, Copy)]
/// Properties of a frame procedure.
pub struct FrameProcedureProperties {
    /// Has alloca calls.
    pub has_alloca: bool,
    /// Has setjmp calls.
    pub has_set_jmp: bool,
    /// Has longjmp calls.
    pub has_long_jmp: bool,
    /// Has inline assembly.
    pub has_inline_assembly: bool,
    /// Has exception handling.
    pub has_exception_handling: bool,
    /// Is marked inline.
    pub marked_inline: bool,
    /// Has structured exception handling.
    pub has_structured_exception_handling: bool,
    /// Is a naked function.
    pub is_naked: bool,
    /// Has security checks.
    pub has_security_checks: bool,
    /// Has async exception handling.
    pub has_async_exception_handling: bool,
    /// Has no stack ordering for security checks.
    pub has_no_stack_ordering_for_security_checks: bool,
    /// Is inlined.
    pub is_inlined: bool,
    /// Has strict security checks.
    pub has_strict_security_checks: bool,
    /// Has safe buffers.
    pub has_safe_buffers: bool,
    /// Encoded local base pointer.
    pub encoded_local_base_pointer: B2,
    /// Encoded parameter base pointer.
    pub encoded_param_base_pointer: B2,
    /// Has profile-guided optimizations.
    pub has_profile_guided_optimizations: bool,
    /// Has valid profile counts.
    pub has_valid_profile_counts: bool,
    /// Is optimized for speed.
    pub is_optimized_for_speed: bool,
    /// Has guard CFG.
    pub has_guard_cfg: bool,
    /// Has guard CFW.
    pub has_guard_cfw: bool,
    #[skip]
    unused: B9,
}

impl_bitfield_codecs!(FrameProcedureProperties);
