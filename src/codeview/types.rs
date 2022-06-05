use std::fmt::Debug;

use declio::ctx::Len;
use declio::util::LittleEndian;
use declio::{Decode, Encode, EncodedSize};
use modular_bitfield::prelude::*;

use crate::utils::StrBuf;
use crate::{
    codecs, constants, div_ceil, impl_bitfield_codecs, impl_bitfield_specifier_codecs, Guid, Integer, TypeIndex
};

#[derive(Debug, Encode, Decode, EncodedSize)]
#[declio(ctx_is = "constants::ENDIANESS", id_type = "LittleEndian<u16>")]
pub enum TypeRecord {
    #[declio(id = "constants::LF_POINTER.into()")]
    Pointer {
        referent: TypeIndex,
        properties: PointerProperties,
        #[declio(skip_if = "!properties.mode().is_member_pointer()")]
        containing_class: Option<TypeIndex>,
    },
    #[declio(id = "constants::LF_MODIFIER.into()")]
    Modifier {
        modified_type: TypeIndex,
        properties: ModifierProperties,
    },
    #[declio(id = "constants::LF_PROCEDURE.into()")]
    Procedure {
        #[declio(with = "codecs::optional_index")]
        return_type: Option<TypeIndex>,
        calling_conv: CallingConvention,
        properties: FunctionProperties,
        arg_count: u16,
        arg_list: TypeIndex,
    },
    #[declio(id = "constants::LF_MFUNCTION.into()")]
    MemberFunction {
        #[declio(with = "codecs::optional_index")]
        return_type: Option<TypeIndex>,
        #[declio(with = "codecs::optional_index")]
        class_type: Option<TypeIndex>,
        #[declio(with = "codecs::optional_index")]
        this_type: Option<TypeIndex>,
        calling_conv: CallingConvention,
        properties: FunctionProperties,
        arg_count: u16,
        arg_list: TypeIndex,
        this_adjustment: i32,
    },
    #[declio(id = "constants::LF_LABEL.into()")]
    Label(LabelType),
    #[declio(id = "constants::LF_ARGLIST.into()")]
    ArgList {
        count: u32,
        #[declio(ctx = "(Len(*count as usize), constants::ENDIANESS)")]
        arg_list: Vec<u32>,
    },
    #[declio(id = "constants::LF_FIELDLIST.into()")]
    FieldList {
        #[declio(with = "codecs::padded_rem_list")]
        fields: Vec<TypeRecord>,
    },
    #[declio(id = "constants::LF_ARRAY.into()")]
    Array {
        element_type: TypeIndex,
        index_type: TypeIndex,
        #[declio(with = "codecs::padded_rem_list")]
        dimensions: Vec<Integer>,
    },
    #[declio(id = "constants::LF_CLASS.into()")]
    Class(StructRecord),
    #[declio(id = "constants::LF_STRUCTURE.into()")]
    Struct(StructRecord),
    #[declio(id = "constants::LF_INTERFACE.into()")]
    Interface(StructRecord),
    #[declio(id = "constants::LF_UNION.into()")]
    Union(UnionRecord),
    #[declio(id = "constants::LF_ENUM.into()")]
    Enum(EnumRecord),
    #[declio(id = "constants::LF_TYPESERVER2.into()")]
    TypeServer2 { guid: Guid, age: u32, name: StrBuf },
    #[declio(id = "constants::LF_VFTABLE.into()")]
    VFTable {
        complete_class: TypeIndex,
        overriden_vftable: TypeIndex,
        vfptr_offset: u32,
        name_count: u32,
        // todo method_names
    },
    #[declio(id = "constants::LF_VTSHAPE.into()")]
    VfTableShape(VftShape),
    #[declio(id = "constants::LF_BITFIELD.into()")]
    BitField {
        field_type: TypeIndex,
        bit_size: u8,
        bit_offset: u8,
    },
    #[declio(id = "constants::LF_BCLASS.into()")]
    BaseClass(BaseClasRecord),
    #[declio(id = "constants::LF_BINTERFACE.into()")]
    BaseInterface(BaseClasRecord),
    #[declio(id = "constants::LF_VBCLASS.into()")]
    VirtualBaseClass(VirtualBaseClasRecord),
    #[declio(id = "constants::LF_IVBCLASS.into()")]
    IndirectVirtualBaseClass(VirtualBaseClasRecord),
    #[declio(id = "constants::LF_VFUNCTAB.into()")]
    VFPtr {
        reserved: [u8; 2],
        table_type: TypeIndex,
    },
    #[declio(id = "constants::LF_STMEMBER.into()")]
    StaticDataMember {
        properties: MemberProperties,
        field_type: TypeIndex,
        name: StrBuf,
    },
    #[declio(id = "constants::LF_METHOD.into()")]
    OverloadedMethod {
        count: u16,
        method_list: TypeIndex,
        name: StrBuf,
    },
    #[declio(id = "constants::LF_MEMBER.into()")]
    DataMember {
        properties: MemberProperties,
        #[declio(with = "codecs::optional_index")]
        field_type: Option<TypeIndex>,
        offset: Integer,
        name: StrBuf,
    },
    #[declio(id = "constants::LF_NESTTYPE.into()")]
    NestedType {
        properties: MemberProperties,
        nested_type: TypeIndex,
        name: StrBuf,
    },
    #[declio(id = "constants::LF_ONEMETHOD.into()")]
    OneMethod {
        properties: MemberProperties,
        method_type: TypeIndex,
        #[declio(skip_if = "!properties.method_kind().is_introducing()")]
        vtable_offset: Option<u32>,
        name: StrBuf,
    },
    #[declio(id = "constants::LF_ENUMERATE.into()")]
    Enumerator {
        properties: MemberProperties,
        value: Integer,
        name: StrBuf,
    },
    #[declio(id = "constants::LF_INDEX.into()")]
    ListContinuation(TypeIndex),
    #[declio(id = "constants::LF_METHODLIST.into()")]
    MethodList {
        #[declio(with = "codecs::padded_rem_list")]
        methods: Vec<MethodListEntry>,
    },
}

#[derive(Debug, Encode, Decode, EncodedSize)]
#[declio(ctx_is = "constants::ENDIANESS", id_type = "LittleEndian<u16>")]
pub enum IdRecord {
    #[declio(id = "constants::LF_FUNC_ID.into()")]
    FuncId {
        #[declio(with = "codecs::optional_index")]
        parent_scope: Option<TypeIndex>,
        function_type: TypeIndex,
        name: StrBuf,
    },
    #[declio(id = "constants::LF_MFUNC_ID.into()")]
    MemberFuncId {
        class_type: TypeIndex,
        function_type: TypeIndex,
        name: StrBuf,
    },
    #[declio(id = "constants::LF_BUILDINFO.into()")]
    BuildInfo {
        count: u16,
        #[declio(ctx = "(Len(*count as usize), constants::ENDIANESS)")]
        arguments: Vec<u32>,
    },
    #[declio(id = "constants::LF_SUBSTR_LIST.into()")]
    StringList {
        count: u32,
        #[declio(ctx = "(Len(*count as usize), constants::ENDIANESS)")]
        strings: Vec<TypeIndex>,
    },
    #[declio(id = "constants::LF_STRING_ID.into()")]
    StringId {
        #[declio(with = "codecs::optional_index")]
        id: Option<TypeIndex>,
        string: StrBuf,
    },
    #[declio(id = "constants::LF_UDT_SRC_LINE.into()")]
    UdtSourceLine {
        udt: TypeIndex,
        source_file: TypeIndex,
        line_number: u32,
    },
    #[declio(id = "constants::LF_UDT_MOD_SRC_LINE.into()")]
    UdtModSourceLine {
        udt: TypeIndex,
        source_file: TypeIndex,
        line_number: u32,
        module: u16,
    },
}

#[derive(Debug, Encode, Decode, EncodedSize)]
#[declio(ctx_is = "constants::ENDIANESS")]
pub struct StructRecord {
    pub member_count: u16,
    pub properties: ClassProperties,
    #[declio(with = "codecs::optional_index")]
    pub field_list: Option<TypeIndex>,
    #[declio(with = "codecs::optional_index")]
    pub derivation_list: Option<TypeIndex>,
    #[declio(with = "codecs::optional_index")]
    pub vtable_shape: Option<TypeIndex>,
    pub size: Integer,
    pub name: StrBuf,
    #[declio(skip_if = "!properties.has_unique_name()")]
    pub unique_name: StrBuf,
}

#[derive(Debug, Encode, Decode, EncodedSize)]
#[declio(ctx_is = "constants::ENDIANESS")]
pub struct UnionRecord {
    pub member_count: u16,
    pub properties: ClassProperties,
    #[declio(with = "codecs::optional_index")]
    pub field_list: Option<TypeIndex>,
    pub size: Integer,
    pub name: StrBuf,
    #[declio(skip_if = "!properties.has_unique_name()")]
    pub unique_name: StrBuf,
}

#[derive(Debug, Encode, Decode, EncodedSize)]
#[declio(ctx_is = "constants::ENDIANESS")]
pub struct EnumRecord {
    pub member_count: u16,
    pub properties: ClassProperties,
    pub underlying_type: TypeIndex,
    pub field_list: TypeIndex,
    pub size: Integer,
    pub name: StrBuf,
    #[declio(skip_if = "!properties.has_unique_name()")]
    pub unique_name: StrBuf,
}

#[derive(Debug, Encode, Decode, EncodedSize)]
#[declio(ctx_is = "constants::ENDIANESS")]
pub struct BaseClasRecord {
    pub properties: MemberProperties,
    pub base_type: TypeIndex,
    pub offset: Integer,
}

#[derive(Debug, Encode, Decode, EncodedSize)]
#[declio(ctx_is = "constants::ENDIANESS")]
pub struct VirtualBaseClasRecord {
    pub properties: MemberProperties,
    pub base_type: TypeIndex,
    pub vbptr_type: TypeIndex,
    pub vbptr_offset: Integer,
    pub vtable_index: Integer,
}

#[derive(Debug, Encode, Decode, EncodedSize)]
#[declio(ctx_is = "constants::ENDIANESS")]
pub struct MethodListEntry {
    pub properties: MemberProperties,
    pub reserved: [u8; 2],
    pub method_type: TypeIndex,
    #[declio(skip_if = "!properties.method_kind().is_introducing()")]
    pub vtable_offset: Option<u32>,
}

#[derive(Debug)]
pub struct VftShape {
    pub slots: Vec<VFTableSlotKind>,
}

impl<Ctx: Copy> Decode<Ctx> for VftShape {
    fn decode<R>(ctx: Ctx, reader: &mut R) -> Result<Self, declio::Error>
    where
        R: std::io::Read,
    {
        let count = u16::decode(constants::ENDIANESS, reader)?;
        let mut slots = Vec::with_capacity(count as usize);
        for _ in 0..div_ceil(count.into(), 2) {
            let byte = u8::decode(ctx, reader)?;
            let high = byte >> 4;
            slots.push(VFTableSlotKind::from_bytes(high).map_err(declio::Error::new)?);
            if count % 2 != 0 {
                let low = byte & 0x0F;
                slots.push(VFTableSlotKind::from_bytes(low).map_err(declio::Error::new)?);
            }
        }
        Ok(Self { slots })
    }
}

impl<Ctx> Encode<Ctx> for VftShape {
    fn encode<W>(&self, _ctx: Ctx, _writer: &mut W) -> Result<(), declio::Error>
    where
        W: std::io::Write,
    {
        todo!()
    }
}

impl<Ctx> EncodedSize<Ctx> for VftShape {
    fn encoded_size(&self, _ctx: Ctx) -> usize {
        u16::default_encoded_size(()) + div_ceil(self.slots.len() as u32, 2) as usize
    }
}

#[bitfield(bits = 32)]
#[derive(Debug, Clone, Copy)]
pub struct PointerProperties {
    pub kind: PointerKind,
    pub mode: PointerMode,
    pub is_flat32: bool,
    pub is_volatile: bool,
    pub is_const: bool,
    pub is_unaligned: bool,
    pub is_restrict: bool,
    pub size: B6,
    pub is_mocom: bool,
    pub is_lref: bool,
    pub is_rref: bool,
    #[skip]
    unused: B10,
}

impl_bitfield_codecs!(PointerProperties);

#[derive(Debug, Clone, Copy, BitfieldSpecifier)]
#[bits = 5]
pub enum PointerKind {
    Near16 = 0x00,
    Far16 = 0x01,
    Huge16 = 0x02,
    BasedOnSegment = 0x03,
    BasedOnValue = 0x04,
    BasedOnSegmentValue = 0x05,
    BasedOnAddress = 0x06,
    BasedOnSegmentAddress = 0x07,
    BasedOnType = 0x08,
    BasedOnSelf = 0x09,
    Near32 = 0x0a,
    Far32 = 0x0b,
    Near64 = 0x0c,
}

impl_bitfield_specifier_codecs!(PointerKind);

#[derive(Debug, Clone, Copy, BitfieldSpecifier)]
#[bits = 3]
pub enum PointerMode {
    Vanilla = 0x00,
    LValueReference = 0x01,
    DataMember = 0x02,
    MemberFunction = 0x03,
    RValueReference = 0x04,
}

impl PointerMode {
    pub fn is_member_pointer(self) -> bool {
        matches!(self, PointerMode::DataMember | PointerMode::MemberFunction)
    }
}

impl_bitfield_specifier_codecs!(PointerMode);

#[bitfield(bits = 16)]
#[derive(Debug, Clone, Copy)]
pub struct ModifierProperties {
    pub is_const: bool,
    pub is_volatile: bool,
    pub is_unaligned: bool,
    #[skip]
    unused: B13,
}

impl_bitfield_codecs!(ModifierProperties);

#[bitfield(bits = 8)]
#[derive(Debug, Clone, Copy)]
pub struct FunctionProperties {
    pub is_cxx_return_udt: bool,
    pub is_constructor: bool,
    pub is_constructor_with_virtual_bases: bool,
    #[skip]
    unused: B5,
}

impl_bitfield_codecs!(FunctionProperties);

#[bitfield(bits = 16)]
#[derive(Debug, Clone, Copy)]
pub struct ClassProperties {
    pub is_packed: bool,
    pub has_constructor_or_deconstructor: bool,
    pub has_overloaded_operator: bool,
    pub is_nested: bool,
    pub contains_nested: bool,
    pub has_overloaded_assignment: bool,
    pub has_conversion: bool,
    pub is_forward_ref: bool,
    pub is_scoped: bool,
    pub has_unique_name: bool,
    pub is_sealed: bool,
    #[skip]
    unused: B2,
    pub is_intrinsic: bool,
    #[skip]
    unused: B2,
}

impl_bitfield_codecs!(ClassProperties);

#[bitfield(bits = 16)]
#[derive(Debug, Clone, Copy)]
pub struct MemberProperties {
    pub access: MemberAccess,
    pub method_kind: MethodKind,
    pub is_pseudo: bool,
    pub is_no_inherit: bool,
    pub is_no_construct: bool,
    pub is_compiler_generated: bool,
    pub is_sealed: bool,
    #[skip]
    unused: B6,
}

impl_bitfield_codecs!(MemberProperties);

#[derive(Debug, Clone, Copy, BitfieldSpecifier)]
#[bits = 8]
pub enum CallingConvention {
    NearC = 0x00,
    FarC = 0x01,
    NearPascal = 0x02,
    FarPascal = 0x03,
    NearFast = 0x04,
    FarFast = 0x05,
    NearStdCall = 0x07,
    FarStdCall = 0x08,
    NearSysCall = 0x09,
    FarSysCall = 0x0a,
    ThisCall = 0x0b,
    MipsCall = 0x0c,
    Generic = 0x0d,
    AlphaCall = 0x0e,
    PpcCall = 0x0f,
    SHCall = 0x10,
    ArmCall = 0x11,
    AM33Call = 0x12,
    TriCall = 0x13,
    SH5Call = 0x14,
    M32RCall = 0x15,
    ClrCall = 0x16,
    Inline = 0x17,
    NearVector = 0x18,
}

impl_bitfield_specifier_codecs!(CallingConvention);

#[derive(Debug, Clone, Copy, BitfieldSpecifier)]
#[bits = 16]
pub enum LabelType {
    Near = 0x0,
    Far = 0x4,
}

impl_bitfield_specifier_codecs!(LabelType);

#[derive(Debug, Clone, Copy, BitfieldSpecifier)]
#[bits = 4]
pub enum VFTableSlotKind {
    Near16 = 0x00,
    Far16 = 0x01,
    This = 0x02,
    Outer = 0x03,
    Meta = 0x04,
    Near = 0x05,
    Far = 0x06,
}

impl_bitfield_specifier_codecs!(VFTableSlotKind);

#[derive(Debug, Clone, Copy, BitfieldSpecifier)]
#[bits = 2]
pub enum MemberAccess {
    None = 0,
    Private = 1,
    Protected = 2,
    Public = 3,
}

impl_bitfield_specifier_codecs!(MemberAccess);

#[derive(Debug, Clone, Copy, BitfieldSpecifier)]
#[bits = 3]
pub enum MethodKind {
    Vanilla = 0x00,
    Virtual = 0x01,
    Static = 0x02,
    Friend = 0x03,
    IntroducingVirtual = 0x04,
    PureVirtual = 0x05,
    PureIntroducingVirtual = 0x06,
}

impl MethodKind {
    pub fn is_introducing(self) -> bool {
        matches!(self, Self::IntroducingVirtual | Self::PureIntroducingVirtual)
    }
}

impl_bitfield_specifier_codecs!(MethodKind);

#[derive(Debug, Clone, Copy, BitfieldSpecifier)]
#[bits = 32]
pub enum BuiltinType {
    Void = 0x0003,
    NotTranslated = 0x0007,
    HResult = 0x0008,
    SignedChar = 0x0010,
    UnsignedChar = 0x0020,
    NarrowChar = 0x0070,
    WideChar = 0x0071,
    Char16 = 0x007a,
    Char32 = 0x007b,
    Char8 = 0x007c,

    I8 = 0x0068,
    U8 = 0x0069,
    I16Short = 0x0011,
    U16Short = 0x0021,
    I16 = 0x0072,
    U16 = 0x0073,
    I32Long = 0x0012,
    U32Long = 0x0022,
    I32 = 0x0074,
    U32 = 0x0075,
    I64Quad = 0x0013,
    U64Quad = 0x0023,
    I64 = 0x0076,
    U64 = 0x0077,
    I128Oct = 0x0014,
    U128Oct = 0x0024,
    I128 = 0x0078,
    U128 = 0x0079,

    F16 = 0x0046,
    F32 = 0x0040,
    F32PartialPrecision = 0x0045,
    F48 = 0x0044,
    F64 = 0x0041,
    F80 = 0x0042,
    F128 = 0x0043,

    Complex16 = 0x0056,
    Complex32 = 0x0050,
    Complex32PartialPrecision = 0x0055,
    Complex48 = 0x0054,
    Complex64 = 0x0051,
    Complex80 = 0x0052,
    Complex128 = 0x0053,

    Bool8 = 0x0030,
    Bool16 = 0x0031,
    Bool32 = 0x0032,
    Bool64 = 0x0033,
    Bool128 = 0x0034,
}

impl_bitfield_specifier_codecs!(BuiltinType);

impl From<BuiltinType> for TypeIndex {
    fn from(tp: BuiltinType) -> Self {
        TypeIndex::try_from(tp as u32).unwrap()
    }
}

#[derive(Debug)]
pub struct NonBuiltinType;

impl TryFrom<TypeIndex> for BuiltinType {
    type Error = NonBuiltinType;

    fn try_from(value: TypeIndex) -> Result<Self, Self::Error> {
        BuiltinType::from_bytes(u32::from(value)).map_err(|_| NonBuiltinType)
    }
}
