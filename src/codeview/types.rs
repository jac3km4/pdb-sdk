use std::fmt::Debug;

use declio::ctx::Len;
use declio::util::LittleEndian;
use declio::{Decode, Encode, EncodedSize};
use modular_bitfield::prelude::*;

use crate::utils::StrBuf;
use crate::{
    codecs, constants, impl_bitfield_codecs, impl_bitfield_specifier_codecs, Guid, Integer, TypeIndex
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
    /// Contains information about a type server.
    TypeServer2 {
        /// GUID of the type server.
        guid: Guid,
        /// Age of the type server.
        age: u32,
        /// Name of the type server or symbol.
        name: StrBuf,
    },
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
    /// A continuation of a field list.
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
    /// Identifies a member function.
    #[declio(id = "constants::LF_MFUNC_ID.into()")]
    MemberFuncId {
        /// Type of the class.
        class_type: TypeIndex,
        /// Function type.
        function_type: TypeIndex,
        /// Name of the member function.
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
/// Record describing a struct, class, or interface.
pub struct StructRecord {
    /// Number of members.
    pub member_count: u16,
    /// Class properties.
    pub properties: ClassProperties,
    /// Field list type index.
    #[declio(with = "codecs::optional_index")]
    pub field_list: Option<TypeIndex>,
    /// Derivation list type index.
    #[declio(with = "codecs::optional_index")]
    pub derivation_list: Option<TypeIndex>,
    /// VTable shape type index.
    #[declio(with = "codecs::optional_index")]
    pub vtable_shape: Option<TypeIndex>,
    /// Size in bytes.
    pub size: Integer,
    /// Name of the struct.
    pub name: StrBuf,
    /// Unique name of the struct.
    #[declio(skip_if = "!properties.has_unique_name()")]
    pub unique_name: StrBuf,
}

#[derive(Debug, Encode, Decode, EncodedSize)]
#[declio(ctx_is = "constants::ENDIANESS")]
/// Record describing a union.
pub struct UnionRecord {
    /// Number of members.
    pub member_count: u16,
    /// Class properties.
    pub properties: ClassProperties,
    /// Field list type index.
    #[declio(with = "codecs::optional_index")]
    pub field_list: Option<TypeIndex>,
    /// Size in bytes.
    pub size: Integer,
    /// Name of the union.
    pub name: StrBuf,
    /// Unique name of the union.
    #[declio(skip_if = "!properties.has_unique_name()")]
    pub unique_name: StrBuf,
}

#[derive(Debug, Encode, Decode, EncodedSize)]
#[declio(ctx_is = "constants::ENDIANESS")]
/// Record describing an enumeration.
pub struct EnumRecord {
    /// Number of members.
    pub member_count: u16,
    /// Class properties.
    pub properties: ClassProperties,
    /// Underlying integer type.
    pub underlying_type: TypeIndex,
    /// Field list type index.
    pub field_list: TypeIndex,
    /// Name of the enum.
    pub name: StrBuf,
    /// Unique name of the enum.
    #[declio(skip_if = "!properties.has_unique_name()")]
    pub unique_name: StrBuf,
}

#[derive(Debug, Encode, Decode, EncodedSize)]
#[declio(ctx_is = "constants::ENDIANESS")]
/// Record describing a base class.
pub struct BaseClasRecord {
    /// Member properties.
    pub properties: MemberProperties,
    /// Base class type index.
    pub base_type: TypeIndex,
    /// Offset in the parent class.
    pub offset: Integer,
}

#[derive(Debug, Encode, Decode, EncodedSize)]
#[declio(ctx_is = "constants::ENDIANESS")]
/// Record describing a virtual base class.
pub struct VirtualBaseClasRecord {
    /// Member properties.
    pub properties: MemberProperties,
    /// Base class type index.
    pub base_type: TypeIndex,
    /// Type index of the virtual base pointer.
    pub vbptr_type: TypeIndex,
    /// Offset of the virtual base pointer.
    pub vbptr_offset: Integer,
    /// Index in the vtable.
    pub vtable_index: Integer,
}

#[derive(Debug, Encode, Decode, EncodedSize)]
#[declio(ctx_is = "constants::ENDIANESS")]
/// Entry in a method list.
pub struct MethodListEntry {
    /// Member properties.
    pub properties: MemberProperties,
    /// Reserved padding.
    pub reserved: [u8; 2],
    /// Type index of the method.
    pub method_type: TypeIndex,
    /// Optional offset in the vtable.
    #[declio(skip_if = "!properties.method_kind().is_introducing()")]
    pub vtable_offset: Option<u32>,
}

#[derive(Debug)]
/// Shape of a virtual function table (slots).
pub struct VftShape {
    /// Kinds of vtable slots.
    pub slots: Vec<VFTableSlotKind>,
}

impl<Ctx: Copy> Decode<Ctx> for VftShape {
    fn decode<R>(ctx: Ctx, reader: &mut R) -> Result<Self, declio::Error>
    where
        R: std::io::Read,
    {
        let count = u16::decode(constants::ENDIANESS, reader)?;
        let mut slots = Vec::with_capacity(count as usize);
        for _ in 0..count.div_ceil(2) {
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
        u16::default_encoded_size(()) + self.slots.len().div_ceil(2)
    }
}

#[bitfield(bits = 32)]
#[derive(Debug, Clone, Copy)]
/// Attributes of a pointer (kind, mode, modifiers, etc).
pub struct PointerProperties {
    /// Kind of pointer.
    pub kind: PointerKind,
    /// Mode of the pointer.
    pub mode: PointerMode,
    /// Is flat 32-bit pointer.
    pub is_flat32: bool,
    /// Is volatile.
    pub is_volatile: bool,
    /// Is const.
    pub is_const: bool,
    /// Is unaligned.
    pub is_unaligned: bool,
    /// Is restricted.
    pub is_restrict: bool,
    /// Size of the pointer.
    pub size: B6,
    /// Is MOCOM.
    pub is_mocom: bool,
    /// Is an L-value reference.
    pub is_lref: bool,
    /// Is an R-value reference.
    pub is_rref: bool,
    #[skip]
    unused: B10,
}

impl_bitfield_codecs!(PointerProperties);

#[derive(Debug, Clone, Copy, Specifier)]
#[bits = 5]
pub enum PointerKind {
    /// 16 bit pointer.
    Near16 = 0x00,
    /// 16:16 far pointer.
    Far16 = 0x01,
    /// 16:16 huge pointer.
    Huge16 = 0x02,
    /// Based on segment.
    BasedOnSegment = 0x03,
    /// Based on value of base.
    BasedOnValue = 0x04,
    /// Based on segment value of base.
    BasedOnSegmentValue = 0x05,
    /// Based on address of base.
    BasedOnAddress = 0x06,
    /// Based on segment address of base.
    BasedOnSegmentAddress = 0x07,
    /// Based on type.
    BasedOnType = 0x08,
    /// Based on self.
    BasedOnSelf = 0x09,
    /// 32 bit pointer.
    Near32 = 0x0a,
    /// 16:32 pointer.
    Far32 = 0x0b,
    /// 64 bit pointer.
    Near64 = 0x0c,
}

impl_bitfield_specifier_codecs!(PointerKind);

#[derive(Debug, Clone, Copy, Specifier)]
#[bits = 3]
pub enum PointerMode {
    /// Normal pointer.
    Vanilla = 0x00,
    /// L-value reference.
    LValueReference = 0x01,
    /// Pointer to data member.
    DataMember = 0x02,
    /// Pointer to member function.
    MemberFunction = 0x03,
    /// R-value reference.
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
/// Attributes for a modified type (const, volatile, unaligned).
pub struct ModifierProperties {
    /// Is const.
    pub is_const: bool,
    /// Is volatile.
    pub is_volatile: bool,
    /// Is unaligned.
    pub is_unaligned: bool,
    #[skip]
    unused: B13,
}

impl_bitfield_codecs!(ModifierProperties);

#[bitfield(bits = 8)]
#[derive(Debug, Clone, Copy)]
/// Attributes for a function (e.g., constructor, cxx return UDT).
pub struct FunctionProperties {
    /// Returns a C++ UDT.
    pub is_cxx_return_udt: bool,
    /// Is a constructor.
    pub is_constructor: bool,
    /// Is a constructor with virtual bases.
    pub is_constructor_with_virtual_bases: bool,
    #[skip]
    unused: B5,
}

impl_bitfield_codecs!(FunctionProperties);

#[bitfield(bits = 16)]
#[derive(Debug, Clone, Copy)]
/// Properties of a class/struct (e.g., forward reference, scoped, has constructor).
pub struct ClassProperties {
    /// Is packed.
    pub is_packed: bool,
    /// Has constructor or destructor.
    pub has_constructor_or_deconstructor: bool,
    /// Has overloaded operator.
    pub has_overloaded_operator: bool,
    /// Is nested.
    pub is_nested: bool,
    /// Contains nested class.
    pub contains_nested: bool,
    /// Has overloaded assignment operator.
    pub has_overloaded_assignment: bool,
    /// Has conversion operator.
    pub has_conversion: bool,
    /// Is a forward reference.
    pub is_forward_ref: bool,
    /// Is scoped.
    pub is_scoped: bool,
    /// Has a unique name.
    pub has_unique_name: bool,
    /// Is sealed.
    pub is_sealed: bool,
    #[skip]
    unused: B2,
    /// Is intrinsic.
    pub is_intrinsic: bool,
    #[skip]
    unused: B2,
}

impl_bitfield_codecs!(ClassProperties);

#[bitfield(bits = 16)]
#[derive(Debug, Clone, Copy)]
/// Properties of a member (access level, static, virtual).
pub struct MemberProperties {
    /// Access level.
    pub access: MemberAccess,
    /// Kind of method.
    pub method_kind: MethodKind,
    /// Is pseudo.
    pub is_pseudo: bool,
    /// Cannot be inherited.
    pub is_no_inherit: bool,
    /// Cannot be constructed.
    pub is_no_construct: bool,
    /// Is compiler generated.
    pub is_compiler_generated: bool,
    /// Is sealed.
    pub is_sealed: bool,
    #[skip]
    unused: B6,
}

impl_bitfield_codecs!(MemberProperties);

#[derive(Debug, Clone, Copy, Specifier)]
#[bits = 8]
pub enum CallingConvention {
    /// Near C calling convention.
    NearC = 0x00,
    /// Far C calling convention.
    FarC = 0x01,
    /// Near Pascal calling convention.
    NearPascal = 0x02,
    /// Far Pascal calling convention.
    FarPascal = 0x03,
    /// Near Fast calling convention.
    NearFast = 0x04,
    /// Far Fast calling convention.
    FarFast = 0x05,
    /// Near stdcall calling convention.
    NearStdCall = 0x07,
    /// Far stdcall calling convention.
    FarStdCall = 0x08,
    /// Near syscall calling convention.
    NearSysCall = 0x09,
    /// Far syscall calling convention.
    FarSysCall = 0x0a,
    /// thiscall calling convention.
    ThisCall = 0x0b,
    /// MIPS calling convention.
    MipsCall = 0x0c,
    /// Generic calling convention.
    Generic = 0x0d,
    /// Alpha calling convention.
    AlphaCall = 0x0e,
    /// PowerPC calling convention.
    PpcCall = 0x0f,
    /// SuperH calling convention.
    SHCall = 0x10,
    /// ARM calling convention.
    ArmCall = 0x11,
    /// AM33 calling convention.
    AM33Call = 0x12,
    /// TriCore calling convention.
    TriCall = 0x13,
    /// SuperH 5 calling convention.
    SH5Call = 0x14,
    /// M32R calling convention.
    M32RCall = 0x15,
    /// CLR calling convention.
    ClrCall = 0x16,
    /// Inline calling convention.
    Inline = 0x17,
    /// Near vector calling convention.
    NearVector = 0x18,
}

impl_bitfield_specifier_codecs!(CallingConvention);

#[derive(Debug, Clone, Copy, Specifier)]
#[bits = 16]
pub enum LabelType {
    /// Near label.
    Near = 0x0,
    /// Far label.
    Far = 0x4,
}

impl_bitfield_specifier_codecs!(LabelType);

#[derive(Debug, Clone, Copy, Specifier)]
#[bits = 4]
pub enum VFTableSlotKind {
    /// 16 bit pointer.
    Near16 = 0x00,
    /// 16:16 far pointer.
    Far16 = 0x01,
    /// This pointer slot.
    This = 0x02,
    /// Outer pointer slot.
    Outer = 0x03,
    /// Meta pointer slot.
    Meta = 0x04,
    /// Near pointer slot.
    Near = 0x05,
    /// Far pointer slot.
    Far = 0x06,
}

impl_bitfield_specifier_codecs!(VFTableSlotKind);

#[derive(Debug, Clone, Copy, Specifier)]
#[bits = 2]
pub enum MemberAccess {
    /// No access protection.
    None = 0,
    /// Private access.
    Private = 1,
    /// Protected access.
    Protected = 2,
    /// Public access.
    Public = 3,
}

impl_bitfield_specifier_codecs!(MemberAccess);

#[derive(Debug, Clone, Copy, Specifier)]
#[bits = 3]
pub enum MethodKind {
    /// Normal method.
    Vanilla = 0x00,
    /// Virtual method.
    Virtual = 0x01,
    /// Static method.
    Static = 0x02,
    /// Friend method.
    Friend = 0x03,
    /// Introducing virtual method.
    IntroducingVirtual = 0x04,
    /// Pure virtual method.
    PureVirtual = 0x05,
    /// Pure introducing virtual method.
    PureIntroducingVirtual = 0x06,
}

impl MethodKind {
    pub fn is_introducing(self) -> bool {
        matches!(self, Self::IntroducingVirtual | Self::PureIntroducingVirtual)
    }
}

impl_bitfield_specifier_codecs!(MethodKind);

#[derive(Debug, Clone, Copy, Specifier)]
#[bits = 32]
pub enum BuiltinType {
    /// Void type.
    Void = 0x0003,
    /// Not translated type.
    NotTranslated = 0x0007,
    /// HRESULT type.
    HResult = 0x0008,
    /// Signed char.
    SignedChar = 0x0010,
    /// Unsigned char.
    UnsignedChar = 0x0020,
    /// Narrow char.
    NarrowChar = 0x0070,
    /// Wide char.
    WideChar = 0x0071,
    /// Char16.
    Char16 = 0x007a,
    /// Char32.
    Char32 = 0x007b,
    /// Char8.
    Char8 = 0x007c,

    /// 8-bit signed int.
    I8 = 0x0068,
    /// 8-bit unsigned int.
    U8 = 0x0069,
    /// 16-bit signed short.
    I16Short = 0x0011,
    /// 16-bit unsigned short.
    U16Short = 0x0021,
    /// 16-bit signed int.
    I16 = 0x0072,
    /// 16-bit unsigned int.
    U16 = 0x0073,
    /// 32-bit signed long.
    I32Long = 0x0012,
    /// 32-bit unsigned long.
    U32Long = 0x0022,
    /// 32-bit signed int.
    I32 = 0x0074,
    /// 32-bit unsigned int.
    U32 = 0x0075,
    /// 64-bit signed quad.
    I64Quad = 0x0013,
    /// 64-bit unsigned quad.
    U64Quad = 0x0023,
    /// 64-bit signed int.
    I64 = 0x0076,
    /// 64-bit unsigned int.
    U64 = 0x0077,
    /// 128-bit signed oct.
    I128Oct = 0x0014,
    /// 128-bit unsigned oct.
    U128Oct = 0x0024,
    /// 128-bit signed int.
    I128 = 0x0078,
    /// 128-bit unsigned int.
    U128 = 0x0079,

    /// 16-bit float.
    F16 = 0x0046,
    /// 32-bit float.
    F32 = 0x0040,
    /// 32-bit float with partial precision.
    F32PartialPrecision = 0x0045,
    /// 48-bit float.
    F48 = 0x0044,
    /// 64-bit float.
    F64 = 0x0041,
    /// 80-bit float.
    F80 = 0x0042,
    /// 128-bit float.
    F128 = 0x0043,

    /// 16-bit complex.
    Complex16 = 0x0056,
    /// 32-bit complex.
    Complex32 = 0x0050,
    /// 32-bit complex with partial precision.
    Complex32PartialPrecision = 0x0055,
    /// 48-bit complex.
    Complex48 = 0x0054,
    /// 64-bit complex.
    Complex64 = 0x0051,
    /// 80-bit complex.
    Complex80 = 0x0052,
    /// 128-bit complex.
    Complex128 = 0x0053,

    /// 8-bit boolean.
    Bool8 = 0x0030,
    /// 16-bit boolean.
    Bool16 = 0x0031,
    /// 32-bit boolean.
    Bool32 = 0x0032,
    /// 64-bit boolean.
    Bool64 = 0x0033,
    /// 128-bit boolean.
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
