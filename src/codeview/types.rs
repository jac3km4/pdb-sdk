use std::fmt::Debug;

use declio::ctx::Len;
use declio::util::LittleEndian;
use declio::{Decode, Encode, EncodedSize};
use modular_bitfield::prelude::*;

use crate::utils::StrBuf;
use crate::{
    Guid, Integer, TypeIndex, codecs, constants, impl_bitfield_codecs,
    impl_bitfield_specifier_codecs,
};

#[derive(Debug, Encode, Decode, EncodedSize)]
#[declio(ctx_is = "constants::ENDIANESS", id_type = "LittleEndian<u16>")]
/// CodeView Type Record, representing various types (e.g., pointers, modifiers, structs).
pub enum TypeRecord {
    #[declio(id = "constants::LF_POINTER.into()")]
    /// Describes a pointer to another type.
    Pointer {
        /// The type being pointed to.
        referent: TypeIndex,
        /// Pointer attributes.
        properties: PointerProperties,
        /// The class containing the member pointer.
        #[declio(skip_if = "!properties.mode().is_member_pointer()")]
        containing_class: Option<TypeIndex>,
    },
    #[declio(id = "constants::LF_MODIFIER.into()")]
    /// Describes a modified type (e.g., const, volatile).
    Modifier {
        /// The type being modified.
        modified_type: TypeIndex,
        /// Modifier attributes.
        properties: ModifierProperties,
    },
    #[declio(id = "constants::LF_PROCEDURE.into()")]
    /// Describes a procedure (function) type.
    Procedure {
        /// Return type of the procedure.
        #[declio(with = "codecs::optional_index")]
        return_type: Option<TypeIndex>,
        /// Calling convention.
        calling_conv: CallingConvention,
        /// Function attributes.
        properties: FunctionProperties,
        /// Number of arguments.
        arg_count: u16,
        /// Type index of the argument list.
        arg_list: TypeIndex,
    },
    #[declio(id = "constants::LF_MFUNCTION.into()")]
    /// Describes a member function type.
    MemberFunction {
        /// Return type of the procedure.
        #[declio(with = "codecs::optional_index")]
        return_type: Option<TypeIndex>,
        /// The class type this method belongs to.
        #[declio(with = "codecs::optional_index")]
        class_type: Option<TypeIndex>,
        /// Type of the `this` pointer.
        #[declio(with = "codecs::optional_index")]
        this_type: Option<TypeIndex>,
        /// Calling convention.
        calling_conv: CallingConvention,
        /// Function attributes.
        properties: FunctionProperties,
        /// Number of arguments.
        arg_count: u16,
        /// Type index of the argument list.
        arg_list: TypeIndex,
        /// Adjustment to the `this` pointer.
        this_adjustment: i32,
    },
    #[declio(id = "constants::LF_LABEL.into()")]
    /// Describes a label type.
    Label(LabelType),
    #[declio(id = "constants::LF_ARGLIST.into()")]
    /// A list of arguments for a procedure.
    ArgList {
        /// Number of elements.
        count: u32,
        /// List of argument type indices.
        #[declio(ctx = "(Len(*count as usize), constants::ENDIANESS)")]
        arg_list: Vec<u32>,
    },
    #[declio(id = "constants::LF_FIELDLIST.into()")]
    /// A list of members in a class, struct, or union.
    FieldList {
        /// List of member fields.
        #[declio(with = "codecs::padded_rem_list")]
        fields: Vec<TypeRecord>,
    },
    #[declio(id = "constants::LF_ARRAY.into()")]
    /// Describes an array type.
    Array {
        /// Type of array elements.
        element_type: TypeIndex,
        /// Type of the array index.
        index_type: TypeIndex,
        /// Dimensions of the array.
        #[declio(with = "codecs::padded_rem_list")]
        dimensions: Vec<Integer>,
    },
    #[declio(id = "constants::LF_CLASS.into()")]
    /// Describes a class.
    Class(StructRecord),
    #[declio(id = "constants::LF_STRUCTURE.into()")]
    /// Describes a structure.
    Struct(StructRecord),
    #[declio(id = "constants::LF_INTERFACE.into()")]
    /// Describes an interface.
    Interface(StructRecord),
    #[declio(id = "constants::LF_UNION.into()")]
    /// Describes a union.
    Union(UnionRecord),
    #[declio(id = "constants::LF_ENUM.into()")]
    /// Describes an enumeration.
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
    /// Describes a virtual function table.
    VFTable {
        /// Complete class type.
        complete_class: TypeIndex,
        /// Overridden virtual function table.
        overriden_vftable: TypeIndex,
        /// Offset of the virtual function pointer.
        vfptr_offset: u32,
        /// Number of names.
        name_count: u32,
        // todo method_names
    },
    #[declio(id = "constants::LF_VTSHAPE.into()")]
    /// Describes the shape of a virtual function table.
    VfTableShape(VftShape),
    #[declio(id = "constants::LF_BITFIELD.into()")]
    /// Describes a bitfield member of a struct/class.
    BitField {
        /// Type of the bitfield.
        field_type: TypeIndex,
        /// Size of the bitfield in bits.
        bit_size: u8,
        /// Offset of the bitfield in bits.
        bit_offset: u8,
    },
    #[declio(id = "constants::LF_BCLASS.into()")]
    /// Base class of a class or struct.
    BaseClass(BaseClasRecord),
    #[declio(id = "constants::LF_BINTERFACE.into()")]
    /// Base interface of a class or struct.
    BaseInterface(BaseClasRecord),
    #[declio(id = "constants::LF_VBCLASS.into()")]
    /// Virtual base class of a class or struct.
    VirtualBaseClass(VirtualBaseClasRecord),
    #[declio(id = "constants::LF_IVBCLASS.into()")]
    /// Indirect virtual base class.
    IndirectVirtualBaseClass(VirtualBaseClasRecord),
    #[declio(id = "constants::LF_VFUNCTAB.into()")]
    /// Pointer to a virtual function table.
    VFPtr {
        /// Reserved padding.
        reserved: [u8; 2],
        /// Type of the virtual function table.
        table_type: TypeIndex,
    },
    #[declio(id = "constants::LF_STMEMBER.into()")]
    /// A static data member of a class.
    StaticDataMember {
        /// Member attributes.
        properties: MemberProperties,
        /// Type of the bitfield.
        field_type: TypeIndex,
        /// Name of the static member.
        name: StrBuf,
    },
    #[declio(id = "constants::LF_METHOD.into()")]
    /// An overloaded method.
    OverloadedMethod {
        /// Number of elements.
        count: u16,
        /// Type index of the method list.
        method_list: TypeIndex,
        /// Name of the overloaded method.
        name: StrBuf,
    },
    #[declio(id = "constants::LF_MEMBER.into()")]
    /// A standard data member of a class, struct, or union.
    DataMember {
        /// Member attributes.
        properties: MemberProperties,
        /// Type of the data member.
        #[declio(with = "codecs::optional_index")]
        field_type: Option<TypeIndex>,
        /// Offset of the data member.
        offset: Integer,
        /// Name of the data member.
        name: StrBuf,
    },
    #[declio(id = "constants::LF_NESTTYPE.into()")]
    /// A nested type definition.
    NestedType {
        /// Member attributes.
        properties: MemberProperties,
        /// Type of the nested class/struct/enum.
        nested_type: TypeIndex,
        /// Name of the nested type.
        name: StrBuf,
    },
    #[declio(id = "constants::LF_ONEMETHOD.into()")]
    /// A single method of a class.
    OneMethod {
        /// Member attributes.
        properties: MemberProperties,
        /// Type of the method.
        method_type: TypeIndex,
        /// Offset in the vtable.
        #[declio(skip_if = "!properties.method_kind().is_introducing()")]
        vtable_offset: Option<u32>,
        /// Name of the method.
        name: StrBuf,
    },
    #[declio(id = "constants::LF_ENUMERATE.into()")]
    /// An enumerator value.
    Enumerator {
        /// Member attributes.
        properties: MemberProperties,
        /// Value of the enumerator.
        value: Integer,
        /// Name of the enumerator.
        name: StrBuf,
    },
    #[declio(id = "constants::LF_INDEX.into()")]
    /// A continuation of a field list.
    ListContinuation(TypeIndex),
    #[declio(id = "constants::LF_METHODLIST.into()")]
    /// A list of methods.
    MethodList {
        /// List of methods.
        #[declio(with = "codecs::padded_rem_list")]
        methods: Vec<MethodListEntry>,
    },
}

#[derive(Debug, Encode, Decode, EncodedSize)]
#[declio(ctx_is = "constants::ENDIANESS", id_type = "LittleEndian<u16>")]
/// CodeView ID Record, representing items like function IDs, string IDs, etc.
pub enum IdRecord {
    #[declio(id = "constants::LF_FUNC_ID.into()")]
    /// Identifies a function.
    FuncId {
        /// Parent scope type.
        #[declio(with = "codecs::optional_index")]
        parent_scope: Option<TypeIndex>,
        /// Function type.
        function_type: TypeIndex,
        /// Name of the function.
        name: StrBuf,
    },
    #[declio(id = "constants::LF_MFUNC_ID.into()")]
    /// Identifies a member function.
    MemberFuncId {
        /// Type of the class.
        class_type: TypeIndex,
        /// Function type.
        function_type: TypeIndex,
        /// Name of the member function.
        name: StrBuf,
    },
    #[declio(id = "constants::LF_BUILDINFO.into()")]
    /// Contains build information.
    BuildInfo {
        /// Number of arguments.
        count: u16,
        /// Build info arguments.
        #[declio(ctx = "(Len(*count as usize), constants::ENDIANESS)")]
        arguments: Vec<u32>,
    },
    #[declio(id = "constants::LF_SUBSTR_LIST.into()")]
    /// A list of strings.
    StringList {
        /// Number of strings.
        count: u32,
        /// List of string type indices.
        #[declio(ctx = "(Len(*count as usize), constants::ENDIANESS)")]
        strings: Vec<TypeIndex>,
    },
    #[declio(id = "constants::LF_STRING_ID.into()")]
    /// An ID for a string.
    StringId {
        /// ID for the string.
        #[declio(with = "codecs::optional_index")]
        id: Option<TypeIndex>,
        /// The string data.
        string: StrBuf,
    },
    #[declio(id = "constants::LF_UDT_SRC_LINE.into()")]
    /// Source line information for a user-defined type.
    UdtSourceLine {
        /// User-defined type.
        udt: TypeIndex,
        /// Source file containing the UDT.
        source_file: TypeIndex,
        /// Line number in the source file.
        line_number: u32,
    },
    #[declio(id = "constants::LF_UDT_MOD_SRC_LINE.into()")]
    /// Module source line information for a user-defined type.
    UdtModSourceLine {
        /// User-defined type.
        udt: TypeIndex,
        /// Source file containing the UDT.
        source_file: TypeIndex,
        /// Line number in the source file.
        line_number: u32,
        /// Module containing the source line.
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
/// Underlying kind of a pointer (e.g., Near32, Far64).
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
/// Mode of a pointer (e.g., pointer, L-value reference, member data pointer).
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
    /// Checks if this modifier indicates a member pointer.
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
/// Calling convention of a function (e.g., NearC, ThisCall).
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
/// Type of label (Near or Far).
pub enum LabelType {
    /// Near label.
    Near = 0x0,
    /// Far label.
    Far = 0x4,
}

impl_bitfield_specifier_codecs!(LabelType);

#[derive(Debug, Clone, Copy, Specifier)]
#[bits = 4]
/// Type of slot in a virtual function table.
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
/// Access level for a class member (Private, Protected, Public).
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
/// Kind of a method (Virtual, Static, etc).
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
    /// Checks if this virtual function table shape indicates an introducing virtual function.
    pub fn is_introducing(self) -> bool {
        matches!(
            self,
            Self::IntroducingVirtual | Self::PureIntroducingVirtual
        )
    }
}

impl_bitfield_specifier_codecs!(MethodKind);

#[derive(Debug, Clone, Copy, Specifier)]
#[bits = 32]
/// Built-in types (e.g., Void, I32, F64).
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
/// Error type for when a TypeIndex is not a builtin type.
pub struct NonBuiltinType;

impl TryFrom<TypeIndex> for BuiltinType {
    type Error = NonBuiltinType;

    fn try_from(value: TypeIndex) -> Result<Self, Self::Error> {
        BuiltinType::from_bytes(u32::from(value)).map_err(|_| NonBuiltinType)
    }
}
