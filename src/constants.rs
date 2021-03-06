use declio::ctx::Endian;

pub const ENDIANESS: Endian = Endian::Little;

pub const LF_POINTER: u16 = 0x1002;
pub const LF_MODIFIER: u16 = 0x1001;
pub const LF_PROCEDURE: u16 = 0x1008;
pub const LF_MFUNCTION: u16 = 0x1009;
pub const LF_LABEL: u16 = 0x000e;
pub const LF_ARGLIST: u16 = 0x1201;
pub const LF_FIELDLIST: u16 = 0x1203;
pub const LF_ARRAY: u16 = 0x1503;
pub const LF_CLASS: u16 = 0x1504;
pub const LF_STRUCTURE: u16 = 0x1505;
pub const LF_INTERFACE: u16 = 0x1519;
pub const LF_UNION: u16 = 0x1506;
pub const LF_ENUM: u16 = 0x1507;
pub const LF_TYPESERVER2: u16 = 0x1515;
pub const LF_VFTABLE: u16 = 0x151d;
pub const LF_VTSHAPE: u16 = 0x000a;
pub const LF_BITFIELD: u16 = 0x1205;

pub const LF_BCLASS: u16 = 0x1400;
pub const LF_BINTERFACE: u16 = 0x151a;
pub const LF_VBCLASS: u16 = 0x1401;
pub const LF_IVBCLASS: u16 = 0x1402;
pub const LF_VFUNCTAB: u16 = 0x1409;
pub const LF_STMEMBER: u16 = 0x150e;
pub const LF_METHOD: u16 = 0x150f;
pub const LF_MEMBER: u16 = 0x150d;
pub const LF_NESTTYPE: u16 = 0x1510;
pub const LF_ONEMETHOD: u16 = 0x1511;
pub const LF_ENUMERATE: u16 = 0x1502;
pub const LF_INDEX: u16 = 0x1404;
pub const LF_FUNC_ID: u16 = 0x1601;
pub const LF_MFUNC_ID: u16 = 0x1602;
pub const LF_BUILDINFO: u16 = 0x1603;
pub const LF_SUBSTR_LIST: u16 = 0x1604;
pub const LF_STRING_ID: u16 = 0x1605;
pub const LF_UDT_SRC_LINE: u16 = 0x1606;
pub const LF_UDT_MOD_SRC_LINE: u16 = 0x1607;
pub const LF_METHODLIST: u16 = 0x1206;

pub const LF_NUMERIC: u16 = 0x8000;
pub const LF_CHAR: u16 = 0x8000;
pub const LF_SHORT: u16 = 0x8001;
pub const LF_USHORT: u16 = 0x8002;
pub const LF_LONG: u16 = 0x8003;
pub const LF_ULONG: u16 = 0x8004;
pub const LF_QUADWORD: u16 = 0x8009;
pub const LF_UQUADWORD: u16 = 0x800a;

pub const LF_PAD0: u8 = 0xf0;
pub const LF_PAD15: u8 = 0xff;

pub const S_INLINEES: u16 = 0x1168;
pub const S_END: u16 = 0x0006;
pub const S_INLINESITE_END: u16 = 0x114e;
pub const S_PROC_ID_END: u16 = 0x114f;
pub const S_THUNK32: u16 = 0x1102;
pub const S_TRAMPOLINE: u16 = 0x112c;
pub const S_SECTION: u16 = 0x1136;
pub const S_COFFGROUP: u16 = 0x1137;
pub const S_EXPORT: u16 = 0x1138;
pub const S_LPROC32: u16 = 0x110f;
pub const S_GPROC32: u16 = 0x1110;
pub const S_LPROC32_ID: u16 = 0x1146;
pub const S_GPROC32_ID: u16 = 0x1147;
pub const S_LPROC32_DPC: u16 = 0x1155;
pub const S_LPROC32_DPC_ID: u16 = 0x1156;
pub const S_REGISTER: u16 = 0x1106;
pub const S_PUB32: u16 = 0x110e;
pub const S_PROCREF: u16 = 0x1125;
pub const S_LPROCREF: u16 = 0x1127;
pub const S_ENVBLOCK: u16 = 0x113d;
pub const S_INLINESITE: u16 = 0x114d;
pub const S_LOCAL: u16 = 0x113e;
pub const S_DEFRANGE: u16 = 0x113f;
pub const S_DEFRANGE_SUBFIELD: u16 = 0x1140;
pub const S_DEFRANGE_REGISTER: u16 = 0x1141;
pub const S_DEFRANGE_FRAMEPOINTER_REL: u16 = 0x1142;
pub const S_DEFRANGE_SUBFIELD_REGISTER: u16 = 0x1143;
pub const S_DEFRANGE_FRAMEPOINTER_REL_FULL_SCOPE: u16 = 0x1144;
pub const S_DEFRANGE_REGISTER_REL: u16 = 0x1145;
pub const S_BLOCK32: u16 = 0x1103;
pub const S_LABEL32: u16 = 0x1105;
pub const S_OBJNAME: u16 = 0x1101;
pub const S_COMPILE2: u16 = 0x1116;
pub const S_COMPILE3: u16 = 0x113c;
pub const S_FRAMEPROC: u16 = 0x1012;
pub const S_CALLSITEINFO: u16 = 0x1139;
pub const S_FILESTATIC: u16 = 0x1153;
pub const S_HEAPALLOCSITE: u16 = 0x115e;
pub const S_FRAMECOOKIE: u16 = 0x113a;
pub const S_CALLEES: u16 = 0x115a;
pub const S_CALLERS: u16 = 0x115b;
pub const S_UDT: u16 = 0x1108;
pub const S_COBOLUDT: u16 = 0x1109;
pub const S_BUILDINFO: u16 = 0x114c;
pub const S_BPREL32: u16 = 0x110b;
pub const S_REGREL32: u16 = 0x1111;
pub const S_CONSTANT: u16 = 0x1107;
pub const S_MANCONSTANT: u16 = 0x112d;
pub const S_LDATA32: u16 = 0x110c;
pub const S_GDATA32: u16 = 0x110d;
pub const S_LMANDATA: u16 = 0x111c;
pub const S_GMANDATA: u16 = 0x111d;
pub const S_LTHREAD32: u16 = 0x1112;
pub const S_GTHREAD32: u16 = 0x1113;
pub const S_UNAMESPACE: u16 = 0x1124;
pub const S_ANNOTATION: u16 = 0x1019;
