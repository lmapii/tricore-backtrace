# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: exc.proto
"""Generated protocol buffer code."""
from google.protobuf.internal import enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n\texc.proto\"I\n\x08TrapInfo\x12\x17\n\x04trap\x18\x01 \x01(\x0e\x32\t.TrapType\x12\x0c\n\x04\x64str\x18\x02 \x01(\x07\x12\x16\n\x0e\x61\x64\x64r_of_access\x18\x03 \x01(\x07\"&\n\x03\x43sa\x12\x10\n\x08is_upper\x18\x01 \x01(\x08\x12\r\n\x05words\x18\x02 \x03(\x07\"\xa3\x02\n\x08\x43oreDump\x12\x1c\n\x04\x63\x66sr\x18\x01 \x01(\x0b\x32\x0e.CoreDump.Cfsr\x12\r\n\x05gpr_d\x18\x02 \x03(\x07\x12\r\n\x05gpr_a\x18\x03 \x03(\x07\x1a\xda\x01\n\x04\x43\x66sr\x12\n\n\x02pc\x18\x01 \x01(\x07\x12\x0b\n\x03psw\x18\x02 \x01(\x07\x12\x0c\n\x04pcxi\x18\x03 \x01(\x07\x12\x0b\n\x03icr\x18\x04 \x01(\x07\x12\x0e\n\x06syscon\x18\x05 \x01(\x07\x12\x0e\n\x06\x63pu_id\x18\x06 \x01(\x07\x12\x0f\n\x07\x63ore_id\x18\x07 \x01(\x07\x12\x0b\n\x03\x62iv\x18\x08 \x01(\x07\x12\x0b\n\x03\x62tv\x18\t \x01(\x07\x12\x0b\n\x03isp\x18\n \x01(\x07\x12\x0b\n\x03\x66\x63x\x18\x0b \x01(\x07\x12\x0b\n\x03lcx\x18\x0c \x01(\x07\x12\x0e\n\x06\x63us_id\x18\r \x01(\x07\x12\r\n\x05\x64\x63on2\x18\x11 \x01(\x07\x12\r\n\x05pcon2\x18\x14 \x01(\x07\"\x9c\x01\n\nExcDefault\x12\x16\n\x0eversion_marker\x18\x01 \x01(\r\x12\x0f\n\x07task_id\x18\x02 \x01(\x07\x12\x10\n\x08\x63ore_idx\x18\x03 \x01(\x07\x12\x1c\n\ttrap_info\x18\x04 \x01(\x0b\x32\t.TrapInfo\x12\x1c\n\tcore_dump\x18\x05 \x01(\x0b\x32\t.CoreDump\x12\x17\n\tbacktrace\x18\x06 \x03(\x0b\x32\x04.Csa*\xfb\x03\n\x08TrapType\x12\x0b\n\x07UNKNOWN\x10\x00\x12\r\n\tC0_T0_VAF\x10\x01\x12\r\n\tC0_T1_VAP\x10\x02\x12\x0e\n\nC1_T1_PRIV\x10\x03\x12\r\n\tC1_T2_MPR\x10\x04\x12\r\n\tC1_T3_MPW\x10\x05\x12\r\n\tC1_T4_MPX\x10\x06\x12\r\n\tC1_T5_MPP\x10\x07\x12\r\n\tC1_T6_MPN\x10\x08\x12\x0e\n\nC1_T7_GRWP\x10\t\x12\x0e\n\nC2_T1_IOPC\x10\n\x12\x0e\n\nC2_T2_UOPC\x10\x0b\x12\r\n\tC2_T3_OPD\x10\x0c\x12\r\n\tC2_T4_ALN\x10\r\x12\r\n\tC2_T5_MEM\x10\x0e\x12\r\n\tC3_T1_FCD\x10\x0f\x12\r\n\tC3_T2_CDO\x10\x10\x12\r\n\tC3_T3_CDU\x10\x11\x12\r\n\tC3_T4_FCU\x10\x12\x12\r\n\tC3_T5_CSU\x10\x13\x12\x0e\n\nC3_T6_CTYP\x10\x14\x12\x0e\n\nC3_T7_NEST\x10\x15\x12\r\n\tC4_T1_PSE\x10\x16\x12\r\n\tC4_T2_DSE\x10\x17\x12\r\n\tC4_T3_DAE\x10\x18\x12\r\n\tC4_T4_CAE\x10\x19\x12\r\n\tC4_T5_PIE\x10\x1a\x12\r\n\tC4_T6_DIE\x10\x1b\x12\r\n\tC4_T7_TAE\x10\x1c\x12\r\n\tC5_T1_OVF\x10\x1d\x12\x0e\n\nC5_T2_SOVF\x10\x1e\x12\n\n\x06\x43\x36_SYS\x10\x1f\x12\r\n\tC7_T0_NMI\x10 b\x06proto3')

_TRAPTYPE = DESCRIPTOR.enum_types_by_name['TrapType']
TrapType = enum_type_wrapper.EnumTypeWrapper(_TRAPTYPE)
UNKNOWN = 0
C0_T0_VAF = 1
C0_T1_VAP = 2
C1_T1_PRIV = 3
C1_T2_MPR = 4
C1_T3_MPW = 5
C1_T4_MPX = 6
C1_T5_MPP = 7
C1_T6_MPN = 8
C1_T7_GRWP = 9
C2_T1_IOPC = 10
C2_T2_UOPC = 11
C2_T3_OPD = 12
C2_T4_ALN = 13
C2_T5_MEM = 14
C3_T1_FCD = 15
C3_T2_CDO = 16
C3_T3_CDU = 17
C3_T4_FCU = 18
C3_T5_CSU = 19
C3_T6_CTYP = 20
C3_T7_NEST = 21
C4_T1_PSE = 22
C4_T2_DSE = 23
C4_T3_DAE = 24
C4_T4_CAE = 25
C4_T5_PIE = 26
C4_T6_DIE = 27
C4_T7_TAE = 28
C5_T1_OVF = 29
C5_T2_SOVF = 30
C6_SYS = 31
C7_T0_NMI = 32


_TRAPINFO = DESCRIPTOR.message_types_by_name['TrapInfo']
_CSA = DESCRIPTOR.message_types_by_name['Csa']
_COREDUMP = DESCRIPTOR.message_types_by_name['CoreDump']
_COREDUMP_CFSR = _COREDUMP.nested_types_by_name['Cfsr']
_EXCDEFAULT = DESCRIPTOR.message_types_by_name['ExcDefault']
TrapInfo = _reflection.GeneratedProtocolMessageType('TrapInfo', (_message.Message,), {
  'DESCRIPTOR' : _TRAPINFO,
  '__module__' : 'exc_pb2'
  # @@protoc_insertion_point(class_scope:TrapInfo)
  })
_sym_db.RegisterMessage(TrapInfo)

Csa = _reflection.GeneratedProtocolMessageType('Csa', (_message.Message,), {
  'DESCRIPTOR' : _CSA,
  '__module__' : 'exc_pb2'
  # @@protoc_insertion_point(class_scope:Csa)
  })
_sym_db.RegisterMessage(Csa)

CoreDump = _reflection.GeneratedProtocolMessageType('CoreDump', (_message.Message,), {

  'Cfsr' : _reflection.GeneratedProtocolMessageType('Cfsr', (_message.Message,), {
    'DESCRIPTOR' : _COREDUMP_CFSR,
    '__module__' : 'exc_pb2'
    # @@protoc_insertion_point(class_scope:CoreDump.Cfsr)
    })
  ,
  'DESCRIPTOR' : _COREDUMP,
  '__module__' : 'exc_pb2'
  # @@protoc_insertion_point(class_scope:CoreDump)
  })
_sym_db.RegisterMessage(CoreDump)
_sym_db.RegisterMessage(CoreDump.Cfsr)

ExcDefault = _reflection.GeneratedProtocolMessageType('ExcDefault', (_message.Message,), {
  'DESCRIPTOR' : _EXCDEFAULT,
  '__module__' : 'exc_pb2'
  # @@protoc_insertion_point(class_scope:ExcDefault)
  })
_sym_db.RegisterMessage(ExcDefault)

if _descriptor._USE_C_DESCRIPTORS == False:

  DESCRIPTOR._options = None
  _TRAPTYPE._serialized_start=582
  _TRAPTYPE._serialized_end=1089
  _TRAPINFO._serialized_start=13
  _TRAPINFO._serialized_end=86
  _CSA._serialized_start=88
  _CSA._serialized_end=126
  _COREDUMP._serialized_start=129
  _COREDUMP._serialized_end=420
  _COREDUMP_CFSR._serialized_start=202
  _COREDUMP_CFSR._serialized_end=420
  _EXCDEFAULT._serialized_start=423
  _EXCDEFAULT._serialized_end=579
# @@protoc_insertion_point(module_scope)