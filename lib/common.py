# -*- coding: utf-8 -*-
__all__ = ['CPUID_LEAF', 'CStruct', 'cmnmodel', 'cmnvendor', 'opcodes', 'sizeof']

from ctypes import Structure, c_uint32, sizeof
from os     import name
from struct import pack
from sys    import maxsize

class CStruct(Structure):
   @property
   def raw(self):
      return [getattr(self, x) for x, _ in self._fields_]
   @property
   def size(self):
      return sizeof(self)

class CPUID_LEAF(CStruct):
   _fields_ = [(x, c_uint32) for x in ('eax', 'ebx', 'ecx', 'edx')]

opcodes = bytes(([
   0x53,                           # push  rbx
   0x89, 0xd0,                     # mov   eax, edx
   0x49, 0x89, 0xc9,               # mov   r9,  rcx
   0x44, 0x89, 0xc1,               # mov   ecx, r8d
   0x0f, 0xa2,                     # cpuid
   0x41, 0x89, 0x01,               # mov   dword ptr [r9],      eax
   0x41, 0x89, 0x59, 0x04,         # mov   dword ptr [r9 +  4], ebx
   0x41, 0x89, 0x49, 0x08,         # mov   dword ptr [r9 +  8], ecx
   0x41, 0x89, 0x51, 0x0c,         # mov   dword ptr [r9 + 12], edx
   0x5b,                           # pop   rbx
   0xc3                            # ret
] if 'nt' == name else [
   0x53,                           # push  rbx
   0x89, 0xf0,                     # mov   eax, esi
   0x89, 0xd1,                     # mov   ecx, edx
   0x0f, 0xa2,                     # cpuid
   0x89, 0x07,                     # mov   dword ptr [rdi],      eax
   0x89, 0x5f, 0x04,               # mov   dword ptr [rdi +  4], ebx
   0x89, 0x4f, 0x08,               # mov   dword ptr [rdi +  8], ecx
   0x89, 0x57, 0x0c,               # mov   dword ptr [rdi + 12], edx
   0x5b,                           # pop   rbx
   0xc3                            # ret
]) if maxsize > 2**32 else [
   0x53,                           # push  ebx
   0x57,                           # push  edi
   0x8b, 0x7c, 0x24, 0x0c,         # mov   edi, dword ptr [esp + 12]
   0x8b, 0x44, 0x24, 0x10,         # mov   eax, dword ptr [esp + 16]
   0x8b, 0x4c, 0x24, 0x14,         # mov   ecx, dword ptr [esp + 20]
   0x0f, 0xa2,                     # cpuid
   0x89, 0x07,                     # mov   dword ptr [edi], eax
   0x89, 0x5f, 0x04,               # mov   dword ptr [edi +  4], ebx
   0x89, 0x4f, 0x08,               # mov   dword ptr [edi +  8], ecx
   0x89, 0x57, 0x0c,               # mov   dword ptr [edi + 12], edx
   0x5f,                           # pop   edi
   0x5b,                           # pop   ebx
   0xc3                            # ret
])
#
# def cmnmodel(c : CPUID) -> str
#
def cmnmodel(c):
   return ''.join([
      pack(
         'IIII', *c(0x80000000 + i).raw
      ).decode('utf-8') for i in range(2, 5)
   ]).strip()
#
# def cmnvendor(c : CPUID_LEAF, hv : bool) -> str
#
def cmnvendor(c, hv):
   raw = c.raw[1:]
   if not hv:
      raw[1], raw[2] = raw[2], raw[1]
   return pack('III', *raw).decode('utf-8')
