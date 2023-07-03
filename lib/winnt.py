# -*- coding: utf-8 -*-
__all__ = ['getmodel', 'getvendor']

from common import *
from ctypes import (
   CFUNCTYPE, FormatError, GetLastError, POINTER, byref, c_long, c_size_t, c_ulong,
   c_void_p, create_unicode_buffer, memmove, windll
)
from sys    import stderr
from winreg import (
   HKEY_LOCAL_MACHINE as HKLM, CloseKey, EnumKey, OpenKeyEx, QueryInfoKey, QueryValueEx
)

MEM_COMMIT  = c_ulong(0x00001000).value
MEM_RESERVE = c_ulong(0x00002000).value
MEM_RELEASE = c_ulong(0x00008000).value
PAGE_EXECUTE_READWRITE = c_ulong(0x00000040).value

STATUS_INFO_LENGTH_MISMATCH = c_long(0xC0000004).value

VirtualAlloc = windll.kernelbase.VirtualAlloc
VirtualAlloc.restype = c_void_p # LPVOID
VirtualAlloc.argtypes = (
   c_void_p, # LPVOID lpAddress
   c_size_t, # SIZE_T dwSize
   c_ulong,  # DWORD  flAllocationType
   c_ulong   # DWORD  flProtect
)

VirtualFree  = windll.kernelbase.VirtualFree
VirtualFree.restype = c_long # BOOL
VirtualFree.argtypes = (
   c_void_p, # LPVOID lpAddress
   c_size_t, # SIZE_T dwSize
   c_ulong   # DWORD  dwFreeType
)

NtQuerySystemInformation = windll.ntdll.NtQuerySystemInformation
NtQuerySystemInformation.restype = c_long
NtQuerySystemInformation.argtypes = (
   c_ulong,  # SYSTEM_INFORMATION_CLASS
   c_void_p, # SystemInformation
   c_ulong,  # SystemInformationLength
   POINTER(c_ulong), # ReturnLength
)

RtlNtStatusToDosError    = windll.ntdll.RtlNtStatusToDosError
RtlNtStatusToDosError.restype = c_ulong
RtlNtStatusToDosError.argtype = c_long # NTSTATUS

def NT_SUCCESS(Status):
   return Status >= 0

class CPUID(object):
   def __init__(self):
      sz = len(opcodes)
      self.addr = VirtualAlloc(None, sz, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)
      if not self.addr:
         raise OSError(FormatError(GetLastError()))
      memmove(self.addr, opcodes, sz)
      self.func = CFUNCTYPE(None, POINTER(CPUID_LEAF), c_ulong)(self.addr)
   def __call__(self, lp):
       self.func((block := CPUID_LEAF()), lp)
       return block
   def __del__(self):
      if not VirtualFree(self.addr, 0, MEM_RELEASE):
         print(FormatError(GetLastError()), file=stderr)

def read_registry(v : str) -> str:
   res, inf = [], r'HARDWARE\DESCRIPTION\System\CentralProcessor'
   with OpenKeyEx(HKLM, inf) as key:
      for x in range(QueryInfoKey(key)[0]):
         with OpenKeyEx(HKLM, f'{inf}\\{EnumKey(key, x)}') as cur:
            res.append(QueryValueEx(cur, v)[0])
         CloseKey(cur) # prevent leak
   CloseKey(key)
   return next(iter(set(res)))

def getmodel():
   try:
      print(cmnmodel(CPUID()))
   except Exception:
      # print(read_registry('ProcessorNameString'))
      req = c_ulong(0) # SystemProcessorBrandString = 0n105
      nts = NtQuerySystemInformation(105, None, 0, byref(req))
      if STATUS_INFO_LENGTH_MISMATCH != nts or 0 == req.value:
         print(FormatError(RtlNtStatusToDosError(nts)))
         return
      buf = create_unicode_buffer(req.value)
      nts = NtQuerySystemInformation(105, buf, len(buf), None)
      if not NT_SUCCESS(nts):
         print(FormatError(RtlNtStatusToDosError(nts)))
         return
      print(str(buf, 'utf-8').strip())

def getvendor():
   try:
      print(cmnvendor(CPUID()(0)))
   except Exception:
      print(read_registry('VendorIdentifier'))
