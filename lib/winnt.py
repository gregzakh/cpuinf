# -*- coding: utf-8 -*-
__all__ = ['getcache', 'getfrequency', 'gethypervisor', 'getmodel', 'getvendor']

from common import *
from ctypes import (
   CFUNCTYPE, FormatError, GetLastError, POINTER, Union, byref, cast, c_byte, c_long, c_size_t, c_ulong,
   c_ulonglong, c_ushort, c_void_p, create_string_buffer, create_unicode_buffer, memmove, windll
)
from enum   import IntEnum
from sys    import stderr
from winreg import (
   HKEY_LOCAL_MACHINE as HKLM, CloseKey, EnumKey, OpenKeyEx, QueryInfoKey, QueryValueEx
)

MEM_COMMIT  = c_ulong(0x00001000).value
MEM_RESERVE = c_ulong(0x00002000).value
MEM_RELEASE = c_ulong(0x00008000).value
PAGE_EXECUTE_READWRITE = c_ulong(0x00000040).value

STATUS_INFO_LENGTH_MISMATCH = c_long(0xC0000004).value
STATUS_BUFFER_TOO_SMALL = c_long(0xC0000023).value

class PROCESSOR_POWER_INFORMATION(CStruct):
   _fields_ = [(x, c_ulong) for x in (
      'Number', 'MaxMhz', 'CurrentMhz', 'MhzLimit', 'MaxIdleState', 'CurrentIdleState'
   )]


class PROCESSORCORE(CStruct):
   _fields_ = [
      ('Flags', c_byte),
   ]


class NUMANODE(CStruct):
   _fields_ = [
      ('NodeNumber', c_ulong),
   ]


PROCESSOR_CACHE_TYPE = IntEnum('PROCESSOR_CACHE_TYPE', [
   'CacheUnified', 'CacheInstruction', 'CacheData', 'CacheTrace'
], start=0)


class CACHE_DESCRIPTOR(CStruct):
   _fields_ = [
      ('Level',         c_byte),
      ('Associativity', c_byte),
      ('LineSize',      c_ushort),
      ('Size',          c_ulong),
      ('_Type',         c_ulong),
   ]
   @property
   def Type(self):
      return PROCESSOR_CACHE_TYPE(self._Type).name


class SYSTEM_LOGICAL_PROCESSOR_INFORMATION_UNION(Union):
   _fields_ = [
      ('ProcessorCore', PROCESSORCORE),
      ('NumaNode',      NUMANODE),
      ('Cache',         CACHE_DESCRIPTOR),
      ('Reserved',      c_ulonglong * 2),
   ]


ULONG_PTR = c_ulonglong if maxsize > 2**32 else c_ulong
class SYSTEM_LOGICAL_PROCESSOR_INFORMATION(CStruct):
   _fields_ = [
      ('ProcessorMask', ULONG_PTR),
      ('Relashionship', ULONG_PTR),
      ('ProcessorInfo', SYSTEM_LOGICAL_PROCESSOR_INFORMATION_UNION),
   ]


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

NtPowerInformation       = windll.ntdll.NtPowerInformation
NtPowerInformation.restype = c_long # NTSTATUS
NtPowerInformation.argtypes = (
   c_ulong,  # POWER_INFORMATION_LEVEL
   c_void_p, # InputBuffer
   c_ulong,  # InputBufferLength
   c_void_p, # OutputBuffer
   c_ulong   # OutputBufferLength
)

NtQuerySystemInformation = windll.ntdll.NtQuerySystemInformation
NtQuerySystemInformation.restype = c_long # NTSTATUS
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


def getcache():
   # note that there is GetLogicalProcessorInformation in kernelbase.dll
   req = c_ulong(0) # SystemLogicalProcessorInformation = 0n73
   # check GetLastError value when using GetLogicalProcessorInformation:
   # if it's ERROR_INSUFFICIENT_BUFFER (0x0000007A) then allocate a buffer with required length
   # otherwise something's wrong and there's no way to complete the task (tada!..)
   if STATUS_INFO_LENGTH_MISMATCH != (nts := NtQuerySystemInformation(73, None, 0, byref(req))):
      print(FormatError(RtlNtStatusToDosError(nts)))
      return
   buf = create_string_buffer(req.value)
   if not NT_SUCCESS((nts := NtQuerySystemInformation(73, buf, len(buf), None))):
      print(FormatError(RtlNtStatusToDosError(nts)))
      return
   fmt = '{0.Type:<19}L{0.Level}: {1:5} KB, Assoc {0.Associativity:2}, LineSize {0.LineSize}'
   for x in cast(buf, POINTER(SYSTEM_LOGICAL_PROCESSOR_INFORMATION * (
                           len(buf) // sizeof(SYSTEM_LOGICAL_PROCESSOR_INFORMATION)))).contents:
      if 2 == x.Relashionship:
         print(fmt.format(( inf := x.ProcessorInfo.Cache), inf.Size // 1024))


def getfrequency():
   # print(read_registry('~MHz'))
   buf = create_string_buffer((sz := sizeof(PROCESSOR_POWER_INFORMATION)))
   while STATUS_BUFFER_TOO_SMALL == NtPowerInformation(11, None, 0, buf, len(buf)):
      buf = create_string_buffer(len(buf) * 2) # ProcessorInformation = 0n11
   arr = cast(buf, POINTER(PROCESSOR_POWER_INFORMATION * (len(buf) // sz)))
   print(next(iter(set(x.CurrentMhz for x in arr.contents))))


def gethypervisor():
   # there're also several classes for NtQuerySystemInformation marked with the word "hyper"
   # they all seem to be useful when detailed hypervisor information is needed
   data = CPUID() # bit 31 of ECX (leaf 1) points if the feature is present
   print(cmnvendor(data(0x40000000), True) if 1 == data(1).raw[2] >> 31 else 'Not presented.')


def getmodel():
   try:
      print(cmnmodel(CPUID()))
   except Exception:
      # print(read_registry('ProcessorNameString'))
      req = c_ulong(0) # SystemProcessorBrandString = 0n105
      if STATUS_INFO_LENGTH_MISMATCH != (nts := NtQuerySystemInformation(105, None, 0, byref(req))):
         print(FormatError(RtlNtStatusToDosError(nts)))
         return
      buf = create_unicode_buffer(req.value)
      if not NT_SUCCESS((nts := NtQuerySystemInformation(105, buf, len(buf), None))):
         print(FormatError(RtlNtStatusToDosError(nts)))
         return
      print(str(buf, 'utf-8').strip())


def getvendor():
   try:
      print(cmnvendor(CPUID()(0)))
   except Exception:
      print(read_registry('VendorIdentifier'))
