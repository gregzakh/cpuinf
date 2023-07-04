# -*- coding: utf-8 -*-
__all__ = ['getfrequency', 'getmodel', 'getvendor']

from common import *
from ctypes import CFUNCTYPE, POINTER, addressof, c_uint32, c_void_p
from mmap   import PROT_EXEC, PROT_READ, PROT_WRITE, mmap
from re     import compile

class CPUID(object):
   def __init__(self):
      self.memo = mmap(-1, len(opcodes), prot=PROT_EXEC | PROT_READ | PROT_WRITE)
      self.memo.write(opcodes)
      self.addr = c_void_p.from_buffer(self.memo)
      self.func = CFUNCTYPE(None, POINTER(CPUID_LEAF), c_uint32)
   def __call__(self, lp):
      self.func(addressof(self.addr))((block := CPUID_LEAF()), lp)
      return block
   def __del__(self):
      del self.addr
      self.memo.close()

def read_cpuinfo(v : str) -> str:
   with open('/proc/cpuinfo', 'r') as f:
      res = ''.join(filter( # looking for among unique strings
         lambda x: compile(f'(?i:{v})').match(x), set(f.readlines())
      )).split(':')[1].strip()
   return res

def getfrequency():
   print(read_cpuinfo('cpu mhz'))

def getmodel():
   try:
      print(cmnmodel(CPUID()))
   except Exception:
      print(read_cpuinfo('model name'))

def getvendor():
   try:
      print(cmnvendor(CPUID()(0)))
   except Exception:
      print(read_cpuinfo('vendor_id'))
