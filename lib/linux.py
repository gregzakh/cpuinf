# -*- coding: utf-8 -*-
__all__ = ['getcache', 'getfrequency', 'gethypervisor', 'getmodel', 'getvendor']

from common  import *
from ctypes  import CDLL, CFUNCTYPE, POINTER, addressof, c_uint32, c_void_p
from glob    import glob
from mmap    import PROT_EXEC, PROT_READ, PROT_WRITE, mmap
from os.path import basename
from re      import compile

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


def read_cpucache(v : int) -> None:
   targets = ['type', 'level', 'size', 'ways_of_associativity', 'coherency_line_size']
   unitinf = dict(zip(iter(targets), iter([''] * len(targets))))
   for index in sorted(glob(f'/sys/devices/system/cpu/cpu{v}/cache/index[0-9]/')):
      for target in glob(f'{index}*'):
         if (bn := basename(target)) in targets:
            with open(target) as file:
               unitinf[bn] = file.readline().strip()
      print(unitinf)
      # unitinf.fromkeys(unitinf, '')


def read_cpuinfo(v : str) -> str:
   with open('/proc/cpuinfo', 'r') as f:
      res = ''.join(filter( # looking for among unique strings
         lambda x: compile(f'(?i:{v})').match(x), set(f.readlines())
      )).split(':')[1].strip()
   return res


def getcache():
   libc = CDLL('libc.so.6')
   data = list(zip( # read_cpucache (see above) returns more pretty data
      ['L1', 'L1', 'L2', 'L3', 'L4'],
      [tuple(libc.sysconf(x) for x in range(i, i + 3)) for i in range(185, 200, 3)]
   ))
   fmt = '\r{0[0]}: {1:5} KB, Assoc {0[1][1]:2}, LineSize {0[1][2]}\n'
   print(*[fmt.format(x, x[1][0] // 1024) for x in data if x[1][0] > 0])


def getfrequency():
   print(read_cpuinfo('cpu mhz'))


def gethypervisor():
   data = CPUID() # bit 31 of ECX (leaf 1) points if the feature is present
   print(cmnvendor(data(0x40000000), True) if 1 == data(1).raw[2] >> 31 else 'Not presented.')


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
