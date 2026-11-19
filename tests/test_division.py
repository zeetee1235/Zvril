"""Signed/unsigned DIV at all four widths, including native #DE state."""
import ctypes as C
import json
from pathlib import Path
import random
import signal
import struct
import subprocess
import sys
import tempfile
EXE,CC,CLANG,ROOT=Path(sys.argv[1]).resolve(),sys.argv[2],sys.argv[3],Path(sys.argv[4]).resolve()
BASE=0x10000000;SIZE=4096;SENTINEL=0xfffffffffffffff0;MASK=(1<<64)-1
class Memory(C.Structure):
 _fields_=[('data',C.c_void_p)]+[(n,C.c_uint64) for n in ['base','size','fault','fault_pc','fault_address','fault_width','steps_left','return_pc']]
def run(args):
 p=subprocess.run(list(map(str,args)),capture_output=True,text=True,timeout=60)
 assert p.returncode==0,(args,p.returncode,p.stdout,p.stderr)
 return p
with tempfile.TemporaryDirectory(prefix='zvril-divisions-') as temporary:
 d=Path(temporary);asm=d/'division.S';source=['.text'];forms=[]
 for signed in [False,True]:
  for bits,operand in [(8,'%cl'),(16,'%cx'),(32,'%ecx'),(64,'%rcx')]:
   name=('idiv' if signed else 'div')+str(bits);forms.append((name,signed,bits))
   source.append(f'''
.globl {name}
.type {name},@function
{name}:
 mov %rdx,%rcx
 mov %rdi,%rax
 mov %rsi,%rdx
 cmp %r8,%r8
 pushfq
 pop %r10
 mov %r10,40(%r9)
 {'idiv' if signed else 'div'} {operand}
 mov %rdx,0(%r9)
 mov %rdi,8(%r9)
 mov %rsi,16(%r9)
 mov %rax,24(%r9)
 pushfq
 pop %r10
 mov %r10,32(%r9)
 ret
.size {name},.-{name}
''')
 source.append('.section .note.GNU-stack,"",@progbits');asm.write_text('\n'.join(source))
 native_path=d/'native.so';run([CC,'-shared','-fPIC',asm,ROOT/'tests/fixtures/string_oracle.c','-o',native_path])
 native=C.CDLL(str(native_path));oracle=native.division_oracle;oracle.argtypes=[C.c_void_p,C.c_uint64,C.c_uint64,C.c_uint64,C.c_uint64,C.c_uint64,C.POINTER(C.c_uint64)]
 rng=random.Random(0x5a561d);comparisons=0;faults=0
 for name,signed,bits in forms:
  out=d/name;report=json.loads(run([EXE,'lift',native_path,'--symbol',name,'--out',out,'--json']).stdout);pc=int(report['lifting']['entry'],16)
  pcmap=json.loads((out/'pcmap.json').read_text())['instructions'];divpc=next(int(r['pc'],16) for r in pcmap if r['semantics'].startswith(('DIV_','IDIV_')))
  fn=C.cast(getattr(native,name),C.c_void_p).value
  mask=(1<<bits)-1
  def inputs(numerator,divisor):
   encoded=numerator & ((1<<(2*bits))-1)
   if bits==8:return ((rng.getrandbits(48)<<16)|encoded,rng.getrandbits(64),(rng.getrandbits(56)<<8)|(divisor&mask))
   low=(rng.getrandbits(64)&~mask)|(encoded&mask);high=(rng.getrandbits(64)&~mask)|((encoded>>bits)&mask)
   return low,high,(rng.getrandbits(64)&~mask)|(divisor&mask)
  cases=[]
  for i in range(1000):
   if signed:
    q=rng.randrange(-(1<<(bits-1)),1<<(bits-1));divisor=0
    while not divisor:divisor=rng.randrange(-(1<<(bits-1)),1<<(bits-1))
    numerator=q*divisor;remainder=rng.randrange(abs(divisor));numerator+=remainder if numerator>=0 else -remainder
   else:
    q=rng.randrange(1<<bits);divisor=rng.randrange(1,1<<bits);numerator=q*divisor+rng.randrange(divisor)
   cases.append(inputs(numerator,divisor))
  bad=[inputs(0,0),inputs((1<<(2*bits-1))-1,1)]
  if signed:bad.extend([inputs(-(1<<(2*bits-1)),-1),inputs(-(1<<(bits-1))-1,1),inputs(1<<(bits-1),1)])
  else:bad.extend([inputs(1<<bits,1),inputs((1<<(2*bits))-1,mask)])
  for level in [0,2]:
   shared=out/f'compiled-{level}.so';run([CLANG,f'-O{level}','-shared','-fPIC','-Wno-override-module',out/'module.bc','-o',shared]);lib=C.CDLL(str(shared))
   lib.zvril_state_size.restype=C.c_uint64;lib.zvril_state_set.argtypes=[C.c_void_p,C.c_uint32,C.c_uint64];lib.zvril_state_get.argtypes=[C.c_void_p,C.c_uint32];lib.zvril_state_get.restype=C.c_uint64
   lib.zvril_lifted.argtypes=[C.c_void_p,C.c_uint64,C.POINTER(Memory)]
   for exceptional,rows in [(False,cases),(True,bad)]:
    for low,high,divisor in rows:
     expected=(C.c_uint64*8)();code=oracle(fn,low,high,divisor,0,0,expected)
     assert code==(signal.SIGFPE if exceptional else 0),(name,low,high,divisor,exceptional,code)
     state=C.create_string_buffer(lib.zvril_state_size());memory_bytes=C.create_string_buffer(SIZE);struct.pack_into('<Q',memory_bytes,SIZE-8,SENTINEL)
     for reg,value in zip([7,6,2,1,8,9,4],[low,high,divisor,0,0,BASE,BASE+SIZE-8]):lib.zvril_state_set(state,reg,value)
     memory=Memory(C.addressof(memory_bytes),BASE,SIZE,0,0,0,0,1000,SENTINEL)
     lib.zvril_lifted(state,pc,C.byref(memory))
     assert memory.fault==(5 if exceptional else 0),(name,level,exceptional,memory.fault)
     assert lib.zvril_state_get(state,0)==expected[3] and lib.zvril_state_get(state,2)==expected[0],(name,level,exceptional,'RAX/RDX',low,high,divisor)
     if exceptional:
      assert memory.fault_pc==divpc and expected[7]==divpc-pc
      flags=sum(lib.zvril_state_get(state,reg)<<bit for reg,bit in [(17,4),(18,0),(19,10),(20,11),(21,2),(22,7),(23,6)])
      assert (flags^expected[4])&0xcd5==0,(name,'fault FLAGS')
      faults+=1
     else:comparisons+=1
 print(json.dumps({'forms':len(forms),'native_comparisons':comparisons,'native_divide_fault_state_comparisons':faults,'result_optimizations':[0,2]}))
