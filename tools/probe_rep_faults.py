"""Measure repeat-comparison fault FLAGS using fixed native calibration cases."""
import ctypes as C
import json
from pathlib import Path
import subprocess
import sys
import tempfile
ROOT=Path(__file__).resolve().parents[1]
with tempfile.TemporaryDirectory(prefix='zvril-rep-profile-') as temporary:
 d=Path(temporary);asm=d/'probe.S';source=['.text'];forms=[]
 for prefix in ['repe','repne']:
  for stem in ['cmps','scas']:
   for suffix,width in [('b',1),('w',2),('l',4),('q',8)]:
    name=f'{prefix}_{stem}{suffix}';forms.append((name,prefix,stem,width))
    source.append(f'''
.globl {name}
.type {name},@function
{name}:
 push %rbx
 mov %r9,%rbx
 mov %rcx,%rax
 mov %rdx,%rcx
 test %r8,%r8
 jz 1f
 std
 jmp 2f
1: cld
2: mov $16,%r10
 cmp $1,%r10
 pushfq
 pop %r10
 mov %r10,40(%rbx)
 {prefix} {stem}{suffix}
 pushfq
 pop %r10
 mov %r10,32(%rbx)
 cld
 pop %rbx
 ret
.size {name},.-{name}
''')
 source.append('.section .note.GNU-stack,"",@progbits');asm.write_text('\n'.join(source))
 so=d/'probe.so';subprocess.run(['cc','-shared','-fPIC',asm,ROOT/'tests/fixtures/string_oracle.c','-o',so],check=True)
 native=C.CDLL(str(so));oracle=native.string_oracle
 oracle.argtypes=[C.c_void_p,C.c_void_p,C.c_void_p,C.c_uint64,C.c_uint64,C.c_uint64,C.POINTER(C.c_uint64)];oracle.restype=C.c_int
 libc=C.CDLL(None);libc.mmap.argtypes=[C.c_void_p,C.c_size_t,C.c_int,C.c_int,C.c_int,C.c_long];libc.mmap.restype=C.c_void_p
 libc.mprotect.argtypes=[C.c_void_p,C.c_size_t,C.c_int];libc.munmap.argtypes=[C.c_void_p,C.c_size_t]
 rows=[];profile={'repe':set(),'repne':set()};mask=0xcd5
 for name,prefix,stem,width in forms:
  for backward in [0,1]:
   mapping=libc.mmap(None,12288,3,0x22,-1,0);assert mapping and mapping!=C.c_void_p(-1).value
   assert libc.mprotect(mapping,4096,0)==0 and libc.mprotect(mapping+8192,4096,0)==0
   base=mapping+4096;C.memset(base,0x31,4096)
   edge=2*width if backward else 4096-3*width
   src=base+edge if stem=='cmps' else base+512;dst=base+1024 if stem=='cmps' else base+edge
   if stem=='cmps' and prefix=='repne':C.memset(base+512,0x32,1024)
   acc=0x3232323232323232 if stem=='scas' and prefix=='repne' else 0x3131313131313131
   before=(C.c_uint64*8)();after=(C.c_uint64*8)()
   fn=C.cast(getattr(native,name),C.c_void_p)
   assert oracle(fn,dst,src,3,acc,backward,before)==0
   assert oracle(fn,dst,src,8,acc,backward,after)==11
   initial=after[5]&mask;progress=before[4]&mask;fault=after[4]&mask
   assert initial!=progress,(name,initial,progress)
   mode='initial' if fault==initial else 'progress' if fault==progress else 'other'
   profile[prefix].add(mode);rows.append({'instruction':name,'backward':backward,'initial':hex(initial),'completed':hex(progress),'fault':hex(fault),'mode':mode})
   libc.munmap(mapping,12288)
 record={'profile':{key:sorted(value) for key,value in profile.items()},'cases':rows}
 print(json.dumps(record,indent=2))
 if len(sys.argv)>1:Path(sys.argv[1]).write_text(json.dumps(record,indent=2)+'\n')
