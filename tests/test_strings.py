"""Native REP element/progress/FLAGS comparison, including real page faults."""
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
BASE=0x10000000;SIZE=32768;MASK=(1<<64)-1;SENTINEL=0xfffffffffffffff0
FLAGS=[(17,4),(18,0),(19,10),(20,11),(21,2),(22,7),(23,6)]
class Memory(C.Structure):
 _fields_=[('data',C.c_void_p)]+[(n,C.c_uint64) for n in ['base','size','fault','fault_pc','fault_address','fault_width','steps_left','return_pc']]
def run(args):
 p=subprocess.run(list(map(str,args)),capture_output=True,text=True,timeout=60)
 assert p.returncode==0,(args,p.returncode,p.stdout,p.stderr)
 return p
class Lifted:
 def __init__(self,path):
  self.lib=C.CDLL(str(path));l=self.lib
  l.zvril_state_size.restype=C.c_uint64
  l.zvril_state_get.argtypes=[C.c_void_p,C.c_uint32];l.zvril_state_get.restype=C.c_uint64
  l.zvril_state_set.argtypes=[C.c_void_p,C.c_uint32,C.c_uint64]
  l.zvril_lifted.argtypes=[C.c_void_p,C.c_uint64,C.POINTER(Memory)]
  l.zvril_runtime_create.argtypes=[C.c_uint64,C.c_uint64];l.zvril_runtime_create.restype=C.c_void_p
  l.zvril_runtime_map.argtypes=[C.c_void_p,C.c_uint64,C.c_uint64,C.c_uint,C.c_void_p,C.c_uint64,C.c_int]
  l.zvril_runtime_read.argtypes=[C.c_void_p,C.c_uint64,C.c_void_p,C.c_uint64]
  l.zvril_runtime_clear_fault.argtypes=[C.c_void_p]
  l.zvril_runtime_status.argtypes=[C.c_void_p];l.zvril_runtime_status.restype=C.POINTER(Memory)
  l.zvril_runtime_destroy.argtypes=[C.c_void_p]
  l.zvril_runtime_set_rep_fault_flags.argtypes=[C.c_void_p,C.c_uint]
  l.zvril_lifted_v2.argtypes=[C.c_void_p,C.c_uint64,C.c_void_p]
 def state(self,args,sp):
  state=C.create_string_buffer(self.lib.zvril_state_size())
  for reg,value in zip([7,6,2,1,8,9],args):self.lib.zvril_state_set(state,reg,value)
  self.lib.zvril_state_set(state,4,sp)
  return state
 def flags(self,state):
  return sum(self.lib.zvril_state_get(state,reg)<<bit for reg,bit in FLAGS)

with tempfile.TemporaryDirectory(prefix='zvril-strings-') as temporary:
 d=Path(temporary);asm=d/'strings.S';forms=[];source=['.text']
 profile_path=d/'native-profile.json';run([sys.executable,ROOT/'tools/probe_rep_faults.py',profile_path])
 profile=json.loads(profile_path.read_text())['profile'];assert all(v in [['initial'],['progress']] for v in profile.values()),profile
 restore_mask=(1 if profile['repe']==['initial'] else 0)|(2 if profile['repne']==['initial'] else 0)
 for stem in ['movs','stos','lods','cmps','scas']:
  for suffix,width in [('b',1),('w',2),('l',4),('q',8)]:
   for repeat in (['repe','repne'] if stem in ['cmps','scas'] else ['rep']):
    name=f'{repeat}_{stem}{suffix}';forms.append((name,stem,repeat,width))
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
2: cmp $1,%r8
 pushfq
 pop %r10
 mov %r10,40(%rbx)
 {repeat} {stem}{suffix}
 mov %rcx,0(%rbx)
 mov %rdi,8(%rbx)
 mov %rsi,16(%rbx)
 mov %rax,24(%rbx)
 pushfq
 pop %rdx
 mov %rdx,32(%rbx)
 cld
 pop %rbx
 ret
.size {name},.-{name}
''')
 source.append('.globl rep_raw\n.type rep_raw,@function\nrep_raw: rep movsb\nret\n.size rep_raw,.-rep_raw')
 source.append('.section .note.GNU-stack,"",@progbits');asm.write_text('\n'.join(source))
 native_path=d/'native.so';run([CC,'-shared','-fPIC',asm,ROOT/'tests/fixtures/string_oracle.c','-o',native_path])
 native=C.CDLL(str(native_path));oracle=native.string_oracle
 oracle.argtypes=[C.c_void_p,C.c_void_p,C.c_void_p,C.c_uint64,C.c_uint64,C.c_uint64,C.POINTER(C.c_uint64)];oracle.restype=C.c_int
 libc=C.CDLL(None);libc.mmap.argtypes=[C.c_void_p,C.c_size_t,C.c_int,C.c_int,C.c_int,C.c_long];libc.mmap.restype=C.c_void_p
 libc.mprotect.argtypes=[C.c_void_p,C.c_size_t,C.c_int];libc.munmap.argtypes=[C.c_void_p,C.c_size_t]
 rng=random.Random(0x5a5615);compared=0;faults=0;budgeted=0;variants=0
 for name,stem,repeat,width in forms:
  output=d/name
  report=json.loads(run([EXE,'lift',native_path,'--symbol',name,'--out',output,'--json']).stdout)
  pc=int(report['lifting']['entry'],16)
  pcmap=json.loads((output/'pcmap.json').read_text())['instructions']
  rep_pc=next(int(i['pc'],16) for i in pcmap if i['semantics'].startswith(('REP_','REPE_','REPNE_')))
  fn=C.cast(getattr(native,name),C.c_void_p).value
  getattr(native,name).argtypes=[C.c_void_p,C.c_void_p,C.c_uint64,C.c_uint64,C.c_uint64,C.c_void_p]
  for optimization in [0,2]:
   so=output/f'lifted-o{optimization}.so';run([CLANG,f'-O{optimization}','-shared','-fPIC','-Wno-override-module',output/'module.bc','-o',so])
   lifted=Lifted(so);variants+=1
   for case in range(256):
    count=case%65;direction=(case//65)%2;acc=rng.getrandbits(64)
    data=bytearray(rng.randbytes(16384))+bytearray(SIZE-16384)
    src,dst=1024,8192
    if stem=='cmps':
     data[dst:dst+count*width]=data[src:src+count*width]
     if count and case%4: data[dst+((case%count)*width)]^=0x80
    if stem=='scas':
     data[dst:dst+count*width]=((acc & ((1<<(width*8))-1)).to_bytes(width,'little'))*count
     if count and case%4:data[dst+((case%count)*width)]^=0x80
    if direction:
     src+=max(count-1,0)*width;dst+=max(count-1,0)*width
    original=C.create_string_buffer(bytes(data));translated=C.create_string_buffer(bytes(data))
    expected=(C.c_uint64*8)()
    getattr(native,name)(C.addressof(original)+dst,C.addressof(original)+src,count,acc,direction,expected)
    sp=BASE+SIZE-8;struct.pack_into('<Q',translated,SIZE-8,SENTINEL)
    state=lifted.state([BASE+dst,BASE+src,count,acc,direction,BASE+20000],sp)
    memory=Memory(C.addressof(translated),BASE,SIZE,0,0,0,0,10000,SENTINEL)
    lifted.lib.zvril_lifted(state,pc,C.byref(memory))
    assert memory.fault==0,(name,optimization,case,memory.fault)
    observed=struct.unpack_from('<6Q',translated,20000)
    assert observed[0]==expected[0] and observed[3]==expected[3],(name,case,observed,list(expected))
    assert observed[1]-BASE==expected[1]-C.addressof(original),(name,case,'RDI')
    assert observed[2]-BASE==expected[2]-C.addressof(original),(name,case,'RSI')
    assert (observed[4]^expected[4])&0xcd5==0,(name,case,'FLAGS',hex(observed[4]),hex(expected[4]))
    assert translated.raw[:16384]==original.raw[:16384],(name,case,'memory')
    assert lifted.lib.zvril_state_get(state,19)==0
    compared+=1
   # Real native page faults after three committed elements. Independent guest
   # backing has the same mapped/hole layout; the native handler reads ucontext.
   for direction in [0,1]:
    mapping=libc.mmap(None,12288,3,0x22,-1,0);assert mapping not in [None,MASK]
    assert libc.mprotect(mapping,4096,0)==0 and libc.mprotect(mapping+8192,4096,0)==0
    base=mapping+4096
    data=bytearray([0x31]*4096);acc=0x3131313131313131
    src,dst=256,1024
    fault_offset=3*width if direction else 4096-3*width
    # backward starts three elements above the lower guard page.
    if direction:fault_offset=2*width
    if stem in ['movs','lods','cmps']:src=fault_offset
    else:dst=fault_offset
    if stem=='cmps' and repeat=='repne':data[dst-64:dst+64]=bytes([0x32])*128
    if stem=='scas' and repeat=='repne':acc=0x3232323232323232
    C.memmove(base,bytes(data),4096);expected=(C.c_uint64*8)()
    code=oracle(fn,base+dst,base+src,8,acc,direction,expected)
    assert code==signal.SIGSEGV,(name,direction,code)
    runtime=lifted.lib.zvril_runtime_create(1024*1024,10000);assert runtime
    assert lifted.lib.zvril_runtime_set_rep_fault_flags(runtime,restore_mask)
    initial=C.create_string_buffer(bytes(data))
    assert lifted.lib.zvril_runtime_map(runtime,BASE,4096,3,initial,4096,1)
    stack=BASE+0x10000;stack_data=C.create_string_buffer(bytes(56)+struct.pack('<Q',SENTINEL))
    assert lifted.lib.zvril_runtime_map(runtime,stack,64,3,stack_data,64,1)
    # v2 root sentinel is independent of the layout of its stack allocation.
    status=lifted.lib.zvril_runtime_status(runtime);status.contents.return_pc=SENTINEL
    state=lifted.state([BASE+dst,BASE+src,8,acc,direction,BASE+2048],stack+56)
    lifted.lib.zvril_lifted_v2(state,pc,runtime)
    fault=status.contents.fault
    assert fault==(2 if stem=='stos' else 1),(name,direction,fault)
    assert status.contents.fault_pc==rep_pc,(name,'fault_pc')
    regs=[lifted.lib.zvril_state_get(state,r) for r in [1,7,6,0]]
    assert regs[0]==expected[0]==5,(name,direction,'RCX',regs,list(expected))
    assert regs[1]-BASE==expected[1]-base and regs[2]-BASE==expected[2]-base,(name,direction,'indices',regs,list(expected))
    assert regs[3]==expected[3],(name,direction,'RAX')
    assert (lifted.flags(state)^expected[4])&0xcd5==0,(name,direction,'fault FLAGS',hex(lifted.flags(state)),hex(expected[4]),hex(expected[5]))
    lifted.lib.zvril_runtime_clear_fault(runtime);actual=C.create_string_buffer(4096)
    assert lifted.lib.zvril_runtime_read(runtime,BASE,actual,4096)
    # Both sides wrote their pre-instruction flags observation at different
    # locations, so compare the actual destination bytes only.
    if stem in ['movs','stos']:
     extent=3*width
     start=dst-2*width if direction else dst
     assert actual.raw[start:start+extent]==C.string_at(base+start,extent),(name,direction,'partial writes')
    lifted.lib.zvril_runtime_destroy(runtime);libc.munmap(mapping,12288);faults+=1
   # A malicious repeat count is interrupted by the guest step budget.
   if stem=='stos':
    translated=C.create_string_buffer(SIZE);struct.pack_into('<Q',translated,SIZE-8,SENTINEL)
    state=lifted.state([BASE+8192,BASE+1024,MASK,0x42,0,BASE+20000],BASE+SIZE-8)
    memory=Memory(C.addressof(translated),BASE,SIZE,0,0,0,0,32,SENTINEL)
    lifted.lib.zvril_lifted(state,pc,C.byref(memory))
    assert memory.fault==3 and memory.steps_left==0 and memory.fault_pc==rep_pc
    assert 0<lifted.lib.zvril_state_get(state,1)<MASK
    budgeted+=1
 # Zero count must not consume an unknown DF or access NULL pointers.
 output=d/'raw'
 report=json.loads(run([EXE,'lift',native_path,'--symbol','rep_raw','--out',output,'--json']).stdout)
 shared=output/'raw.so';run([CLANG,'-O2','-shared','-fPIC','-Wno-override-module',output/'module.bc','-o',shared]);raw=Lifted(shared)
 raw.lib.zvril_runtime_set_flags_valid.argtypes=[C.c_void_p,C.c_uint64]
 raw.lib.zvril_runtime_unknown_flags.argtypes=[C.c_void_p];raw.lib.zvril_runtime_unknown_flags.restype=C.c_uint64
 raw.lib.zvril_runtime_success.argtypes=[C.c_void_p]
 for count in [0,1]:
  rt=raw.lib.zvril_runtime_create(1024*1024,1000);raw.lib.zvril_runtime_set_flags_valid(rt,0)
  data=C.create_string_buffer(bytes(range(64)));stack=C.create_string_buffer(bytes(56)+struct.pack('<Q',SENTINEL))
  assert raw.lib.zvril_runtime_map(rt,BASE,64,3,data,64,1)
  assert raw.lib.zvril_runtime_map(rt,BASE+4096,64,3,stack,64,1)
  raw.lib.zvril_runtime_status(rt).contents.return_pc=SENTINEL
  state=raw.state([BASE+32 if count else 0,BASE if count else 0,0,count,0,0],BASE+4096+56)
  raw.lib.zvril_lifted_v2(state,int(report['lifting']['entry'],16),rt)
  assert raw.lib.zvril_runtime_status(rt).contents.fault==0
  assert raw.lib.zvril_runtime_unknown_flags(rt)==(0x400 if count else 0)
  assert raw.lib.zvril_runtime_success(rt)==(0 if count else 1)
  raw.lib.zvril_runtime_destroy(rt)
 print(json.dumps({'forms':len(forms),'compiled_variants':variants,'normal_comparisons':compared,'native_fault_state_comparisons':faults,'repeat_budget_cases':budgeted,'address_size':64,'unknown_df_cases':2}))
