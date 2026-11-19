"""Compiler-produced indirect transfers, relocation formats and ABI cases."""
import json
from pathlib import Path
import random
import shutil
import struct
import subprocess
import sys
import tempfile

EXE,CC,CLANG,ROOT=Path(sys.argv[1]).resolve(),sys.argv[2],sys.argv[3],Path(sys.argv[4]).resolve()
def cli(*args,expected=0):
 p=subprocess.run([str(EXE),*map(str,args),'--json'],capture_output=True,text=True,timeout=45)
 assert p.returncode==expected,(args,p.returncode,p.stdout,p.stderr)
 assert not p.stderr,p.stderr
 return json.loads(p.stdout)
with tempfile.TemporaryDirectory(prefix='zvril-expansion-') as temporary:
 d=Path(temporary);rng=random.Random(746)
 cases=d/'switch.json';cases.write_text(json.dumps({'signature':{'return':'u64','arguments':['u32','u64']},'cases':[
  {'arguments':[i%12,rng.randrange(100000)]} for i in range(120)]+[{'arguments':[0xffffffff,42]}]}))
 evidence=0;total=0
 compilers=list(dict.fromkeys([CC,CLANG]))
 for number,compiler in enumerate(compilers):
  for opt in [1,2,3]:
   native=d/f'switch-{number}-{opt}.so'
   subprocess.run([compiler,'-x','c','-shared','-fPIC',f'-O{opt}',str(ROOT/'tests/fixtures/switch.c'),'-o',str(native)],check=True)
   r=cli('verify',native,'--symbol','program_switch','--cases',cases,'--allow-exec','--out',d/f'output-{number}-{opt}')
   assert r['validation']['passed']==121
   evidence+=len(r['lifting']['indirect_resolution']);total+=121
 # Marking a table's segment writable must invalidate the immutable-table proof.
 native=d/'switch-0-2.so';modified=bytearray(native.read_bytes())
 phoff=struct.unpack_from('<Q',modified,32)[0];count=struct.unpack_from('<H',modified,56)[0]
 for i in range(count):
  at=phoff+i*56;kind,flags=struct.unpack_from('<II',modified,at)
  if kind==1 and flags==4:struct.pack_into('<I',modified,at+4,6)
 mutable=d/'mutable.so';mutable.write_bytes(modified)
 blocked=cli('lift',mutable,'--symbol','program_switch','--out',d/'mutable-out',expected=1)
 assert blocked['status']=='BLOCKED' and blocked['diagnostics'][-1]['code']=='E_UNRESOLVED_EDGE'

 # A branch that bypasses the CMP/JA guard invalidates a finite table proof.
 bypass=d/'bypass.S';bypass.write_text("""
.text
.globl bypass_switch
.type bypass_switch,@function
bypass_switch:
 test %esi,%esi
 jne .Ltable
 cmp $1,%edi
 ja .Lout
.Ltable:
 lea .Ldata(%rip),%rdx
 movslq (%rdx,%rdi,4),%rax
 add %rdx,%rax
 jmp *%rax
.Lone:
 mov $1,%eax
 ret
.Ltwo:
 mov $2,%eax
 ret
.Lout:
 xor %eax,%eax
 ret
.size bypass_switch,.-bypass_switch
.section .rodata
.align 4
.Ldata:
.long .Lone-.Ldata,.Ltwo-.Ldata
.section .note.GNU-stack,"",@progbits
""")
 bypass_so=d/'bypass.so';subprocess.run([CC,'-shared','-fPIC',str(bypass),'-o',str(bypass_so)],check=True)
 blocked=cli('lift',bypass_so,'--symbol','bypass_switch','--out',d/'bypass-out',expected=1)
 assert blocked['diagnostics'][-1]['code']=='E_UNRESOLVED_EDGE',blocked
 # TLSDESC's special calling convention uses RAX and preserves other GPRs.
 tls=d/'tls.c';tls.write_text('#include <stdint.h>\n__thread volatile uint64_t v=7;uint64_t tlsdesc_test(uint64_t x){v+=x;return v;}\n')
 tls_so=d/'tls.so';subprocess.run([CC,'-shared','-fPIC','-O1','-mtls-dialect=gnu2',str(tls),'-o',str(tls_so)],check=True)
 tls_cases=d/'tls.json';tls_cases.write_text(json.dumps({'signature':{'return':'u64','arguments':['u64']},'cases':[{'arguments':[x]} for x in [0,1,0xfffffffffffffff9]]}))
 tls_result=cli('verify',tls_so,'--symbol','tlsdesc_test','--cases',tls_cases,'--allow-exec','--out',d/'tls-out')
 assert tls_result['validation']['passed']==3
 # Negative RELR metadata cases must fail during parsing, before IR output.
 rel=d/'rel.c';rel.write_text('static unsigned long x=7; static unsigned long * volatile p[16]={' + ','.join(['&x']*16) + '};unsigned long reltest(unsigned long i){return *p[i&15];}\n')
 rel_so=d/'rel.so';subprocess.run([CC,'-shared','-fPIC','-O1','-Wl,-z,pack-relative-relocs',str(rel),'-o',str(rel_so)],check=True)
 data=bytearray(rel_so.read_bytes());phoff=struct.unpack_from('<Q',data,32)[0];phnum=struct.unpack_from('<H',data,56)[0]
 segments=[];tags={}
 for i in range(phnum):
  at=phoff+i*56;kind=struct.unpack_from('<I',data,at)[0];off,va=struct.unpack_from('<QQ',data,at+8);size=struct.unpack_from('<Q',data,at+32)[0]
  if kind==1:segments.append((off,va,size))
  if kind==2:
   for q in range(off,off+size,16):
    tag,val=struct.unpack_from('<qQ',data,q)
    if not tag:break
    tags[tag]=(q,val)
 assert 36 in tags and 35 in tags and 37 in tags,tags
 relva=tags[36][1];reloff=next(off+relva-va for off,va,size in segments if va<=relva<va+size)
 for name,modify in [
  ('entry-size',lambda b:struct.pack_into('<Q',b,tags[37][0]+8,4)),
  ('unanchored',lambda b:struct.pack_into('<Q',b,reloff,3)),
  ('duplicate',lambda b:struct.pack_into('<Q',b,reloff+8,struct.unpack_from('<Q',b,reloff)[0])),
 ]:
  bad=bytearray(data);modify(bad);path=d/(name+'.so');path.write_bytes(bad)
  result=cli('inspect',path,expected=3)
  assert result['diagnostics'][-1]['code']=='E_ELF_INVALID',result
 # Whole-lift limits must apply before any stale module can be reused.
 budget=d/'budget-out'
 cli('lift',native,'--symbol','program_switch','--out',budget)
 for flag,value in [('--timeout-ms',1),('--memory-mb',1),('--max-functions',1),('--max-blocks',1)]:
  limited=cli('lift',native,'--symbol','program_switch','--out',budget,flag,value,expected=1)
  assert limited['status']=='BLOCKED' and limited['diagnostics'][-1]['code']=='E_RESOURCE_LIMIT',limited
  assert not (budget/'module.bc').exists() and not (budget/'module.ll').exists()
  assert not any(x.name.startswith('.zvril-stage') for x in budget.iterdir())

 # A hidden, stripped callee without unwind metadata remains a candidate with
 # unknown bounds, never an invented complete function.
 discover=d/'discover.S';discover.write_text("""
.text
.globl visible_root
.type visible_root,@function
visible_root:
 call hidden_leaf
 ret
.size visible_root,.-visible_root
.hidden hidden_leaf
.globl hidden_leaf
.type hidden_leaf,@function
hidden_leaf:
 mov $42,%rax
 ret
.size hidden_leaf,.-hidden_leaf
.section .note.GNU-stack,"",@progbits
""")
 discovered_so=d/'discover.so';subprocess.run([CC,'-shared','-fPIC','-nostdlib','-s',str(discover),'-o',str(discovered_so)],check=True)
 metadata=cli('inspect',discovered_so)
 assert all(not f['name'].startswith('call_') for f in metadata['functions'])
 discovered=cli('inspect',discovered_so,'--discover-calls')
 candidates=[f for f in discovered['functions'] if f['name'].startswith('call_')]
 assert len(candidates)==1 and candidates[0]['confidence']=='call_target_only' and not candidates[0]['boundary_known'],discovered
 assert discovered['code_discovery']['new_call_candidates']==1
 bounded=cli('functions',discovered_so,'--discover-calls','--max-instructions',1,expected=1)
 assert bounded['diagnostics'][-1]['code']=='E_RESOURCE_LIMIT'
 # Real ptrace comparison is optional on restricted kernels. Failure must be
 # explicit; it cannot silently degrade into result-only verification.
 trace_case=d/'trace.json';trace_case.write_text(json.dumps({'signature':{'return':'u64','arguments':['u32','u64']},'cases':[{'arguments':[0,42]}]}))
 p=subprocess.run([str(EXE),'verify',str(native),'--symbol','program_switch','--cases',str(trace_case),'--native-trace','--allow-exec','--out',str(d/'trace-out'),'--json'],capture_output=True,text=True,timeout=40)
 trace=json.loads(p.stdout)
 if p.returncode==1:
  assert trace['diagnostics'][-1]['code']=='E_TRACE_UNAVAILABLE',trace
  trace_status='kernel_denied'
 else:
  assert p.returncode==0,(p.returncode,trace,p.stderr)
  assert trace['validation']['records'][0]['trace_comparison']['status']=='PASS',trace
  trace_status='PASS'
 assert evidence>=2
 print(json.dumps({'switch_comparisons':total,'proven_tables':evidence,'mutable_table_rejected':True,'guard_bypass_rejected':True,'tlsdesc_comparisons':3,'malformed_relr_rejected':3,'whole_lift_limits':4,'native_trace':trace_status,'stripped_direct_call_candidate':True}))
