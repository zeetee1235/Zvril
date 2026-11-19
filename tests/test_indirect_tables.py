import ctypes as C
import json
from pathlib import Path
import random
import subprocess
import sys
import tempfile

EXE,CC,CLANG,ROOT=Path(sys.argv[1]).resolve(),sys.argv[2],sys.argv[3],Path(sys.argv[4]).resolve()
def run(args,code=0):
 p=subprocess.run(list(map(str,args)),capture_output=True,text=True,timeout=60)
 assert p.returncode==code,(args,p.returncode,p.stdout,p.stderr)
 return p
with tempfile.TemporaryDirectory(prefix='zvril-function-table-') as temporary:
 d=Path(temporary);source=ROOT/'tests/fixtures/indirect_tables.S';native=d/'native.so'
 run([CC,'-shared','-fPIC',source,'-o',native]);original=C.CDLL(str(native))
 comparisons=0;proofs=0
 for name in ['table_tail','table_call']:
  abi=d/(name+'.json');abi.write_text(json.dumps({'return':'u64','arguments':['u32','u64']}))
  output=d/name
  report=json.loads(run([EXE,'lift',native,'--symbol',name,'--abi',abi,'--out',output,'--json']).stdout)
  proof=report['lifting']['indirect_resolution'][0]
  assert len(proof['targets'])==3 and len(proof['relocation_backed_reads'])==3 and proof['transfer_operand']=='memory',proof
  assert len(report['functions'])==4,report['functions']
  proofs+=1
  fn=getattr(original,name);fn.argtypes=[C.c_uint32,C.c_uint64];fn.restype=C.c_uint64
  for level in [0,2]:
   shared=output/f'lifted-{level}.so';run([CLANG,f'-O{level}','-shared','-fPIC','-Wno-override-module',output/'module.bc','-o',shared]);lifted=C.CDLL(str(shared))
   lifted.zvril_runtime_create.argtypes=[C.c_uint64,C.c_uint64];lifted.zvril_runtime_create.restype=C.c_void_p
   lifted.zvril_init_image.argtypes=[C.c_void_p,C.c_uint64]
   lifted.zvril_typed.argtypes=[C.c_void_p,C.c_uint32,C.c_uint64];lifted.zvril_typed.restype=C.c_uint64
   lifted.zvril_runtime_success.argtypes=[C.c_void_p]
   lifted.zvril_runtime_destroy.argtypes=[C.c_void_p]
   runtime=lifted.zvril_runtime_create(1024*1024,1000000)
   assert runtime and lifted.zvril_init_image(runtime,0x4000000000)==1
   rng=random.Random(1252)
   for i in range(1500):
    index=i%7 if i<1499 else 0xffffffff;value=rng.getrandbits(64)
    assert lifted.zvril_typed(runtime,index,value)==fn(index,value),(name,index,value)
    assert lifted.zvril_runtime_success(runtime)==1
    comparisons+=1
   lifted.zvril_runtime_destroy(runtime)
 mutable=d/'mutable.so';run([CC,'-shared','-fPIC','-DMUTABLE_TABLE',source,'-o',mutable])
 blocked=json.loads(run([EXE,'lift',mutable,'--symbol','table_tail','--out',d/'mutable','--json'],1).stdout)
 assert blocked['diagnostics'][-1]['code']=='E_UNRESOLVED_EDGE'
 print(json.dumps({'native_comparisons':comparisons,'relocation_proofs':proofs,'mutable_table_rejected':True}))
