import ctypes as C
import json
from pathlib import Path
import random
import subprocess
import sys
import tempfile
EXE,CC,CLANG,ROOT=Path(sys.argv[1]).resolve(),sys.argv[2],sys.argv[3],Path(sys.argv[4]).resolve()
T={'u8':C.c_uint8,'i8':C.c_int8,'u16':C.c_uint16,'i16':C.c_int16,'u32':C.c_uint32,'i32':C.c_int32,'u64':C.c_uint64,'i64':C.c_int64}
def run(args,code=0):
 p=subprocess.run(list(map(str,args)),capture_output=True,text=True,timeout=60)
 assert p.returncode==code,(args,p.returncode,p.stdout,p.stderr)
 return p
with tempfile.TemporaryDirectory(prefix='zvril-narrow-') as temporary:
 d=Path(temporary);comparisons=0;verified=0;wrappers=0
 specs=[('narrow_u8','u8',['u8']),('narrow_i8','i8',['i64']),('narrow_u16','u16',['u16']),('narrow_i16','i16',['i64']),
        ('narrow_args','i64',['i8','i16','u8','u16']),('narrow_stack','i64',['i8','i16','u8','u16','i8','i16','i8','i16','u16']),
        ('narrow_variadic','i64',['u8','i32','i32','i32'])]
 for compiler_index,compiler in enumerate(dict.fromkeys([CC,CLANG])):
  original_path=d/f'original-{compiler_index}.so';run([compiler,'-x','c','-shared','-fPIC','-O2',ROOT/'tests/fixtures/narrow.c','-o',original_path]);original=C.CDLL(str(original_path))
  for name,result,arguments in specs:
   signature={'return':result,'arguments':arguments}
   if name=='narrow_variadic':signature.update(variadic=True,fixed_arguments=1)
   rng=random.Random(5232);rows=[]
   for i in range(1000):
    values=[T[t](rng.getrandbits(64)).value for t in arguments]
    if i<6:values=[T[t](v).value for t,v in zip(arguments,([-1,0,1,127,128,65535][i] for _ in arguments))]
    if name=='narrow_variadic':values[0]=i%4
    rows.append(values)
   contract=d/(name+'.json');contract.write_text(json.dumps({'signature':signature,'cases':[{'arguments':r} for r in rows[:6]]}))
   output=d/f'{compiler_index}-{name}'
   # The native CLI is intentionally disabled in the sanitizer build.
   doctor=json.loads(run([EXE,'doctor','--json']).stdout)
   if doctor['capabilities']['sanitized_build']:
    run([EXE,'lift',original_path,'--symbol',name,'--abi',contract,'--out',output,'--json'])
   else:
    report=json.loads(run([EXE,'verify',original_path,'--symbol',name,'--cases',contract,'--allow-exec','--out',output,'--json']).stdout)
    assert report['validation']['passed']==6,report
    verified+=6
    run([EXE,'lift',original_path,'--symbol',name,'--abi',contract,'--out',output,'--json'])
   native=getattr(original,name);native.argtypes=[T[t] for t in arguments];native.restype=T[result]
   for level in [0,2]:
    shared=output/f'compiled-{level}.so';run([CLANG,'-shared','-fPIC',f'-O{level}','-Wno-override-module',output/'module.bc','-o',shared]);lib=C.CDLL(str(shared))
    lib.zvril_runtime_create.argtypes=[C.c_uint64,C.c_uint64];lib.zvril_runtime_create.restype=C.c_void_p
    lib.zvril_init_image.argtypes=[C.c_void_p,C.c_uint64];lib.zvril_runtime_destroy.argtypes=[C.c_void_p]
    lib.zvril_runtime_success.argtypes=[C.c_void_p]
    call=lib.zvril_typed;call.argtypes=[C.c_void_p]+[T[t] for t in arguments];call.restype=T[result]
    context=lib.zvril_runtime_create(1024*1024,1000000);assert context and lib.zvril_init_image(context,0x4000000000)
    for values in rows:
     expected=native(*values);actual=call(context,*values)
     assert actual==expected,(name,compiler,level,values,expected,actual)
     assert lib.zvril_runtime_success(context)==1
     comparisons+=1
    lib.zvril_runtime_destroy(context);wrappers+=1
 invalid=d/'unpromoted.json';invalid.write_text(json.dumps({'return':'i64','arguments':['u8','i8'],'variadic':True,'fixed_arguments':1}))
 rejected=json.loads(run([EXE,'lift',original_path,'--symbol','narrow_variadic','--abi',invalid,'--out',d/'unpromoted','--json'],3).stdout)
 assert rejected['diagnostics'][-1]['code']=='E_ABI_UNKNOWN'
 print(json.dumps({'narrow_abi_comparisons':comparisons,'compiled_wrappers':wrappers,'native_cli_cases':verified,'widths':[8,16,32,64],'unpromoted_varargs_rejected':True}))
