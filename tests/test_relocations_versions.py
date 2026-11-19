"""REL loader equivalence and version-qualified symbol selection."""
import ctypes as C
import json
from pathlib import Path
import random
import struct
import subprocess
import sys
import tempfile
EXE,CC,CLANG,ROOT=Path(sys.argv[1]).resolve(),sys.argv[2],sys.argv[3],Path(sys.argv[4]).resolve()
STATIC='--static' in sys.argv[5:]
def run(args,code=0):
 p=subprocess.run(list(map(str,args)),capture_output=True,text=True,timeout=60)
 assert p.returncode==code,(args,p.returncode,p.stdout,p.stderr)
 return p

def elf(data):
 ph=struct.unpack_from('<Q',data,32)[0];num=struct.unpack_from('<H',data,56)[0];segments=[];tags={}
 for i in range(num):
  at=ph+i*56;kind=struct.unpack_from('<I',data,at)[0];off,va=struct.unpack_from('<QQ',data,at+8);size=struct.unpack_from('<Q',data,at+32)[0]
  if kind==1:segments.append((off,va,size))
  if kind==2:
   for p in range(off,off+size,16):
    tag,value=struct.unpack_from('<qQ',data,p)
    if tag==0:break
    tags[tag]=(p,value)
 def offset(va,size=1):return next(off+va-start for off,start,length in segments if va>=start and va-start+size<=length)
 return tags,offset

def module(input,abi,output):
 run([EXE,'lift',input,'--symbol','rel_value','--abi',abi,'--out',output,'--json'])
 shared=output/'recompiled.so';run([CLANG,'-shared','-fPIC','-O2','-Wno-override-module',output/'module.bc','-o',shared])
 lib=C.CDLL(str(shared));lib.zvril_runtime_create.argtypes=[C.c_uint64,C.c_uint64];lib.zvril_runtime_create.restype=C.c_void_p
 lib.zvril_init_image.argtypes=[C.c_void_p,C.c_uint64];lib.zvril_typed.argtypes=[C.c_void_p,C.c_uint64];lib.zvril_typed.restype=C.c_uint64
 lib.zvril_runtime_destroy.argtypes=[C.c_void_p];lib.zvril_runtime_read.argtypes=[C.c_void_p,C.c_uint64,C.c_void_p,C.c_uint64]
 return lib
with tempfile.TemporaryDirectory(prefix='zvril-versions-') as temporary:
 d=Path(temporary);abi=d/'abi.json';abi.write_text('{"return":"u64","arguments":["u64"]}')
 source=d/'native.c';source.write_text('#include <stdint.h>\nuint64_t zvril_rel_value=17;uint64_t* volatile zvril_rel_pointer=&zvril_rel_value;uint64_t rel_value(uint64_t x){return *zvril_rel_pointer+x;}\n')
 original=d/'original.so';run([CC,'-shared','-nostdlib','-fPIC','-O1',source,'-o',original]);native=C.CDLL(str(original)).rel_value;native.argtypes=[C.c_uint64];native.restype=C.c_uint64
 data=bytearray(original.read_bytes());tags,offset=elf(data);begin=offset(tags[7][1]);size=tags[8][1]
 entries=[struct.unpack_from('<QQq',data,at) for at in range(begin,begin+size,24)]
 assert any(info&0xffffffff==1 for _,info,_ in entries),entries
 for i,(target,info,addend) in enumerate(entries):
  struct.pack_into('<Q',data,offset(target,8),addend&((1<<64)-1));struct.pack_into('<QQ',data,begin+i*16,target,info)
 for old,new,value in [(7,17,tags[7][1]),(8,18,len(entries)*16),(9,19,16)]:struct.pack_into('<qQ',data,tags[old][0],new,value)
 if 0x6ffffff9 in tags:struct.pack_into('<q',data,tags[0x6ffffff9][0],0x6ffffffa)
 sh=struct.unpack_from('<Q',data,40)[0];count=struct.unpack_from('<H',data,60)[0]
 for i in range(count):
  at=sh+i*64
  if struct.unpack_from('<I',data,at+4)[0]==4 and struct.unpack_from('<Q',data,at+24)[0]==begin:
   struct.pack_into('<I',data,at+4,9);struct.pack_into('<Q',data,at+32,len(entries)*16);struct.pack_into('<Q',data,at+56,16)
 rel=d/'implicit.so';rel.write_bytes(data)
 for i,path in enumerate([original,rel]):
  lib=module(path,abi,d/f'variant-{i}');context=lib.zvril_runtime_create(1024*1024,1000000)
  assert context and lib.zvril_init_image(context,0x4000000000)
  rng=random.Random(388)
  for n in range(1000):
   value=rng.getrandbits(64);assert lib.zvril_typed(context,value)==native(value)
  lib.zvril_runtime_destroy(context)
 # R_X86_64_32/32S execute with a valid low load bias; overflow must fail
 # image initialization rather than silently truncate a guest pointer.
 original_data=bytearray(original.read_bytes())
 r64_index=next(i for i,(_,info,_) in enumerate(entries) if info&0xffffffff==1)
 target,info,addend=entries[r64_index]
 for kind in [10,11]:
  narrowed=bytearray(original_data);struct.pack_into('<Q',narrowed,begin+r64_index*24+8,(info&~0xffffffff)|kind)
  path=d/f'narrow-{kind}.so';path.write_bytes(narrowed)
  lib=module(path,abi,d/f'narrow-output-{kind}')
  for bias,accepted in [(0x10000000,True),(0x4000000000,False),(0x90000000,kind==10)]:
   context=lib.zvril_runtime_create(1024*1024,1000000)
   assert bool(lib.zvril_init_image(context,bias))==accepted,(kind,bias)
   if accepted:
    for x in [0,1,42,0xffffffffffffffff]:assert lib.zvril_typed(context,x)==native(x)
   lib.zvril_runtime_destroy(context)
 # Signed implicit PC-relative addends must be sign extended before P is subtracted.
 relative=bytearray(data)
 struct.pack_into('<Q',relative,begin+r64_index*16+8,(info&~0xffffffff)|2)
 struct.pack_into('<Q',relative,offset(target,8),0xfffffff4)
 path=d/'implicit-pc32.so';path.write_bytes(relative);lib=module(path,abi,d/'pc32-output')
 context=lib.zvril_runtime_create(1024*1024,1000000);assert lib.zvril_init_image(context,0x4000000000)
 symtab=offset(tags[6][1]);symbol_value=struct.unpack_from('<Q',original_data,symtab+(info>>32)*24+8)[0]
 observed=C.c_uint32();assert lib.zvril_runtime_read(context,0x4000000000+target,C.byref(observed),4)
 assert observed.value==(symbol_value-12-target)&0xffffffff
 lib.zvril_runtime_destroy(context)
 malformed=bytearray(data);rel_tags,_=elf(malformed);struct.pack_into('<Q',malformed,rel_tags[19][0]+8,24)
 bad=d/'bad-relent.so';bad.write_bytes(malformed)
 assert json.loads(run([EXE,'inspect',bad,'--json'],3).stdout)['diagnostics'][-1]['code']=='E_ELF_INVALID'
 duplicate=bytearray(data);assert len(entries)>=2;struct.pack_into('<Q',duplicate,begin+16,entries[0][0]);bad=d/'duplicate.so';bad.write_bytes(duplicate)
 assert json.loads(run([EXE,'lift',bad,'--symbol','rel_value','--out',d/'duplicate','--json'],1).stdout)['diagnostics'][-1]['code']=='E_RELOCATION'
 source=d/'versioned.c';source.write_text('unsigned long old_impl(unsigned long x){return x+1;} unsigned long new_impl(unsigned long x){return x+2;}\n__asm__(".symver old_impl,api@ZVRIL_1.0");\n__asm__(".symver new_impl,api@@ZVRIL_2.0");\n')
 script=d/'versions.map';script.write_text('ZVRIL_1.0 { global: api; local: *; }; ZVRIL_2.0 { global: api; } ZVRIL_1.0;\n')
 versioned=d/'versioned.so';run([CC,'-shared','-nostdlib','-fPIC','-O1',source,'-Wl,--version-script='+str(script),'-Wl,-soname,libzvril-test.so','-o',versioned])
 inspected=json.loads(run([EXE,'inspect',versioned,'--json']).stdout)
 assert any(v['version']=='ZVRIL_1.0' and v['hidden'] for v in inspected['symbol_versions']),inspected
 stripped=d/'sectionless.so';binary=bytearray(versioned.read_bytes());struct.pack_into('<Q',binary,40,0);struct.pack_into('<HHH',binary,58,0,0,0);stripped.write_bytes(binary)
 version_cases=0
 for i,path in enumerate([versioned,stripped]):
  for name,increment in [('api',2),('api@ZVRIL_1.0',1),('api@@ZVRIL_2.0',2)]:
   cases=d/'cases.json';cases.write_text(json.dumps({'signature':{'return':'u64','arguments':['u64']},'cases':[{'arguments':[x]} for x in [0,1,42,0xffffffffffffffff]]}))
   if STATIC:
    result=json.loads(run([EXE,'lift',path,'--symbol',name,'--abi',cases,'--out',d/f'qualified-{i}-{name}','--json']).stdout)
    expected=next(v['address'] for v in inspected['symbol_versions'] if v['symbol']=='api' and v['version']==('ZVRIL_1.0' if increment==1 else 'ZVRIL_2.0'))
    assert result['lifting']['entry']==expected,result
   else:
    result=json.loads(run([EXE,'verify',path,'--symbol',name,'--cases',cases,'--allow-exec','--out',d/f'qualified-{i}-{name}','--json']).stdout)
    assert result['validation']['passed']==4,result
    assert result['validation']['records'][0]['native']['return']==hex(increment)
    version_cases+=4
 custom=d/'custom.c';custom.write_text('int strcmp(const char*a,const char*b){return 77;}')
 custom_map=d/'custom.map';custom_map.write_text('CUSTOM_1 { global: strcmp; local: *; };')
 provider=d/'libcustom.so';run([CC,'-shared','-nostdlib','-fPIC',custom,'-Wl,--version-script='+str(custom_map),'-Wl,-soname,libcustom.so','-o',provider])
 consumer=d/'consumer.c';consumer.write_text('extern int strcmp(const char*,const char*);int uses_compare(const char*a,const char*b){return strcmp(a,b);}')
 target=d/'consumer.so';run([CC,'-shared','-nostdlib','-fPIC','-fno-builtin','-O1',consumer,'-L'+str(d),'-lcustom','-o',target])
 blocked=json.loads(run([EXE,'lift',target,'--symbol','uses_compare','--out',d/'custom-output','--json'],1).stdout)
 assert blocked['diagnostics'][-1]['code']=='E_EXTERNAL_UNMODELED',blocked
 binary=bytearray(versioned.read_bytes());version_tags,va=elf(binary);array=va(version_tags[0x6ffffff0][1]);struct.pack_into('<H',binary,array+2,0x7fff)
 unknown=d/'unknown-version.so';unknown.write_bytes(binary)
 assert json.loads(run([EXE,'inspect',unknown,'--json'],3).stdout)['diagnostics'][-1]['code']=='E_ELF_INVALID'
 print(json.dumps({'rel_rela_native_comparisons':2000,'version_qualified_cases':version_cases,'sectionless_versions':True,'custom_libc_name_rejected':True,'malformed_metadata_cases':3,'narrow_relocation_boundary_cases':6,'signed_implicit_pc32':True,'static_only':STATIC}))
