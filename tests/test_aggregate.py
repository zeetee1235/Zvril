import ctypes as C
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
EXE,CC,CLANG,ROOT=Path(sys.argv[1]).resolve(),sys.argv[2],sys.argv[3],Path(sys.argv[4]).resolve()
def layout(size,classes,pointers=None):
 v={'size':size,'alignment':8,'classes':classes}
 if pointers:v['pointer_offsets']=pointers
 return {'aggregate':v}
def fields(size,alignment,*members):
 return {'aggregate':{'size':size,'alignment':alignment,'fields':[{'offset':o,'type':t} for o,t in members]}}
def packet(fmt,*values):return {'hex':struct.pack('<'+fmt,*values).hex()}
with tempfile.TemporaryDirectory(prefix='zvril-aggregate-') as temp:
 d=Path(temp);total=0
 for number,cc in enumerate(dict.fromkeys([CC,CLANG])):
  native=d/f'native-{number}.so'
  subprocess.run([cc,'-x','c','-shared','-fPIC','-O1',str(ROOT/'tests/fixtures/aggregate.c'),'-o',str(native)],check=True)
  ii=layout(16,['INTEGER','INTEGER']);ss=layout(16,['SSE','SSE']);mix=layout(16,['INTEGER','SSE']);big=layout(24,['MEMORY']);pointer=layout(16,['INTEGER','INTEGER'],[0])
  padding=layout(16,['INTEGER','INTEGER']);padding['aggregate']['defined_bytes']='1111000011111111'
  small=fields(8,4,(0,'u8'),(2,'u16'),(4,'u32'))
  aligned=fields(16,16,(0,'u64'))
  packed=fields(9,1,(0,'u8'),(1,'u64'))
  nested=fields(24,8,(0,fields(16,8,(0,'u32'),(8,'u64'))),(16,'f64'))
  floats=fields(8,4,(0,'f32'),(4,'f32'))
  merged=fields(16,8,(0,'f32'),(4,'u32'),(8,'f64'))
  auto_pointer=fields(16,8,(0,'ptr'),(8,'u64'))
  rows=[
   ('aggregate_narrow','i16',[ii,'i8','i16'],[packet('QQ',100,200),-128,-30000],{}),
   ('aggregate_auto_small',small,[small],[packet('BBHI',7,255,10,100)],{}),
   ('aggregate_auto_aligned_stack','u64',['u64']*7+[aligned,'u64'],[1,2,3,4,5,6,7,packet('QQ',100,0xffffffffffffffff),9],{}),
   ('aggregate_auto_aligned',aligned,[aligned],[packet('QQ',100,0xffffffffffffffff)],{}),
   ('aggregate_auto_packed',packed,[packed],[packet('BQ',3,100)],{}),
   ('aggregate_auto_nested',nested,[nested],[packet('IIQd',10,0xffffffff,20,1.5)],{}),
   ('aggregate_auto_floats',floats,[floats],[packet('ff',1.5,2.25)],{}),
   ('aggregate_auto_merge',merged,[merged],[packet('fId',1.5,10,2.25)],{}),
   ('aggregate_auto_pointer',auto_pointer,[auto_pointer],[{'hex':struct.pack('<QQ',0,4).hex(),'pointers':{'0':{'buffer':'input'}}}],{'input':{'hex':'01020304'}}),
   ('aggregate_sum','u64',[ii,'u64'],[packet('QQ',10,20),3],{}),
   ('aggregate_mixed',mix,[mix,'f64'],[packet('Qd',10,2.5),3.0],{}),
   ('aggregate_double',ss,[ss],[packet('dd',1.0,2.0)],{}),
   ('aggregate_big',big,[big,'u64'],[packet('QQQ',10,20,30),7],{}),
   ('aggregate_rollback','u64',['u64']*5+[ii,'u64'],[1,2,3,4,5,packet('QQ',6,7),8],{}),
   ('aggregate_sse_rollback','f64',['f64']*7+[ss,'f64'],[1.,2.,3.,4.,5.,6.,7.,packet('dd',8.,9.),10.],{}),
   ('aggregate_padding',padding,[padding],[{'hex':struct.pack('<IIQ',41,0xffffffff,100).hex()}],{}),
   ('aggregate_variadic',ii,['u32',ii,ii,ii],[3,packet('QQ',1,2),packet('QQ',3,4),packet('QQ',5,6)],{}),
   ('aggregate_pointer',pointer,[pointer],[{'hex':struct.pack('<QQ',0,4).hex(),'pointers':{'0':{'buffer':'input'}}}],{'input':{'hex':'01020304'}})
  ]
  for name,result,types,args,buffers in rows:
   signature={'return':result,'arguments':types}
   if name=='aggregate_variadic':signature.update(variadic=True,fixed_arguments=1)
   cases=d/(name+'.json');cases.write_text(json.dumps({'signature':signature,'cases':[{'arguments':args,'buffers':buffers}]}))
   p=subprocess.run([str(EXE),'verify',str(native),'--symbol',name,'--cases',str(cases),'--allow-exec','--out',str(d/f'{number}-{name}'),'--json'],capture_output=True,text=True,timeout=40)
   assert p.returncode==0,(name,p.returncode,p.stdout,p.stderr)
   r=json.loads(p.stdout);assert r['validation']['passed']==1,r
   if name=='aggregate_auto_pointer':
    assert r['validation']['records'][0]['lifted']['return_bytes']==struct.pack('<QQ',0x50000001,5).hex(),r
   # Compile the actual exported module and exercise packet ABI, independently
   # of the CLI verifier's marshalling implementation.
   out=d/f'{number}-{name}'
   lifted=d/f'packet-{number}-{name}.so'
   contract=d/(name+'-abi.json');contract.write_text(json.dumps(signature))
   q=subprocess.run([str(EXE),'lift',str(native),'--symbol',name,'--abi',str(contract),'--out',str(out),'--json'],capture_output=True,text=True,timeout=40)
   assert q.returncode==0,(name,q.stdout,q.stderr)
   assert json.loads(q.stdout)['lifting']['typed_wrapper']['symbol']=='zvril_invoke_packet'
   subprocess.run([CLANG,'-O2','-shared','-fPIC','-Wno-override-module',str(out/'module.bc'),'-o',str(lifted)],check=True,capture_output=True)
   lib=C.CDLL(str(lifted))
   lib.zvril_runtime_create.argtypes=[C.c_uint64,C.c_uint64];lib.zvril_runtime_create.restype=C.c_void_p
   lib.zvril_init_image.argtypes=[C.c_void_p,C.c_uint64]
   lib.zvril_runtime_map.argtypes=[C.c_void_p,C.c_uint64,C.c_uint64,C.c_uint,C.c_void_p,C.c_uint64,C.c_int]
   lib.zvril_invoke_packet.argtypes=[C.c_void_p,C.POINTER(C.c_uint64),C.c_void_p]
   lib.zvril_runtime_destroy.argtypes=[C.c_void_p]
   rt=lib.zvril_runtime_create(128*1024*1024,1000000)
   assert rt and lib.zvril_init_image(rt,0x4000000000)==1
   references=[];slots=[]
   for j,(t,value) in enumerate(zip(types,args)):
    if isinstance(t,dict):
     data=bytearray.fromhex(value['hex'])
     for at,ref in value.get('pointers',{}).items():
      struct.pack_into('<Q',data,int(at),0x50000000+ref.get('offset',0))
     memory=C.create_string_buffer(bytes(data));references.append(memory);slots.append(C.addressof(memory))
    elif t=='f64':slots.append(struct.unpack('<Q',struct.pack('<d',value))[0])
    else:slots.append(value)
   for buffer in buffers.values():
    data=bytes.fromhex(buffer['hex']);memory=C.create_string_buffer(data);references.append(memory)
    assert lib.zvril_runtime_map(rt,0x50000000,len(data),3,memory,len(data),1)==1
   output=C.create_string_buffer(4096)
   packed=(C.c_uint64*len(slots))(*slots)
   assert lib.zvril_invoke_packet(rt,packed,output)==1,name
   observation=r['validation']['records'][0]['lifted']
   if isinstance(result,dict):
    expected=bytes.fromhex(observation['return_bytes'])
   else:
    expected=struct.pack('<Q',int(observation['return'],16))
   assert output.raw[:len(expected)]==expected,(name,output.raw[:len(expected)].hex(),expected.hex())
   # Cached stack and sret storage must support repeated independent invocations.
   assert lib.zvril_invoke_packet(rt,packed,output)==1,name
   assert output.raw[:len(expected)]==expected
   lib.zvril_runtime_destroy(rt)
   total+=1
 # Invalid/unsupported ABI layouts cannot publish a successful module.
 negative=[
  layout(16,['SSEUP','SSEUP']),
  fields(8,8,(0,'u64'),(4,'u32')),
  fields(8,8,(7,'f64')),
  {'aggregate':{'size':8,'alignment':8,'fields':[{'offset':0,'type':'u64'}],'classes':['SSE']}},
  layout(24,['INTEGER','INTEGER']),
  layout(16,['INTEGER','INTEGER'],[0,4]),
  {'aggregate':{'size':16,'alignment':8,'classes':['INTEGER','INTEGER'],'defined_bytes':'11'}},
  {'aggregate':{'size':16,'alignment':8,'classes':['INTEGER','INTEGER'],'unexpected':True}},
 ]
 for i,t in enumerate(negative):
  contract=d/f'invalid-{i}.json';contract.write_text(json.dumps({'return':'u64','arguments':[t]}))
  p=subprocess.run([str(EXE),'lift',str(native),'--symbol','aggregate_sum','--abi',str(contract),'--out',str(d/f'invalid-{i}'),'--json'],capture_output=True,text=True,timeout=40)
  assert p.returncode==3,(i,p.stdout,p.stderr)
  assert json.loads(p.stdout)['diagnostics'][-1]['code']=='E_ABI_UNKNOWN'
  assert not (d/f'invalid-{i}'/'module.bc').exists()
 print(json.dumps({'aggregate_comparisons':total,'packet_wrappers':total,'packet_calls':total*2,'register_rollback':True,'sret':True,'pointer_normalization':True,'invalid_layouts_rejected':len(negative)}))
