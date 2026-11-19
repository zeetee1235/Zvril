"""Pinned real-library function corpus. Executes only these trusted sources.

Every build, unsupported function and UNKNOWN comparison is retained. This is
selected-function evidence, not a claim of support for an entire library.
"""
import argparse
import hashlib
import json
from pathlib import Path
import random
import shutil
import struct
import subprocess
import time

ROOT=Path(__file__).resolve().parents[1]
p=argparse.ArgumentParser()
p.add_argument('--zvril',type=Path,default=ROOT/'build/zvril')
p.add_argument('--cc',default='cc')
p.add_argument('--out',type=Path,default=ROOT/'build/corpus-results')
p.add_argument('--cases',type=int,default=1000)
args=p.parse_args()
if not 1<=args.cases<=10000:p.error('--cases must be 1..10000')
args.out.mkdir(parents=True,exist_ok=True)
rng=random.Random(3619)
def buf(data=b'',size=None,**kwargs):
    v={'hex':data.hex(),**kwargs}
    if size is not None:v['size']=size
    return v
def ref(name,offset=0):return {'buffer':name,'offset':offset}
def case(arguments,buffers=None):return {'arguments':arguments,'buffers':buffers or {}}
def pack(n):return struct.pack('<I',n)

specs=[
 ('zserge-jsmn',['jsmn_unit.c'],'jsmn_parse','i32',['ptr','ptr','u64','ptr','u32']),
 ('DaveGamble-cJSON',['cJSON.c'],'cJSON_IsArray','i32',['ptr']),
 ('Cyan4973-xxHash',['xxhash.c'],'XXH32','u32',['ptr','u64','u32']),
 ('richgel999-miniz',['miniz.c'],'mz_adler32','u64',['u64','ptr','u64']),
 ('sheredom-utf8.h',['utf8_unit.c'],'utf8codepointsize','u64',['i32']),
 ('antirez-sds',['sds.c'],'sdscmp','i32',['ptr','ptr']),
 ('rxi-vec',['src/vec.c'],'vec_swap_','void',['ptr','ptr','ptr','i32','i32','i32']),
 ('rxi-log.c',['src/log.c'],'log_set_level','void',['i32']),
 ('clibs-list',['src/list.c','src/list_node.c','src/list_iterator.c'],'list_at','ptr',['ptr','i32']),
 ('kokke-tiny-regex-c',['re.c'],'re_match','i32',['ptr','ptr','ptr']),
]

def make_cases(project):
    rows=[]
    for i in range(args.cases):
        if project=='zserge-jsmn':
            value=json.dumps({'n':rng.randrange(10000),'a':[i%8,True,'text']},separators=(',',':')).encode()
            edges=[b'{}',b'[]',b'{"nested":{"a":[true,false,null,-2,3.5]}}',b'{"escape":"a\\n\\u1234\\\""}',b'{"incomplete":',b'[1,2,3,4,5,6,7,8,9,10]',json.dumps(list(range(50))).encode()]
            if i<len(edges):value=edges[i]
            rows.append(case([ref('parser'),ref('json'),len(value),ref('tokens'),32],{'parser':buf(struct.pack('<IIi',0,0,-1)),'json':buf(value+b'\0'),'tokens':buf(size=512)}))
        elif project=='DaveGamble-cJSON':
            data=bytearray(64);struct.pack_into('<I',data,24,rng.choice([1,2,4,8,16,32,64,128,256|32]))
            rows.append(case([ref('node')],{'node':buf(data)}))
        elif project=='Cyan4973-xxHash':
            lengths=[0,1,3,4,15,16,17,31,32,33,255,256];length=lengths[i] if i<len(lengths) else rng.randrange(1,257)
            value=rng.randbytes(length);rows.append(case([ref('input'),len(value),rng.randrange(2**32)],{'input':buf(value)}))
        elif project=='richgel999-miniz':
            lengths=[0,1,7,8,15,16,255,5551,5552,5553,8192];length=lengths[i] if i<len(lengths) else rng.randrange(1,257)
            value=rng.randbytes(length);rows.append(case([1,ref('input'),len(value)],{'input':buf(value)}))
        elif project=='sheredom-utf8.h':
            edges=[0,0x7f,0x80,0x7ff,0x800,0xffff,0x10000,0x10ffff];rows.append(case([edges[i] if i<len(edges) else rng.randrange(0x110000)]))
        elif project=='antirez-sds':
            a=rng.randbytes(rng.randrange(1,30));b=rng.randbytes(rng.randrange(1,30))
            rows.append(case([ref('a',3),ref('b',3)],{'a':buf(bytes([len(a),len(a),1])+a+b'\0'),'b':buf(bytes([len(b),len(b),1])+b+b'\0')}))
        elif project=='rxi-vec':
            rows.append(case([ref('ptr'),ref('len'),ref('cap'),4,rng.randrange(8),rng.randrange(8)],{'ptr':buf(size=8,pointers={'0':ref('data')}),'len':buf(pack(8)),'cap':buf(pack(8)),'data':buf(rng.randbytes(32))}))
        elif project=='rxi-log.c':rows.append(case([rng.randrange(6)]))
        elif project=='clibs-list':
            rows.append(case([ref('list'),rng.choice([-3,-2,-1,0,1,2,3])],{'list':buf(pack(0)*4+pack(2)+bytes(20),pointers={'0':ref('first'),'8':ref('last')}),'first':buf(size=24,pointers={'8':ref('last')}),'last':buf(size=24,pointers={'0':ref('first')})}))
        else:
            value=rng.choice([b'abc',b'123',b'x123z',b'abcdef',b'xyz',b'aabbcc'])
            rows.append(case([ref('pattern'),ref('text'),ref('length')],{'pattern':buf(rng.choice([b'a.*c\0',b'[0-9]+\0',b'^abc$\0'])),'text':buf(value+b'\0'),'length':buf(size=4)}))
    return rows

lock=json.loads((ROOT/'third_party/corpus.lock.json').read_text())
for f in lock['files']:
    data=(ROOT/f['path']).read_bytes()
    assert hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()==f['sha'],f['path']
results=[]
for project,sources,symbol,ret,types in specs:
    d=args.out/project;d.mkdir(parents=True,exist_ok=True)
    upstream=ROOT/'third_party/corpus'/project
    (d/'jsmn_unit.c').write_text('#include "jsmn.h"\n')
    (d/'utf8_unit.c').write_text('#include "utf8.h"\n')
    # This header is generated by upstream CMake; its definition is kept outside
    # the pinned source tree and only controls symbol visibility.
    (d/'miniz_export.h').write_text('#pragma once\n#define MINIZ_EXPORT\n')
    sourcepaths=[str(d/s if s.endswith('_unit.c') else upstream/s) for s in sources]
    command=[args.cc,'-shared','-fPIC','-O1','-fno-builtin','-fno-stack-protector','-fno-jump-tables','-fno-tree-vectorize','-ffile-prefix-map='+str(ROOT)+'=/zvril','-fmacro-prefix-map='+str(ROOT)+'=/zvril','-I'+str(upstream),'-I'+str(d),'-DMINIZ_NO_ZLIB_APIS','-DMINIZ_NO_ARCHIVE_APIS',*sourcepaths,'-lm','-o',str(d/'native.so')]
    start=time.monotonic();build=subprocess.run(command,capture_output=True,text=True)
    record={'project':project,'function':symbol,'build_command':command,'attempted_cases':args.cases,'status':'BUILD_FAILED','returncode':build.returncode}
    (d/'build.log').write_text(build.stdout+build.stderr)
    if not build.returncode:
        signature={'return':ret,'arguments':types}
        if project=='rxi-log.c':signature['globals']=['L']
        # libc comparison functions promise a sign, not a particular magnitude.
        # This is explicitly a C-level contract, not bitwise return equivalence.
        if project=='antirez-sds':signature['return_comparison']='sign'
        document={'signature':signature,'cases':make_cases(project)}
        cases=d/'cases.json';cases.write_text(json.dumps(document))
        command=[str(args.zvril.resolve()),'verify',str(d/'native.so'),'--symbol',symbol,'--cases',str(cases),'--allow-exec','--out',str(d/'lifted'),'--json']
        verify=subprocess.run(command,capture_output=True,text=True,timeout=max(120,args.cases*2))
        (d/'stderr.log').write_text(verify.stderr)
        (d/'result.json').write_text(verify.stdout)
        record['returncode']=verify.returncode
        try:
            report=json.loads(verify.stdout);record['status']=report['status'];record['diagnostics']=report.get('diagnostics',[])
            record['tool_version']=report.get('tool_version');record['llvm_version']=report.get('llvm_version')
            record['lifting']={k:report.get('lifting',{}).get(k) for k in ['backend','remill_revision','semantics_sha256','runtime_sha256','isa','instruction_count']}
            record['resources']=report.get('resources',{});record['timings']=report.get('timings',{})
            if 'validation' in report:record['validation']={k:v for k,v in report['validation'].items() if k!='records'}
            record['source_sha256']=hashlib.sha256((d/'native.so').read_bytes()).hexdigest()
            record['cases_sha256']=hashlib.sha256(cases.read_bytes()).hexdigest()
        except (ValueError,KeyError):record['status']='CRASH_OR_INVALID_REPORT'
    record['elapsed_seconds']=time.monotonic()-start
    results.append(record)
    print(json.dumps({k:record[k] for k in ['project','function','status','returncode']}),flush=True)
    manifest={'schema_version':'0.1','seed':3619,'compiler':subprocess.check_output([args.cc,'--version'],text=True).splitlines()[0],'packages':lock['packages'],'results':results}
    (args.out/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
raise SystemExit(any(r['status']!='TESTED' for r in results))
