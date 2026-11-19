"""Executes only locally compiled, trusted fixtures in verification workers."""
import json
import ctypes
from pathlib import Path
import subprocess
import sys
import tempfile
import struct

EXE, CC, ROOT = Path(sys.argv[1]).resolve(), sys.argv[2], Path(sys.argv[3])
CLANG=sys.argv[4] if len(sys.argv)>4 else 'clang'

def run(*args, expected=0):
    p=subprocess.run([str(EXE),*map(str,args),'--json'],capture_output=True,text=True,timeout=40)
    assert p.returncode==expected,(args,p.returncode,p.stdout,p.stderr)
    assert not p.stderr,p.stderr
    return json.loads(p.stdout)

with tempfile.TemporaryDirectory(prefix='zvril-verify-test-') as temp:
    d=Path(temp)
    lib=d/'program.so'
    subprocess.run([CC,'-shared','-fPIC','-O1','-fno-builtin','-fno-stack-protector',str(ROOT/'tests/fixtures/program.c'),str(ROOT/'tests/fixtures/vector.S'),'-o',str(lib)],check=True)
    count=0
    def verify(name,ret,args,cases,expected=0,extra=(),signature_extra=None):
        global count
        f=d/(name+'.json');f.write_text(json.dumps({'signature':{'return':ret,'arguments':args,**(signature_extra or {})},'cases':cases}))
        r=run('verify',lib,'--symbol',name,'--cases',f,'--allow-exec','--out',d/name,*extra,expected=expected)
        assert json.loads((d/name/'functions.json').read_text())['functions']==r['functions']
        if expected==0:
            assert r['status']=='TESTED',r
            assert r['validation']['passed']==len(cases),r['validation']
            assert r['validation']['mismatches']==r['validation']['unknown']==0
        count+=len(cases)
        return r
    verify('program_data','u64',['u64'],[{'arguments':[x]} for x in [0,1,42,999]],signature_extra={'globals':['zero_value']})
    verify('program_strlen','u64',['ptr'],[{'arguments':[{'buffer':'a'}],'buffers':{'a':{'hex':v}}} for v in ['00','61626300','01020304050607080900']])
    verify('program_copy','ptr',['ptr','ptr','u64'],[{'arguments':[{'buffer':'a'},{'buffer':'b'},4],'buffers':{'a':{'size':8},'b':{'hex':'01020304'}}}])
    verify('program_compare','i32',['ptr','ptr'],[{'arguments':[{'buffer':'a'},{'buffer':'b'}],'buffers':{'a':{'hex':'61626300'},'b':{'hex':v}}} for v in ['61626300','61626400','61626200']])
    verify('program_heap','u64',['u64'],[{'arguments':[x]} for x in [0,1,42]])
    verify('program_stack','u64',['u64']*8,[{'arguments':list(range(8))}])
    verify('program_float','f64',['f64']*3,[{'arguments':[a,b,c]} for a,b,c in [(1.5,2.0,3.0),(-8.5,0.25,2.0)]])
    verify('program_varint','u64',['u32']+['u64']*9,[{'arguments':[9]+list(range(9))},{'arguments':[0]+[42]*9}],signature_extra={'variadic':True,'fixed_arguments':1})
    verify('program_varfloat','f64',['u32']+['f64']*10,[{'arguments':[10]+[float(i) for i in range(10)]},{'arguments':[3]+[1.5]*10}],signature_extra={'variadic':True,'fixed_arguments':1})
    divide=verify('program_div','i64',['i64','i64'],[{'arguments':[a,b]} for a,b in [(24,3),(-24,3),(1,0),(-9223372036854775808,-1)]])
    for row in divide['validation']['records'][2:]:
        assert row['native']['fault_state']['address_space']=='native'
        assert row['lifted']['fault_state']['address_space']=='guest'
        assert len(row['native']['fault_state']['gpr'])==len(row['lifted']['fault_state']['gpr'])==17
    verify('program_trap','void',[],[{'arguments':[]}])
    verify('program_tls','u64',['u64'],[{'arguments':[x]} for x in [0,1,100]])
    verify('program_constant','u64',['u64','u64'],[{'arguments':[40,2]},{'arguments':[100,27]}])
    verify('program_store','u64',['ptr','u64'],[{'arguments':[{'buffer':'value'},42],'buffers':{'value':{'size':8,'permissions':permission}}} for permission in ['rw','r']])
    verify('program_load','u64',['ptr'],[{'arguments':[0]}])
    invalid_pointer=verify('program_load','u64',['ptr'],[{'arguments':[{'buffer':'input','offset':-1}],'buffers':{'input':{'size':8}}}],expected=1)
    assert invalid_pointer['validation']['unknown']==1 and invalid_pointer['validation']['passed']==0
    mismatch=verify('program_address','u64',[],[{'arguments':[]}],expected=4)
    assert mismatch['validation']['mismatches']==1
    assert mismatch['validation']['first_failure_reproducer']
    assert mismatch['validation']['records'][0]['lifted']['trace']['records']
    verify('program_address','ptr',[],[{'arguments':[]}])
    if 'avx2' in Path('/proc/cpuinfo').read_text().split():
        verify('program_avx2','void',['ptr']*3,[{'arguments':[{'buffer':'out'},{'buffer':'a'},{'buffer':'b'}],
            'buffers':{'out':{'size':32},'a':{'hex':bytes(range(32)).hex()},'b':{'hex':bytes(reversed(range(32))).hex()}}}],extra=('--isa','amd64_avx'))
    # A generated typed wrapper is separately compiled, loaded and invoked.
    for name,kind,argtypes,values,expected in [
        ('program_stack',ctypes.c_uint64,[ctypes.c_uint64]*8,list(range(8)),28),
        ('program_float',ctypes.c_double,[ctypes.c_double]*3,[1.5,2.0,3.0],6.0),
        ('program_varint',ctypes.c_uint64,[ctypes.c_uint32]+[ctypes.c_uint64]*9,[9]+list(range(9)),36),
        ('program_varfloat',ctypes.c_double,[ctypes.c_uint32]+[ctypes.c_double]*10,[10]+[float(i) for i in range(10)],45.0)]:
        out=d/(name+'-typed')
        report=run('lift',lib,'--symbol',name,'--abi',d/(name+'.json'),'--out',out)
        assert report['lifting']['typed_wrapper']['enabled']
        compiled=out/'lifted.so'
        subprocess.run([CLANG,'-shared','-fPIC','-O2',str(out/'module.bc'),'-o',str(compiled)],check=True,capture_output=True)
        loaded=ctypes.CDLL(str(compiled))
        create=loaded.zvril_runtime_create;create.argtypes=[ctypes.c_uint64]*2;create.restype=ctypes.c_void_p
        init=loaded.zvril_init_image;init.argtypes=[ctypes.c_void_p,ctypes.c_uint64];init.restype=ctypes.c_int
        call=loaded.zvril_typed;call.argtypes=[ctypes.c_void_p]+argtypes;call.restype=kind
        destroy=loaded.zvril_runtime_destroy;destroy.argtypes=[ctypes.c_void_p]
        context=create(1024*1024,10000)
        assert context and init(context,0)
        assert call(context,*values)==expected
        assert call(context,*values)==expected
        destroy(context)
    # Input contracts must not be overwritten by artifact publication.
    protected=d/'protected';protected.mkdir();cases=protected/'report.json'
    content='{"signature":{"return":"u64","arguments":["u64"]},"cases":[{"arguments":[1]}]}'
    cases.write_text(content)
    run('verify',lib,'--symbol','program_data','--cases',cases,'--allow-exec','--out',protected,expected=2)
    assert cases.read_text()==content
    r=run('batch',lib,'--symbols','program_data,program_strlen,program_float','--jobs','2','--out',d/'batch')
    assert r['batch']=={'lifted':3,'blocked':0,'total':3}
    # Partial output remains analysis-only and returns a non-success exit.
    asm=d/'blocked.so'
    subprocess.run([CC,'-shared','-fPIC',str(ROOT/'tests/fixtures/lifting.S'),'-o',str(asm)],check=True)
    partial=run('lift',asm,'--symbol','lift_indirect','--allow-partial','--out',d/'partial',expected=1)
    assert partial['status']=='PARTIAL' and partial['lifting']['unresolved']
    assert (d/'partial/module.bc').is_file()
    assert partial['functions'][0]['unresolved_edges']
    # A constructor writes a marker if executed outside the worker sandbox.
    marker=d/'constructor-marker';source=d/'constructor.c';target=d/'constructor.so'
    source.write_text('#include <fcntl.h>\n#include <unistd.h>\n'
        '__attribute__((constructor)) static void init(void){int fd=open('+json.dumps(str(marker))+',O_WRONLY|O_CREAT,0600);if(fd>=0)close(fd);}\n'
        'unsigned long long static_target(unsigned long long x){return x+1;}\n')
    subprocess.run([CC,'-shared','-fPIC','-O1',str(source),'-o',str(target)],check=True)
    run('inspect',target)
    run('lift',target,'--symbol','static_target','--out',d/'nonexec-lift')
    run('batch',target,'--symbols','static_target','--out',d/'nonexec-batch')
    assert not marker.exists(),'Static analysis executed an ELF constructor'
    cases=d/'constructor-cases.json';cases.write_text(json.dumps({'signature':{'return':'u64','arguments':['u64']},'cases':[{'arguments':[41]}]}))
    sandboxed=run('verify',target,'--symbol','static_target','--cases',cases,'--allow-exec','--out',d/'sandbox-ctor')
    assert sandboxed['status']=='TESTED' and not marker.exists(),'Worker constructor escaped its filesystem sandbox'
    # Relocation application must not depend on section-name strings.
    unnamed=d/'unnamed.so';data=bytearray(lib.read_bytes());struct.pack_into('<H',data,62,0);unnamed.write_bytes(data)
    r=run('verify',unnamed,'--symbol','program_data','--cases',d/'program_data.json','--allow-exec','--out',d/'unnamed-output')
    assert r['status']=='TESTED'
    # Full stripping preserves unwind evidence for hidden C functions.
    hidden_source=d/'hidden.c';hidden=d/'hidden.so'
    hidden_source.write_text('__attribute__((noinline,visibility("hidden"))) unsigned long long hidden_target(unsigned long long x){if(x<9)return x*3;return x+4;}\n')
    subprocess.run([CC,'-shared','-fPIC','-O1',str(hidden_source),'-o',str(hidden)],check=True)
    original=run('inspect',hidden);address=next(f['address'] for f in original['functions'] if f['name']=='hidden_target')
    subprocess.run(['strip','--strip-all',str(hidden)],check=True)
    stripped=run('inspect',hidden);candidate=next(f for f in stripped['functions'] if f['address']==address)
    assert candidate['discovery_evidence']==['eh_frame']
    contract=d/'hidden.json';contract.write_text(json.dumps({'signature':{'return':'u64','arguments':['u64']},'cases':[{'arguments':[x]} for x in [0,8,9,100]]}))
    r=run('verify',hidden,'--symbol',candidate['name'],'--cases',contract,'--allow-exec','--out',d/'hidden-output')
    assert r['status']=='TESTED'
    packed=d/'packed.so'
    subprocess.run([CC,'-shared','-fPIC','-O1','-Wl,-z,pack-relative-relocs',str(ROOT/'tests/fixtures/program.c'),'-o',str(packed)],check=True)
    relocated=run('verify',packed,'--symbol','program_data','--cases',d/'program_data.json','--allow-exec','--out',d/'packed-output')
    assert relocated['status']=='TESTED'
    print(json.dumps({'verification_cases':count+13,'expected_mismatch':1,'expected_unknown':1,'typed_wrappers':4,'typed_wrapper_calls':8,'batch_functions':3,'partial_diagnostics':len(partial['lifting']['unresolved'])}))
