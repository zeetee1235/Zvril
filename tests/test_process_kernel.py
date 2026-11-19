"""Deterministic native ELF comparisons for file and signal kernel contracts."""
import json
from pathlib import Path
import resource
import subprocess
import sys
import tempfile

EXE, CC, ROOT = Path(sys.argv[1]).resolve(), sys.argv[2], Path(sys.argv[3]).resolve()

def run(args, expected=0, **kwargs):
    p=subprocess.run(list(map(str,args)),capture_output=True,timeout=180,**kwargs)
    assert p.returncode==expected,(args,p.returncode,p.stderr[-2500:],p.stdout[-3500:])
    return p

records=[]
with tempfile.TemporaryDirectory(prefix='zvril-kernel-') as temporary:
    root=Path(temporary)
    for fixture,exit_code,expected_output in [('files',59,b'ABCF'),('signals',67,b'signals\n')]:
        for pie in [False,True]:
            binary=root/f'{fixture}-{pie}'
            run([CC,'-nostdlib','-static-pie' if pie else '-static','-fPIE' if pie else '-fno-pie',
                 '-O1','-fno-stack-protector','-fno-builtin',ROOT/f'tests/fixtures/process_{fixture}.c','-o',binary])
            native_root=root/f'native-{fixture}-{pie}';guest_root=root/f'guest-{fixture}-{pie}'
            native_root.mkdir();guest_root.mkdir()
            for directory in [native_root,guest_root]:(directory/'input.bin').write_bytes(b'ABCDEF')
            native=run([binary],exit_code,cwd=native_root,preexec_fn=lambda:resource.setrlimit(resource.RLIMIT_CORE,(0,0)))
            assert native.stdout==expected_output,(fixture,pie,native.stdout)
            output=root/f'run-{fixture}-{pie}'
            result=json.loads(run([EXE,'run',binary,'--allow-exec','--sysroot',guest_root,'--out',output,
                         '--timeout-ms',120000,'--json']).stdout)
            process=result['process']
            assert process['guest_exit_code']==exit_code and bytes.fromhex(process['stdout_hex'])==native.stdout, {k:process.get(k) for k in ['guest_exit_code','error','signals']}
            assert not (guest_root/'output.bin').exists()
            if fixture=='files':
                files=process['filesystem']['changed_files'];assert len(files)==1
                assert bytes.fromhex(files[0]['hex'])==(native_root/'output.bin').read_bytes()==b'ABCF'
            else:
                assert process['signals']['delivered']==process['signals']['sigreturns']==4
            records.append({'fixture':fixture,'pie':pie,'instructions':process['instructions'],'modules':process['compiled_modules'],'passed':True})
    # A source file that was opened read-only cannot be modified through an alias.
    # The end-to-end fixture checks both readv offsets and MAP_PRIVATE isolation.
    print(json.dumps({'native_comparisons':len(records),'cases':records}))
    if len(sys.argv)>4:
        output=Path(sys.argv[4]);output.parent.mkdir(parents=True,exist_ok=True)
        output.write_text(json.dumps({'native_comparisons':len(records),'cases':records},indent=2)+'\n')
