"""Install and archive a self-contained LLVM/Remill tool distribution.

The executable uses the target system's ordinary C/C++/zlib/zstd runtime
libraries. LLVM, Remill, a compiler, Python and network access are not needed
to run the installed CLI or its built-in demo.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tarfile

ROOT=Path(__file__).resolve().parents[1]
p=argparse.ArgumentParser();p.add_argument('--build',type=Path,default=ROOT/'build');p.add_argument('--out',type=Path,default=ROOT/'dist');args=p.parse_args()
version=json.loads(subprocess.check_output([str(args.build/'zvril'),'doctor','--json']))['tool_version']
name=f'zvril-{version}-linux-x86_64';stage=args.out/name
if stage.exists():raise SystemExit('Refusing to replace an existing package directory: '+str(stage))
stage.mkdir(parents=True)
subprocess.run(['cmake','--install',str(args.build),'--prefix',str(stage.resolve())],check=True)
exe=stage/'bin/zvril'
dependencies=subprocess.check_output(['ldd',str(exe)],text=True)
manifest={'version':version,'platform':'Linux x86-64','dynamic_dependencies':dependencies,'files':[]}
for path in sorted(stage.rglob('*')):
    if path.is_file():manifest['files'].append({'path':str(path.relative_to(stage)),'sha256':hashlib.sha256(path.read_bytes()).hexdigest(),'bytes':path.stat().st_size})
(stage/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
# Use only installed semantics and trusted embedded fixtures after relocating.
doctor=json.loads(subprocess.check_output([str(exe.resolve()),'doctor','--json']))
assert str(stage.resolve()) in doctor['semantics_path'],doctor
subprocess.run([str(exe.resolve()),'demo'],check=True,env={'PATH':'/nonexistent','LANG':'C'})
archive=args.out/(name+'.tar.gz')
with tarfile.open(archive,'w:gz') as tar:tar.add(stage,arcname=name)
digest=hashlib.sha256(archive.read_bytes()).hexdigest()
archive.with_suffix(archive.suffix+'.sha256').write_text(digest+'  '+archive.name+'\n')
print(json.dumps({'archive':str(archive),'sha256':digest,'runtime_dependencies':dependencies},indent=2))
