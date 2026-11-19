"""Record a trusted native program and a bounded Zvril execution on this host."""
import argparse
import json
import os
from pathlib import Path
import resource
import subprocess
import time
p=argparse.ArgumentParser();p.add_argument('--zvril',type=Path,required=True);p.add_argument('--binary',type=Path,required=True);p.add_argument('--out',type=Path,required=True);p.add_argument('--resident',type=int,default=128);p.add_argument('--timeout-ms',type=int,default=600000);p.add_argument('--max-modules',type=int,default=50000);p.add_argument('--memory-mb',type=int,default=256);p.add_argument('arguments',nargs='*');a=p.parse_args()
a.out.mkdir(parents=True,exist_ok=False)
resource.setrlimit(resource.RLIMIT_AS,(12*1024**3,12*1024**3));resource.setrlimit(resource.RLIMIT_CORE,(0,0))
native=subprocess.run([str(a.binary.resolve()),*a.arguments],capture_output=True,timeout=20)
start=time.monotonic()
with (a.out/'report.json').open('wb') as out,(a.out/'stderr.log').open('wb') as err:
 result=subprocess.run([str(a.zvril.resolve()),'run',str(a.binary.resolve()),'--allow-exec','--sysroot','/','--out',str(a.out/'lifted'),'--json','--resident-modules',str(a.resident),'--max-modules',str(a.max_modules),'--max-steps','5000000','--memory-mb',str(a.memory_mb),'--timeout-ms',str(a.timeout_ms),'--',*a.arguments],stdout=out,stderr=err,timeout=a.timeout_ms/1000+30)
record={'tool_returncode':result.returncode,'native_returncode':native.returncode,'native_stdout_hex':native.stdout.hex(),'native_stderr_hex':native.stderr.hex(),'peak_child_rss_kib':resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss,'elapsed_seconds':time.monotonic()-start,'host':os.uname().nodename}
text=(a.out/'report.json').read_text()
if text:
 document=json.loads(text);process=document.get('process',{})
 record['process']={key:process.get(key) for key in ['status','guest_exit_code','stdout_hex','stderr_hex','instructions','compiled_modules','jit_resident_peak','jit_evictions','jit_reloads','error']}
 record['last_syscalls']=process.get('syscalls',[])[-5:]
 record['matches_native']=result.returncode==0 and process.get('guest_exit_code')==native.returncode and process.get('stdout_hex')==native.stdout.hex() and process.get('stderr_hex')==native.stderr.hex()
(a.out/'summary.json').write_text(json.dumps(record,indent=2)+'\n');print(json.dumps(record,indent=2))
