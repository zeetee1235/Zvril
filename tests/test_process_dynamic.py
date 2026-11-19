"""Dynamically linked glibc process execution through the original loader.

The target is a normal dynamic PIE. Zvril maps the executable and its PT_INTERP,
then executes the recorded ld.so/glibc startup path instruction by instruction
through Remill and MCJIT. This is a bounded observed-path comparison, not a
claim that every DSO or relocation form is supported.
"""
import json
from pathlib import Path
import resource
import subprocess
import sys
import tempfile

EXE, CC, ROOT = Path(sys.argv[1]).resolve(), sys.argv[2], Path(sys.argv[3]).resolve()

def run(args, expected=0, timeout=900, **kwargs):
    p = subprocess.run(list(map(str, args)), capture_output=True,
                       timeout=timeout, **kwargs)
    assert p.returncode == expected, (args, p.returncode, p.stdout[-4000:], p.stderr[-4000:])
    return p

with tempfile.TemporaryDirectory(prefix='zvril-dynamic-') as temporary:
    root = Path(temporary)
    source = root / 'dynamic.c'
    source.write_text('#include <stdio.h>\nint main(void){volatile double value=81.0;printf("dynamic:%.0f\\n",value);return 7;}\n')
    binary = root / 'dynamic'
    run([CC, '-O1', source, '-o', binary], timeout=60)
    native = run([binary], 7, timeout=10,
                 preexec_fn=lambda: resource.setrlimit(resource.RLIMIT_CORE, (0, 0)))
    assert native.stdout == b'dynamic:81\n', native.stdout
    output = root / 'run'
    result = json.loads(run([
        EXE, 'run', binary, '--allow-exec', '--sysroot', '/', '--out', output,
        '--json', '--timeout-ms', 600000, '--max-steps', 5000000,
        '--max-modules', 20000, '--memory-mb', 256,
        '--resident-modules', 1024]).stdout)
    process = result['process']
    assert process['status'] == 'EXECUTED' and process['guest_exit_code'] == 7, {
        key: process.get(key) for key in ['status', 'guest_exit_code', 'error']}
    assert bytes.fromhex(process['stdout_hex']) == native.stdout
    assert bytes.fromhex(process['stderr_hex']) == native.stderr
    assert (output / 'stdout.bin').read_bytes() == native.stdout
    assert process['interpreter_bias'] != '0x0'
    assert all(row['llvm_verified'] for row in process['modules'])
    record = {'native_comparisons': 1, 'dynamic_loader': True,
              'instructions': process['instructions'],
              'compiled_modules': process['compiled_modules'],
              'syscalls': process['syscall_count']}
    if len(sys.argv) > 4:
        destination = Path(sys.argv[4])
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(json.dumps(record, indent=2) + '\n')
    print(json.dumps(record))
