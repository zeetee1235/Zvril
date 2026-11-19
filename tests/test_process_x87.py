"""Static x87/long-double differential test.

Remill's x87 semantics use the separate State.st bank and the FPU control
shadow. This fixture forces x87 loads/stores, FUCOMI/FUCOMIP flag production and
glibc's long-double printf path.
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

with tempfile.TemporaryDirectory(prefix='zvril-x87-') as temporary:
    root = Path(temporary)
    binary = root / 'x87'
    run([CC, '-static', '-O1', '-fno-pie', '-fno-stack-protector',
         '-Wl,--build-id=none', ROOT / 'tests/fixtures/process_x87.c', '-o', binary],
        timeout=300)
    native = run([binary], 0, timeout=30,
                 preexec_fn=lambda: resource.setrlimit(resource.RLIMIT_CORE, (0, 0)))
    assert native.stdout == b'x87:6.0\n', native.stdout
    output = root / 'run'
    result = json.loads(run([
        EXE, 'run', binary, '--allow-exec', '--out', output, '--json',
        '--timeout-ms', 600000, '--max-steps', 5000000,
        '--max-modules', 30000, '--memory-mb', 256,
        '--resident-modules', 1024]).stdout)
    process = result['process']
    assert process['status'] == 'EXECUTED' and process['guest_exit_code'] == 0, {
        key: process.get(key) for key in ['status', 'guest_exit_code', 'error']}
    assert bytes.fromhex(process['stdout_hex']) == native.stdout
    record = {'native_comparisons': 1, 'x87_long_double': True,
              'instructions': process['instructions'],
              'compiled_modules': process['compiled_modules']}
    if len(sys.argv) > 4:
        destination = Path(sys.argv[4])
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(json.dumps(record, indent=2) + '\n')
    print(json.dumps(record))
