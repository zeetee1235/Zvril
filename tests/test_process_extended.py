"""Dynamic glibc pthread and dlopen differential tests.

Both fixtures exercise DSO loader/runtime paths that go beyond a single
executable: pthread_create/join uses clone3, TLS, futex and task exit; dlopen
loads libm through the original ld.so, resolves an IFUNC symbol and executes
its code. Each comparison is bounded to the observed guest path.
"""
import json
from pathlib import Path
import resource
import subprocess
import sys
import tempfile

EXE, CC, ROOT = Path(sys.argv[1]).resolve(), sys.argv[2], Path(sys.argv[3]).resolve()

def run(args, expected=0, timeout=1200, **kwargs):
    p = subprocess.run(list(map(str, args)), capture_output=True,
                       timeout=timeout, **kwargs)
    assert p.returncode == expected, (args, p.returncode, p.stdout[-4000:], p.stderr[-4000:])
    return p

CASES = [
    ('pthread', ['-O1', '-pthread'], b'pthread:21:42\n', 'pthread'),
    ('dlopen', ['-O1', '-ldl'], b'dlopen:9\n', 'dlopen'),
]

with tempfile.TemporaryDirectory(prefix='zvril-extended-') as temporary:
    root = Path(temporary)
    cases = []
    for name, flags, expected_output, kind in CASES:
        source = ROOT / f'tests/fixtures/process_{name}.c'
        binary = root / name
        compiled = subprocess.run([CC, *flags, source, '-o', binary],
                                  capture_output=True, timeout=300)
        if compiled.returncode:
            print(json.dumps({'skipped': name,
                              'stderr': compiled.stderr.decode(errors='replace')[-1000:]}))
            sys.exit(0)
        native = run([binary], 0, timeout=30,
                     preexec_fn=lambda: resource.setrlimit(resource.RLIMIT_CORE, (0, 0)))
        assert native.stdout == expected_output, (name, native.stdout)
        output = root / ('run-' + name)
        result = json.loads(run([
            EXE, 'run', binary, '--allow-exec', '--sysroot', '/', '--out', output,
            '--json', '--timeout-ms', 900000, '--max-steps', 5000000,
            '--max-modules', 30000, '--memory-mb', 512,
            '--resident-modules', 1024]).stdout)
        process = result['process']
        assert process['status'] == 'EXECUTED' and process['guest_exit_code'] == 0, {
            key: process.get(key) for key in ['status', 'guest_exit_code', 'error']}
        assert bytes.fromhex(process['stdout_hex']) == native.stdout
        assert bytes.fromhex(process['stderr_hex']) == native.stderr
        if kind == 'pthread':
            assert len(process['threads']) == 2
            assert all(thread['exited'] for thread in process['threads'])
            assert any(row['number'] in (56, 435) for row in process['syscalls'])
        cases.append({'case': kind, 'instructions': process['instructions'],
                      'compiled_modules': process['compiled_modules'],
                      'syscalls': process['syscall_count']})
    record = {'native_comparisons': len(cases), 'cases': cases}
    if len(sys.argv) > 4:
        destination = Path(sys.argv[4])
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(json.dumps(record, indent=2) + '\n')
    print(json.dumps(record))
