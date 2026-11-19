"""C++ exception and unwinder differential tests.

The fixture exercises a real throw/catch, a destructor during unwinding, and a
rethrow inside a catch(...) block. Two builds are compared when available:

* static non-PIE with libstdc++/libgcc/glibc linked in, stripped afterwards;
* host dynamic PIE through PT_INTERP/ld.so with ``--sysroot /``.

A static build is skipped when the host has no 64-bit static libstdc++.
"""
import json
from pathlib import Path
import resource
import shutil
import subprocess
import sys
import tempfile

EXE, CC, ROOT = Path(sys.argv[1]).resolve(), sys.argv[2], Path(sys.argv[3]).resolve()
CXX = shutil.which('c++') or shutil.which('g++')

def run(args, expected=0, timeout=1200, **kwargs):
    p = subprocess.run(list(map(str, args)), capture_output=True,
                       timeout=timeout, **kwargs)
    assert p.returncode == expected, (args, p.returncode, p.stdout[-4000:], p.stderr[-4000:])
    return p

def compare(binary, output, dynamic):
    native = run([binary], 0, timeout=30,
                 preexec_fn=lambda: resource.setrlimit(resource.RLIMIT_CORE, (0, 0)))
    assert native.stdout == b'exceptions:24\n', native.stdout
    command = [EXE, 'run', binary, '--allow-exec', '--out', output, '--json',
               '--timeout-ms', 900000, '--max-steps', 5000000,
               '--max-modules', 30000, '--memory-mb', 512,
               '--resident-modules', 1024]
    if dynamic:
        command += ['--sysroot', '/']
    result = json.loads(run(command).stdout)
    process = result['process']
    assert process['status'] == 'EXECUTED' and process['guest_exit_code'] == 0, {
        key: process.get(key) for key in ['status', 'guest_exit_code', 'error']}
    assert bytes.fromhex(process['stdout_hex']) == native.stdout
    assert bytes.fromhex(process['stderr_hex']) == native.stderr
    assert (output / 'stdout.bin').read_bytes() == native.stdout
    assert all(row['llvm_verified'] for row in process['modules'])
    return {'dynamic': dynamic, 'instructions': process['instructions'],
            'compiled_modules': process['compiled_modules'],
            'syscalls': process['syscall_count']}

with tempfile.TemporaryDirectory(prefix='zvril-exceptions-') as temporary:
    root = Path(temporary)
    source = ROOT / 'tests/fixtures/process_exceptions.cpp'
    if not CXX:
        print(json.dumps({'skipped': 'no C++ compiler'}))
        sys.exit(0)
    cases, skipped = [], []
    for dynamic in [True, False]:
        binary = root / ('exceptions-dynamic' if dynamic else 'exceptions-static')
        flags = ['-O1', '-Wl,--build-id=none']
        if not dynamic:
            flags += ['-static', '-fno-pie', '-fno-stack-protector']
        compiled = subprocess.run([CXX, *flags, source, '-o', binary],
                                  capture_output=True, timeout=300)
        if compiled.returncode:
            skipped.append({'dynamic': dynamic,
                            'reason': 'static libstdc++ unavailable' if not dynamic
                                      else 'dynamic C++ link unavailable',
                            'stderr': compiled.stderr.decode(errors='replace')[-1000:]})
            continue
        # The unwinder and discovery must work without .symtab, FDE symbol names
        # or C++ runtime symbol hints.
        run(['strip', '--strip-all', binary])
        cases.append(compare(binary, root / ('run-dynamic' if dynamic else 'run-static'),
                             dynamic))
    if not cases:
        print(json.dumps({'skipped': skipped}))
        sys.exit(0)
    record = {'native_comparisons': len(cases), 'exceptions': True,
              'cases': cases, 'skipped': skipped}
    if len(sys.argv) > 4:
        destination = Path(sys.argv[4])
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(json.dumps(record, indent=2) + '\n')
    print(json.dumps(record))
