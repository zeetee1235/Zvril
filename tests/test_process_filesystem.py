"""Host-backed filesystem differential tests using real coreutils.

Each case runs the same system binary natively and through the virtual sysroot.
The guest sees a copy: output files are captured by the virtual filesystem and
never written to the host.
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

with tempfile.TemporaryDirectory(prefix='zvril-fs-') as temporary:
    root = Path(temporary)
    listed = root / 'listed'
    listed.mkdir()
    (listed / 'alpha').write_text('first\nsecond\n')
    (listed / 'beta').write_text('third\n')
    (listed / 'sub').mkdir()
    environment = {'LC_ALL': 'C', 'PATH': '/usr/bin:/bin'}
    cases = [
        ('cat', ['/bin/cat', str(listed / 'alpha')], b'first\nsecond\n'),
        ('ls', ['/bin/ls', str(listed)], b'alpha\nbeta\nsub\n'),
    ]
    records = []
    for name, argv, expected_stdout in cases:
        if not Path(argv[0]).is_file():
            print(json.dumps({'skipped': argv[0]}))
            sys.exit(0)
        native = run(argv, 0, timeout=30, env=environment,
                     preexec_fn=lambda: resource.setrlimit(resource.RLIMIT_CORE, (0, 0)))
        assert native.stdout == expected_stdout, (name, native.stdout)
        output = root / ('run-' + name)
        result = json.loads(run([
            EXE, 'run', argv[0], '--allow-exec', '--sysroot', '/', '--out', output,
            '--json', '--timeout-ms', 600000, '--max-steps', 5000000,
            '--max-modules', 30000, '--memory-mb', 512,
            '--resident-modules', 1024, '--env', 'LC_ALL=C', '--', *argv[1:]
        ]).stdout)
        process = result['process']
        assert process['status'] == 'EXECUTED' and process['guest_exit_code'] == 0, {
            key: process.get(key) for key in ['status', 'guest_exit_code', 'error']}
        assert bytes.fromhex(process['stdout_hex']) == native.stdout
        assert bytes.fromhex(process['stderr_hex']) == native.stderr
        assert (output / 'stdout.bin').read_bytes() == native.stdout
        records.append({'case': name, 'instructions': process['instructions'],
                        'compiled_modules': process['compiled_modules'],
                        'syscalls': process['syscall_count']})
    record = {'native_comparisons': len(records), 'cases': records}
    if len(sys.argv) > 4:
        destination = Path(sys.argv[4])
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(json.dumps(record, indent=2) + '\n')
    print(json.dumps(record))
