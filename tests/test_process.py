"""Functional ELF process/LLVM execution comparisons; no generated fuzz input."""
import json
import re
import resource
import signal
from pathlib import Path
import subprocess
import sys
import tempfile

EXE, CC, ROOT = Path(sys.argv[1]).resolve(), sys.argv[2], Path(sys.argv[3]).resolve()

def invoke(args, expected=0, **kwargs):
    result = subprocess.run(list(map(str,args)), capture_output=True, timeout=180, **kwargs)
    assert result.returncode == expected, (args, result.returncode, result.stdout[-4000:], result.stderr[-2000:])
    return result

with tempfile.TemporaryDirectory(prefix='zvril-process-') as temporary:
    d = Path(temporary)
    count = 0
    summary = []
    for fixture, expected, arguments, source_input in [
        ('start', 23, ['alpha', 'beta'], b'process input\x00\xff\n'),
        ('jit', 37, [], b''),
        ('threads', 41, [], b''),
        ('cpp', None, ['compiler'], b''),
    ]:
        for pie in [False, True]:
            binary = d / f'{fixture}-{pie}'
            flags = ['-O1','-fPIE' if pie else '-fno-pie','-ffreestanding','-fno-builtin','-fno-exceptions','-fno-rtti','-fno-stack-protector'] if fixture=='cpp' else []
            extension = 'cpp' if fixture=='cpp' else 'S'
            invoke([CC, '-nostdlib', '-static-pie' if pie else '-static', '-Wl,--build-id=none', *flags,
                    ROOT / f'tests/fixtures/process_{fixture}.{extension}', '-o', binary])
            # Dynamic execution must work without .symtab or FDE function bounds.
            invoke(['strip', '--strip-all', binary])
            native = subprocess.run([binary, *arguments], input=source_input, env={'TEST_MODE':'yes'}, capture_output=True, timeout=5, preexec_fn=lambda:resource.setrlimit(resource.RLIMIT_CORE,(0,0)))
            assert (expected is None and native.returncode>=0 and native.stdout==b'cpp\n') or native.returncode == expected, (fixture, pie, native.returncode, native.stderr)
            input_file = d / 'stdin.bin'
            input_file.write_bytes(source_input)
            out = d / f'run-{fixture}-{pie}'
            result = json.loads(invoke([EXE, 'run', binary, '--allow-exec', '--out', out,
                  '--stdin', input_file, '--env', 'TEST_MODE=yes', '--timeout-ms', 120000, '--resident-modules', 8,
                  '--json', '--', *arguments]).stdout)
            process = result['process']
            assert process['status'] == 'EXECUTED' and process['guest_exit_code'] == native.returncode, {key:process.get(key) for key in ['status','guest_exit_code','error','threads','syscalls']}
            assert bytes.fromhex(process['stdout_hex']) == native.stdout
            assert bytes.fromhex(process['stderr_hex']) == native.stderr
            assert (out / 'stdout.bin').read_bytes() == native.stdout
            assert (out / 'stderr.bin').read_bytes() == native.stderr
            assert all(row['llvm_verified'] and (out / row['module']).is_file() and (out / row['ir']).is_file() for row in process['modules'])
            assert all(re.fullmatch('[0-9a-f]{64}', row[field]) for row in process['modules'] for field in ['semantics_sha256','runtime_sha256'])
            assert process['jit_resident_peak'] <= 8 and process['jit_evictions'] > 0
            if fixture == 'jit':
                assert process['code_version_changes'] == 1, process['code_version_changes']
                assert process['jit_reloads'] > 0
                assert any(row['number'] == 9 for row in process['syscalls'])
            if fixture == 'threads':
                assert len(process['threads']) == 2 and all(t['exited'] for t in process['threads'])
                assert any(row['number'] == 202 for row in process['syscalls']), process['syscalls']
            assert result['source_sha256'] and result['backend'] == 'remill'
            summary.append({'fixture': fixture, 'pie':pie, 'instructions':process['instructions'], 'modules':process['compiled_modules']})
            count += 1
    def small(name, body):
        source = d / (name + '.S')
        source.write_text('.global _start\n.text\n_start:\n'+body+'\n.section .note.GNU-stack,"",@progbits\n')
        binary = d / name
        invoke([CC, '-nostdlib', '-static', source, '-o', binary])
        return binary
    math = small('math', '''
movsd value(%rip),%xmm0
sqrtsd %xmm0,%xmm1
cvttsd2si %xmm1,%eax
cmp $9,%eax
jne 1f
mov $60,%eax
xor %edi,%edi
syscall
1: mov $60,%eax
mov $1,%edi
syscall
.section .rodata
.balign 8
value: .double 81.0''')
    native = subprocess.run([math], capture_output=True, timeout=5,
                            preexec_fn=lambda:resource.setrlimit(resource.RLIMIT_CORE,(0,0)))
    assert native.returncode == 0, native.returncode
    result = json.loads(invoke([EXE,'run',math,'--allow-exec','--out',d/'math-run','--json']).stdout)
    assert result['process']['status'] == 'EXECUTED' and result['process']['guest_exit_code'] == 0
    fsmut_dir = str(d / 'fsmutdir')
    fsmut = small('fsmut', f'''
mov $83,%eax
lea fsmut_dir(%rip),%rdi
mov $0755,%esi
syscall
test %rax,%rax
jne 9f
mov $2,%eax
lea fsmut_old(%rip),%rdi
mov $0x241,%esi
mov $0644,%edx
syscall
test %rax,%rax
js 9f
mov %rax,%rdi
mov $1,%eax
lea fsmut_message(%rip),%rsi
mov $3,%edx
syscall
mov $3,%eax
syscall
mov $82,%eax
lea fsmut_old(%rip),%rdi
lea fsmut_new(%rip),%rsi
syscall
test %rax,%rax
jne 9f
mov $87,%eax
lea fsmut_new(%rip),%rdi
syscall
test %rax,%rax
jne 9f
mov $84,%eax
lea fsmut_dir(%rip),%rdi
syscall
test %rax,%rax
jne 9f
mov $60,%eax
xor %edi,%edi
syscall
9: mov $60,%eax
mov $1,%edi
syscall
.section .rodata
fsmut_dir: .asciz "{fsmut_dir}"
fsmut_old: .asciz "{fsmut_dir}/a"
fsmut_new: .asciz "{fsmut_dir}/b"
fsmut_message: .ascii "ok\\n"''')
    native = subprocess.run([fsmut], capture_output=True, timeout=5,
                            preexec_fn=lambda:resource.setrlimit(resource.RLIMIT_CORE,(0,0)))
    assert native.returncode == 0, native.returncode
    result = json.loads(invoke([EXE,'run',fsmut,'--allow-exec','--sysroot','/','--out',d/'fsmut-run','--json']).stdout)
    assert result['process']['status'] == 'EXECUTED' and result['process']['guest_exit_code'] == 0
    unknown = small('unknown', 'mov $9999,%eax\nsyscall')
    result = json.loads(invoke([EXE,'run',unknown,'--allow-exec','--out',d/'unknown-run','--json'],1).stdout)
    assert result['process']['error']['code'] == 'E_PROCESS_SYSCALL'
    assert result['status'] == 'BLOCKED'
    loop = small('loop', 'jmp _start')
    result = json.loads(invoke([EXE,'run',loop,'--allow-exec','--out',d/'loop-run','--max-steps','8','--json'],1).stdout)
    assert result['process']['instructions'] == 8 and result['process']['compiled_modules'] == 1
    assert result['process']['error']['code'] == 'E_PROCESS_RESOURCE'
    nx = small('nx', 'lea _start(%rip),%rax\nand $-4096,%rax\nmov %rax,%rdi\nmov $4096,%esi\nmov $3,%edx\nmov $10,%eax\nsyscall\nnop')
    result = json.loads(invoke([EXE,'run',nx,'--allow-exec','--out',d/'nx-run','--json'],1).stdout)
    assert result['process']['error']['code'] == 'E_PROCESS_FETCH'
    for name,body,kind in [
        ('cas-readonly', 'xor %eax,%eax\nmov $1,%edx\nlock cmpxchg %edx,target(%rip)\nud2\n.section .rodata\ntarget:.long 7', '2'),
        ('cas-unaligned', 'lea target+1(%rip),%rdi\nlock cmpxchg16b (%rdi)\nud2\n.data\n.balign 16\ntarget:.quad 7,9,11', '9'),
    ]:
        binary=small(name,body)
        native=subprocess.run([binary],capture_output=True,timeout=5,preexec_fn=lambda:resource.setrlimit(resource.RLIMIT_CORE,(0,0)))
        assert native.returncode==-signal.SIGSEGV,(name,native.returncode)
        record=json.loads(invoke([EXE,'run',binary,'--allow-exec','--out',d/(name+'-run'),'--json'],1).stdout)
        assert record['process']['error']['code']=='E_PROCESS_FAULT',record
        assert 'fault '+kind+' at' in record['process']['error']['message'],record['process']['error']
    denied = json.loads(invoke([EXE,'run',unknown,'--out',d/'no-exec','--json'],3).stdout)
    assert denied['diagnostics'][0]['code'] == 'E_CLI' and not (d/'no-exec').exists()
    # An existing directory must retain files even on a rejected invocation.
    existing = d/'existing';existing.mkdir();(existing/'report.json').write_text('keep')
    invoke([EXE,'run',unknown,'--allow-exec','--out',existing,'--json'],2)
    assert (existing/'report.json').read_text() == 'keep'
    dynamic = d/'dynamic'
    source = d/'dynamic.c';source.write_text('int main(void){return 0;}')
    invoke([CC,source,'-o',dynamic])
    loader = json.loads(invoke([EXE,'run',dynamic,'--allow-exec','--out',d/'loader-run','--json'],1).stdout)
    assert loader['diagnostics'][0]['code'] == 'E_PROCESS_LOADER'
    record = {'native_process_comparisons':count,'negative_contracts':8,'cases':summary}
    if len(sys.argv)>4:
        destination=Path(sys.argv[4]);destination.parent.mkdir(parents=True,exist_ok=True)
        destination.write_text(json.dumps(record,indent=2)+'\n')
    print(json.dumps(record))
