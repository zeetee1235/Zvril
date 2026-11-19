# CLI

```
zvril doctor   [--json]
zvril demo     [--json]
zvril inspect  INPUT [--json] [--out DIR] [--max-bytes N]
               [--discover-calls] [--max-instructions N] [--max-functions N]
zvril functions INPUT [--json] [--out DIR] [--max-bytes N]
               [--discover-calls] [--max-instructions N] [--max-functions N]
zvril lift     INPUT (--symbol NAME | --address VA) --out DIR [--json]
               [--size N] [--isa amd64|amd64_avx|amd64_avx512]
               [--abi FILE] [--max-instructions N] [--max-functions N]
               [--max-blocks N] [--timeout-ms N] [--memory-mb N]
               [--max-bytes N] [--strict | --allow-partial]
zvril batch    INPUT --out DIR [--jobs N] [--symbols A,B] [--isa ISA]
               [--timeout-ms N] [--max-bytes N] [--json]
zvril verify   INPUT --symbol NAME --cases DIR --allow-exec [--out DIR]
               [--json] [--native-trace] [--timeout-ms N] [--max-bytes N]
zvril run      INPUT --allow-exec --out DIR [--stdin FILE]
               [--env NAME=VALUE] [--sysroot DIR]
               [--max-steps N] [--max-modules N] [--resident-modules N]
               [--timeout-ms N] [--memory-mb N] [--max-bytes N]
               [--isa amd64|amd64_avx|amd64_avx512] [-- ARG...]
```

`--json` writes a machine-readable report. Commands that accept `--out` create
a new or empty directory and write artifacts there.

## Commands

### doctor

Prints tool version, LLVM version, backend, semantics path, and capability
booleans such as `dynamic_loader`, `cpp_exceptions`,
`guest_pthread_create_join`, `dlopen_via_original_loader`, `signal_delivery`,
and `complete_linux_process`.

### demo

Runs the embedded trusted demo: ELF inspection, function lifting, and a native
comparison. It does not need network or external tools.

### inspect / functions

`inspect` parses ELF metadata without decoding or executing code. `functions`
lists discovered functions; `--discover-calls` adds bounded direct-call
candidates with evidence. `--max-bytes`, `--max-instructions`, and
`--max-functions` bound parsing/discovery.

### lift

Requires `--symbol` or `--address` and `--out`. Options:

- `--size N`: explicit function extent when no sized symbol exists
- `--isa`: `amd64` (default), `amd64_avx`, `amd64_avx512`
- `--abi FILE`: typed SysV wrapper contract
- `--strict`: reject unresolved edges (default behavior for a complete lift)
- `--allow-partial`: emit analysis-only IR and exit 1
- `--timeout-ms`, `--memory-mb`, `--max-functions`, `--max-blocks`: hard limits

### batch

Lifts multiple functions in parallel workers (`--jobs 1..32`) and preserves
per-function failures. Results are sorted deterministically.

### verify

Runs recorded differential cases against a native worker. Requires
`--allow-exec`. `--native-trace` requests the ptrace comparator when the host
permits it. A passing result is `TESTED`, which means the declared inputs and
observation contract matched, not formal equivalence.

### run

Executes a Linux process through Remill + MCJIT. Requires `--allow-exec` and a
new/empty `--out`. `argv[0]` is `INPUT`; arguments after `--` become `argv[1..]`.
The initial environment is empty unless `--env NAME=VALUE` is repeated.

- `--stdin FILE`: at most 1 MiB
- `--sysroot DIR`: host filesystem view for the guest and required for PT_INTERP
- `--max-steps`: default 1,000,000
- `--max-modules`: default 4,096
- `--resident-modules`: default 128
- `--timeout-ms`: default 30,000
- `--memory-mb`: default 64

Guest exit status is `process.guest_exit_code`; the tool's exit status only says
whether the requested operation completed.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Requested operation succeeded |
| 1 | Unsupported, incomplete, `BLOCKED`, or `UNKNOWN` |
| 2 | Internal, output, or toolchain error |
| 3 | Invalid input or CLI |
| 4 | Differential mismatch |

## Environment

- `ZVRIL_SANITIZERS=ON`: ASan/UBSan build; native verification workers disabled
- `ZVRIL_REMILL=OFF`: analysis-only build
- `ZVRIL_FUZZING=ON`: build the ELF parser fuzz harness
- `ZVRIL_CLANG`, `ZVRIL_LLVM_LINK`: override the LLVM 22 tools at configure time
