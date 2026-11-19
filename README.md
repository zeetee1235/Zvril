# Zvril

x86-64 Linux ELF lifting and bounded process execution through Remill, LLVM IR,
and MCJIT.

Zvril selects functions (or starts a real process), decodes x86-64 instructions
with pinned Remill/XED, emits verified LLVM IR, and records provenance back to
the original PC and bytes. The `run` command executes a Linux program one
instruction at a time through Remill semantics and MCJIT instead of calling the
original machine code.

> Status: pre-alpha. x86-64 Linux only. Not a general-purpose emulator,
> compatibility layer, or security sandbox.

## What works

- ET_EXEC / ET_DYN / static PIE ELF loading, relocations, symbol versions
- Selected-function lifting with `module.ll`, `module.bc`, CFG, PC maps
- SysV AMD64 scalar, stack, varargs, and structured ABI wrappers
- Native differential verification for recorded inputs and contracts
- Dynamic execution of glibc programs through the original `ld.so`
- Static and dynamic C++ exceptions (`throw`, unwind destructor, rethrow)
- `pthread_create` / `pthread_join`, TLS, futex, cooperative tasks
- `dlopen` + IFUNC, signal delivery, sigreturn, altstack
- x87 `long double`, FXSAVE/FXRSTOR, FP varargs
- Virtual sysroot file I/O and directory operations (`echo`, `cat`, `ls` tested)
- Deterministic virtual clock, IDs, and randomness; fail-closed on unsupported
  instructions or syscalls

This is **not** a complete v1.0 implementation. Missing: arbitrary indirect
control flow, full ISA/AVX-512/XSAVE, fork/exec/wait, sockets/epoll/io_uring,
parallel host threads, process replay/export, and clean-VM qualification.

## Requirements

### Release binary

- Linux x86-64
- glibc (the current release is built on Fedora 44; older distros are not
  qualified)
- The dynamic process tests additionally use the host `/bin/cat`, `/bin/ls`,
  and `/bin/echo`

### Building from source

- LLVM 22 development package (the build hard-fails on another major version)
- `clang++-22` and `llvm-link-22` (same major as LLVM)
- CMake 3.21+, Ninja or Make
- C++20 compiler
- Python 3.9+
- `gcc`/`g++` for the test fixtures
- 64-bit static glibc and, for the static C++ exception test, static libstdc++

The pinned Remill/XED/gflags/glog sources are vendored. The build does not
download dependencies.

## Supported environments

| Environment | Status |
|---|---|
| Fedora 44, GCC 16, LLVM/Clang 22.1.8, glibc 2.43 | Verified: 23/23 CTest on lab2 |
| Ubuntu 24.04, GCC 13, LLVM/Clang 22 | Verified in a clean container with LLVM 22 from apt.llvm.org |
| Ubuntu 22.04 | Expected with LLVM 22 from apt.llvm.org; not qualified here |
| Other x86-64 glibc distros | Unverified. You must supply LLVM 22 and a 64-bit static libstdc++ for the full suite |
| musl/Alpine | Unsupported (dynamic loader and test assumptions are glibc-specific) |
| Non-x86-64 | Unsupported |

**Reproducibility:** the tests compare each lifted/emulated run against a native
run on the same host. They do not assert a fixed instruction count or hash
across hosts, because glibc, compiler, and kernel versions change the executed
path. On a supported host the suite is deterministic and repeatable; on an
unsupported host the build or individual process tests stop with a clear error
instead of silently passing.

### Ubuntu 24.04

```sh
sudo ./scripts/install-deps-ubuntu.sh
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build -j 4
ctest --test-dir build --output-on-failure
```

The script adds the apt.llvm.org repository, installs LLVM/Clang 22, and
installs the static libstdc++ needed by the C++ exception test. CMake finds
`/usr/lib/llvm-22` automatically.

## Build

```sh
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build -j 4
./build/zvril doctor --json
```

Analysis-only build without Remill:

```sh
cmake -S . -B build-analysis -G Ninja -DCMAKE_BUILD_TYPE=Release -DZVRIL_REMILL=OFF
```

## Quick start

```sh
./build/zvril demo

gcc -shared -fPIC tests/fixtures/lifting.S -o build/native-fixture.so
./build/zvril inspect build/native-fixture.so --json
./build/zvril lift build/native-fixture.so --symbol lift_add --out build/add
./build/zvril batch build/native-fixture.so --symbols lift_add,lift_sum \
  --jobs 2 --out build/batch
./build/zvril verify build/native-fixture.so --symbol lift_add \
  --cases examples/add-cases.json --allow-exec --out build/verified
```

Run a process (static or static PIE):

```sh
cc -nostdlib -static tests/fixtures/process_jit.S -o build/process-jit
./build/zvril run build/process-jit --allow-exec \
  --out build/process-jit-run --json
```

Run a dynamically linked program through the host loader:

```sh
cc -O1 examples/hello.c -o build/hello
./build/zvril run build/hello --allow-exec --sysroot / \
  --timeout-ms 600000 --max-modules 30000 --resident-modules 1024 \
  --out build/hello-run --json
```

Expected: `status` is `EXECUTED`; the target exit code is in
`process.guest_exit_code`; stdout/stderr are in `stdout.bin`, `stderr.bin`, and
the report's hex fields. Dynamic glibc startup usually needs a larger
`--max-modules` and timeout than the conservative defaults.

## Commands

| Command | Purpose |
|---|---|
| `doctor` | Toolchain, backend, capabilities, and process support |
| `demo` | Offline end-to-end demo using embedded trusted fixtures |
| `inspect` | ELF metadata, imports, relocations, functions |
| `functions` | Function discovery, optionally with direct-call candidates |
| `lift` | Lift one selected function to LLVM IR/bitcode |
| `batch` | Lift multiple selected functions with bounded workers |
| `verify` | Run native/lifted differential cases with an explicit contract |
| `run` | Execute a process through Remill + MCJIT |

Exit codes: `0` success, `1` unsupported/incomplete/UNKNOWN, `2` internal,
output, or toolchain error, `3` invalid input/CLI, `4` differential mismatch.

## Process execution model

`run` maps the ELF image into a checked guest address space and begins at the
entry point. Every fetched instruction is decoded, lowered to Remill semantics,
compiled into an independent LLVM module, verified, and executed through MCJIT.
Indirect branches dispatch on the guest RIP, so stripped inputs and runtime
generated code do not require static function bounds.

Dynamic PIE uses PT_INTERP and the original `ld.so` from `--sysroot`; Zvril does
not reimplement the DSO loader. FXSAVE/FXRSTOR and the x87/XMM register banks are
round-tripped so glibc lazy binding and C++ unwinding preserve FP arguments.

Execution is bounded and fail-closed. Unsupported instructions, syscalls,
relocations, or resource limits produce `BLOCKED` and a diagnostic. `EXECUTED`
means the observed path completed; it is not a proof of semantic equivalence.

`run` is not a security boundary. `verify` uses a separate native worker with
Landlock/seccomp, but that isolation does not extend to `run`.

## Tests

```sh
ctest --test-dir build --output-on-failure
```

The full suite currently contains 23 tests and takes about 17 minutes on a
24-core x86-64 host. Heavy process tests are intentionally single-threaded and
can use 1.5-2 GiB RSS.

Individual groups:

```sh
ctest --test-dir build -R cli_and_elf_regression --output-on-failure
ctest --test-dir build -R dynamic_linux_process_execution --output-on-failure
ctest --test-dir build -R cpp_exception_unwind_process --output-on-failure
ctest --test-dir build -R glibc_filesystem_coreutils --output-on-failure
```

The static C++ exception case is skipped when the host has no 64-bit static
libstdc++; the dynamic case still runs. `tools/check_sources.py` verifies the
vendored source blobs.

## Output

Lifting writes `module.ll`, `module.bc`, `functions.json`, `pcmap.json`,
`cfg.json`, `cfg.dot`, `state_layout.json`, `report.json`, and
`LICENSE.remill`. Verification additionally writes `validation.json`.
`run` writes `image.ll/.bc`, per-instruction `step-N.ll/.bc`, `stdout.bin`,
`stderr.bin`, `report.json`, and `LICENSE.remill`.

Output directories must be new or empty. Existing directories are never
silently overwritten.

## Documentation

- [Architecture](docs/architecture.md)
- [CLI and options](docs/cli.md)
- [Compatibility and limits](docs/compatibility.md)
- [Validation](docs/validation.md)
- [Schemas](schemas/)
- [Packaging notes](packaging/linux/README.md)

## License

No product license is declared yet. Remill, XED, LLVM, gflags, glog, and the
vendored corpus retain their upstream licenses in their original source trees.
WarpLift code was not copied or modified.
