# Compatibility and limits

This table describes observed support, not a claim that every form is verified.
Unsupported behavior is rejected with a diagnostic.

## Host

| Area | Support |
|---|---|
| Architecture | x86-64 only |
| OS | Linux with glibc. Fedora 44 is fully tested; Ubuntu 24.04 with LLVM 22 has verified build and core process tests |
| Toolchain | LLVM/Clang/llvm-link 22.x, CMake 3.21+, C++20 |
| Known gaps | musl/Alpine, non-x86-64, full Ubuntu/RHEL VM qualification |

## Static lifting / verification

| Area | Observed support | Remaining |
|---|---|---|
| ELF | ELF64 LE x86-64, EXEC/DYN, PT_LOAD/BSS/RWX, extended section/symbol indices | Full ELF extensions |
| Discovery | Symbols, .eh_frame/FDE, sectionless EH search table, bounded direct calls | Complete stripped-function discovery, arbitrary heuristics |
| CFG | Direct branch/loop/call/ret/tail/recursion; bounded jump tables; GOT/RELRO indirect calls | Arbitrary indirect control flow |
| Integers | GPR/partial registers, defined FLAGS, 8/16/32/64-bit div/idiv, faults | Every encoding/flag combination |
| SIMD | SSE2/scalar double, AVX2 YMM, AVX-512 bitcode build | Full AVX/AVX-512 forms, MXCSR exceptions |
| Relocations | REL/RELA, RELR, PC32/PLT32/32/32S, GLOB_DAT/JUMP_SLOT, TLS subset | COPY/IRELATIVE static model, text relocations |
| ABI | Scalar integer/SSE/stack/varargs and explicit aggregate contracts | Union auto-classification, X87/vector ABI |
| libc model | mem*/str* and malloc/free family; C locale ctype | Arbitrary libc |
| TLS | Single-module variant II, FS base, TLSDESC subset | Multi-module TLS, GS/TCB details |

## Dynamic execution

| Area | Observed support | Remaining |
|---|---|---|
| Loader | PT_INTERP with original ld.so, static PIE, dynamic glibc PIE | Own DSO search/interposition/COPY/text-relocation model |
| Processes | One cooperative host thread, up to 64 guest tasks | Parallel host threads and memory ordering |
| Threads | clone/clone3 subset, FS/GS, robust list, futex wait/wake | Cancellation, PI robust futex, timed futex |
| Signals | sync faults, pending signals, sigaction/procmask, sigreturn, altstack | Realtime queued signals, XSAVE frames |
| Files | sysroot open/stat/statx/statfs/getdents/readv/writev, virtual mkdir/unlink/rename/truncate | Symlink-faithful lstat, sockets, epoll, io_uring, real ioctl |
| FPU | FXSAVE/FXRSTOR, XMM/x87 ST round-trip, x87 f80 load/store, FUCOMI, long double printf | XSAVE, AVX-512 state, full x87 exceptions |
| C++ | Static/dynamic libstdc++ throw/catch/destructor/rethrow | Full personality/cleanup matrix |
| Atomics | Serialized LOCK XADD/CMPXCHG/8B/16B | Parallel atomic ordering |

## Performance

Dynamic execution compiles one LLVM module per distinct `(PC, bytes)` and
executes one instruction per dispatch. On the validation host:

- small glibc programs: roughly 1,000-12,000 guest instructions/sec
- 1.5-2 GiB RSS for the dynamic tests
- full 23-test suite: about 17 minutes on 24 cores

This is suitable for analysis and differential testing, not for interactive or
production workloads.

## Safety

`run` is deterministic but not an isolation boundary. `verify` uses
Landlock/seccomp in a separate worker; that does not protect `run`. Do not use
Zvril to execute untrusted code without an external sandbox.
