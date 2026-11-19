# Architecture

Zvril has two paths that share ELF parsing, Remill semantics, and the runtime
contract.

## Static lifting

```
ELF image ── parse/discover ── CFG ── Remill instruction semantics
                                      │
                                      ▼
                              LLVM module + verifier
                                      │
                                      ▼
                         module.ll / module.bc + provenance
```

- `src/elf/` validates ELF64 x86-64 headers, PT_LOAD, sections, symbols,
  relocations, and symbol versions.
- `src/semantics/lift.cpp` recovers direct CFG edges, emits Remill semantics,
  lowers memory/intrinsic operations, and runs the LLVM verifier.
- `src/abi/sysv.cpp` builds explicit scalar/aggregate SysV wrappers from a
  user contract.
- `src/verify/` runs native and lifted code in separate workers and compares
  declared returns, buffers, globals, and faults.

Function boundaries come from symbols or FDEs. Direct calls are followed;
indirect edges require a relocation proof, an immutable table with bounds, or a
single constant predecessor. Anything unresolved is rejected unless
`--allow-partial` is used.

## Dynamic process execution

```
guest RIP ─ fetch bytes ─ decode with Remill/XED
              │
              ▼
      per-instruction LLVM module
              │
              ▼
       verify + MCJIT + cache
              │
              ▼
      execute one instruction
              │
              ▼
      next RIP ─ dispatch again
```

`src/process/execute.cpp` implements the dispatcher, guest tasks, syscalls, and
the ELF image initializer. `src/process/files.cpp` implements the virtual
sysroot filesystem; `src/process/signals.cpp` implements Linux signal frames.

The cache key is `(PC, exact encoding bytes)`. Modified code produces a new
module; reverting the bytes reuses the old compiled version. The dispatcher
never calls the original machine code.

## Guest runtime

`src/runtime/runtime.c` provides checked paged memory, permissions, initialized
bits, transactions, step budgets, TLS, FS/GS, and libc bridges. Host pointers
are never exposed to guest code.

## Safety model

- All external instructions, intrinsic calls, imports, relocations, and syscalls
  are allow-listed. Unknown behavior is `BLOCKED`, not a stub success.
- Output directories are new or empty; existing files are not overwritten.
- `verify` uses a separate native worker with Landlock/seccomp and resource
  limits. `run` is a deterministic execution environment, not a security
  boundary.
- Reports distinguish `INSPECTED`, `LIFTED`, `PARTIAL`, `TESTED`, `EXECUTED`,
  `BLOCKED`, `UNKNOWN`, and mismatch.

## Toolchain pinning

Remill, XED, gflags, glog, LLVM/Clang, and the corpus are pinned. Vendored
sources are checked by `tools/check_sources.py`; no network access is needed for
a build.
