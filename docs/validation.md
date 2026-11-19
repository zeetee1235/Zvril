# Validation

Last full run: **2026-11-20**, Fedora 44 x86-64, kernel 7.2.11, 24 cores,
GCC 16.2.1, LLVM/Clang 22.1.8, glibc 2.43.

```sh
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build -j 16
ctest --test-dir build --output-on-failure
```

Result: **23/23 tests passed, 1028.43 s** on a clean source copy built
with `-j 16`. The same suite also passed from the development tree
(1024.26 s).

| Check | Observed |
|---|---|
| Static lifting corpus | 10 projects x 1,000 inputs, 0 mismatches / 0 UNKNOWN |
| ELF/CLI regression | 795 CLI invocations, 732 malformed cases, 16 real fixtures |
| ISA differential | 28,000 integer/ABI comparisons |
| REP / DIV | 14,336 / 16,000 state comparisons incl. faults |
| Aggregate ABI | 36 native comparisons, 36 packet wrappers / 72 calls |
| Dynamic glibc PIE + FP varargs | 92,684 instructions, exit 7, stdout match |
| Static C++ exceptions | stripped, 1,253,188 instructions, exit 0 |
| Dynamic C++ exceptions | stripped PIE, 2,629,961 instructions, exit 0 |
| pthread create/join | 95,757 instructions, 2 tasks exited |
| dlopen + IFUNC sqrt | 123,796 instructions, `dlopen:9` |
| x87 long double | 136,852 instructions, `x87:6.0` |
| `/bin/echo` | 126,377 instructions, output match |
| `/bin/cat` | 139,883 instructions, 42 syscalls |
| `/bin/ls` | 504,972 instructions, 90 syscalls, directory output match |
| virtual mkdir/open/rename/unlink/rmdir | 39 instructions, native exit 0 |

## What the numbers mean

`TESTED`/`EXECUTED` means the observed input and path matched native behavior.
It is not a formal equivalence proof. Results depend on the host glibc,
compiler, kernel, and filesystem. The tests compare against a native run on the
same host; they do not hard-code cross-host hashes.

## Not yet validated

- clean Ubuntu/RHEL/Alpine VM installation
- ASan/UBSan full suite after the latest release
- arbitrary real-world applications, GUI, servers, databases
- full syscall coverage, sockets, epoll, io_uring
- parallel memory ordering, pthread cancellation, PI robust futex
- AVX/AVX-512/XSAVE and multi-module TLS
- process replay/export and independent recompilation packaging

Reports and per-test records are under `build/test-results/`; they are local
artifacts and are not committed.
