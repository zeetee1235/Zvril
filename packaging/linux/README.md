# Linux package

`python3 tools/package.py --build build --out dist` installs the executable,
three ISA bitcode libraries, runtime bitcode, public C header, documentation,
schemas and upstream licenses. It runs the installed demo without development
tools in PATH, then creates a tar.gz and SHA-256 manifest.

Run `bin/zvril doctor` and `bin/zvril demo` after unpacking. LLVM/Clang, Remill,
Python, commercial disassemblers and network access are not runtime dependencies.
The archive uses the build host's glibc/C++ ABI and links system libz, libzstd,
libgcc_s, libstdc++, libm and libc. `manifest.json` records actual dependencies.
Build on the oldest supported distro to lower the glibc baseline. The current
Fedora 44 build is not advertised as compatible with older Ubuntu releases.

Native verification and the integrated demo require Landlock ABI 3+, seccomp,
fork and executable JIT memory. Static inspection/lifting do not require Landlock.
A sanitized build deliberately disables native verification workers because
ASan's reserved virtual address space exceeds their 2 GiB limit.

Clean Ubuntu/Fedora VM qualification and a project license selected by the
copyright owner remain release gates. Local package smoke tests do not replace
those gates.
