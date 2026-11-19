# Corpus baseline

corpus-gcc16-linux.json is the measured 0.3.0 baseline for the pinned corpus,
seed 3619 and the recorded GCC build. It contains 10 functions × 1,000 cases.
Nine functions use bitwise returns; sdscmp explicitly uses an i32 sign contract.

Run tools/run_corpus.py with 1,000 cases and compare its manifest using
tools/check_regression.py. Changed compiler/source/cases/contracts are rejected
as incomparable. Review and regenerate the baseline deliberately for a new
toolchain; do not remove those checks to make a failed comparison green.

The source ELF hashes were reproduced by compiling all 10 inputs in a second
directory. This baseline covers selected functions under scalarized -O1 build
flags, not whole-library or arbitrary optimized-ELF support.
