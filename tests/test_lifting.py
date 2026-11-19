"""End-to-end Remill tests using trusted, newly written native fixtures.

Only this test harness executes original code. zvril lift remains static.
The comparison contract is explicit SysV integer registers/return, defined ADD
flags, callee-saved registers, input-region writes and bounded runtime faults.
"""
import ctypes as C
import hashlib
import json
import math
from pathlib import Path
import random
import shutil
import struct
import subprocess
import sys
import tempfile

EXE, CC, CLANG, ROOT, RESULT = sys.argv[1:]
ROOT = Path(ROOT)
MASK = (1 << 64) - 1
SEED = 0x5A5611
SENTINEL = 0xFFFFFFFFFFFFFFF0
BASE = 0x10000000
SIZE = 32768
SP_OFFSET = SIZE - 8
CALLEE_SAVED = (3, 5, 12, 13, 14, 15)


class Memory(C.Structure):
    _fields_ = [("data", C.c_void_p)] + [(name, C.c_uint64) for name in (
        "base", "size", "fault", "fault_pc", "fault_address", "fault_width", "steps_left", "return_pc")]


def run(args):
    result = subprocess.run(list(map(str, args)), capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, (args, result.returncode, result.stdout, result.stderr)
    return result


def cli(elf, name, output, expected=0, extra=()):
    result = subprocess.run([EXE, "lift", str(elf), "--symbol", name, "--out", str(output), "--json", *map(str, extra)],
                            capture_output=True, text=True, timeout=30)
    assert result.returncode == expected, (name, result.returncode, result.stdout, result.stderr)
    assert not result.stderr, result.stderr
    report = json.loads(result.stdout)
    assert report["status"] == ("LIFTED" if expected == 0 else "BLOCKED")
    assert not list(output.glob(".zvril-stage*"))
    if not expected:
        assert report["backend"] == "remill"
        assert all(f["llvm_verified"] and not f["tested_cases"] for f in report["functions"])
    else:
        assert not (output / "module.ll").exists()
        assert not (output / "module.bc").exists()
    return report


class Lifted:
    def __init__(self, path):
        self.lib = C.CDLL(str(path))
        self.lib.zvril_state_size.restype = C.c_uint64
        self.lib.zvril_state_get.argtypes = [C.c_void_p, C.c_uint32]
        self.lib.zvril_state_get.restype = C.c_uint64
        self.lib.zvril_state_set.argtypes = [C.c_void_p, C.c_uint32, C.c_uint64]
        self.lib.zvril_lifted.argtypes = [C.c_void_p, C.c_uint64, C.POINTER(Memory)]
        self.lib.zvril_lifted.restype = C.c_void_p

    def execute(self, entry, a=0, b=0, data=b"", pointer=False, budget=20000, size=SIZE, base=BASE):
        state = C.create_string_buffer(self.lib.zvril_state_size())
        storage = (C.c_ubyte * SIZE)()
        if data:
            C.memmove(storage, data, len(data))
        C.c_uint64.from_buffer(storage, SP_OFFSET).value = SENTINEL
        memory = Memory(C.addressof(storage), base, size, 0, 0, 0, 0, budget, SENTINEL)
        for index in CALLEE_SAVED:
            self.lib.zvril_state_set(state, index, 0xC0DEC0DE00000000 + index)
        self.lib.zvril_state_set(state, 7, base if pointer else a)
        self.lib.zvril_state_set(state, 6, b)
        self.lib.zvril_state_set(state, 4, base + SP_OFFSET)
        returned = self.lib.zvril_lifted(state, entry, C.byref(memory))
        assert returned == C.addressof(memory)
        regs = [self.lib.zvril_state_get(state, index) for index in range(24)]
        if not memory.fault:
            assert regs[4] == base + SP_OFFSET + 8, regs
            assert regs[16] == SENTINEL, regs
            assert all(regs[index] == 0xC0DEC0DE00000000 + index for index in CALLEE_SAVED)
        return regs, bytes(storage), memory


def exercise(directory):
    assembly = ROOT / "tests/fixtures/lifting.S"
    elf = directory / "native.so"
    run([CC, "-shared", "-fPIC", assembly, "-o", elf])
    native = C.CDLL(str(elf))
    native.native_add_flags.argtypes = [C.c_uint64, C.c_uint64, C.POINTER(C.c_uint64)]
    summaries = []
    total = 0
    names = ("lift_add", "lift_partial", "lift_shift", "lift_sum", "lift_store", "lift_stack",
             "lift_call", "lift_tail", "lift_factorial", "lift_sse", "lift_float", "lift_unaligned")
    for name in names:
        output = directory / name
        report = cli(elf, name, output)
        root_address = int(report["lifting"]["entry"], 16)
        if name in ("lift_call", "lift_tail"):
            assert len(report["functions"]) == 2
        if name == "lift_add":
            executable = output / "recompiled"
            run([CLANG, "-O2", "-Wno-override-module", "-I", ROOT / "include", "-x", "c",
                 ROOT / "examples/call_lifted.c", "-x", "ir", output / "module.bc", "-o", executable])
            assert run([executable, hex(root_address), "40", "2"]).stdout.strip() == "42"
        pcmap = json.loads((output / "pcmap.json").read_text())["instructions"]
        assert len(pcmap) == report["lifting"]["instruction_count"]
        assert len({i["pc"] for i in pcmap}) == len(pcmap)
        layout = json.loads((output / "state_layout.json").read_text())
        assert any(r["name"] == "RAX" and r["bytes"] == 8 for r in layout["registers"])
        if opt := shutil.which("opt"):
            run([opt, "-passes=verify", "-disable-output", output / "module.bc"])
        original = getattr(native, name)
        original.argtypes = [C.c_void_p if name in ("lift_sum", "lift_store", "lift_sse", "lift_unaligned") else C.c_uint64, C.c_uint64]
        original.restype = C.c_uint64
        compared = 0
        for level in (0, 2):
            shared = output / f"lifted-o{level}.so"
            # Compile both the textual and bitcode artifacts.
            run([CLANG, f"-O{level}", "-shared", "-fPIC", "-Wno-override-module",
                 output / ("module.ll" if level == 0 else "module.bc"), "-o", shared])
            lifted = Lifted(shared)
            assert layout["state_bytes"] == lifted.lib.zvril_state_size()
            rng = random.Random(SEED)
            for index in range(1000):
                a = rng.getrandbits(64)
                b = rng.getrandbits(64)
                data = b""
                pointer = name in ("lift_sum", "lift_store", "lift_sse", "lift_unaligned")
                if name == "lift_sum":
                    b = index % 65
                    data = rng.randbytes(b)
                elif name == "lift_store":
                    data = rng.randbytes(8)
                elif name == "lift_sse":
                    data = rng.randbytes(48)
                elif name == "lift_unaligned":
                    data = rng.randbytes(16)
                elif name == "lift_factorial":
                    a = index % 13
                elif name == "lift_float":
                    a = struct.unpack("<Q", struct.pack("<d", rng.uniform(-1e6, 1e6)))[0]
                    b = struct.unpack("<Q", struct.pack("<d", rng.uniform(-1e6, 1e6)))[0]
                elif index < 8:
                    a = (0, 1, MASK, 1 << 63, (1 << 63) - 1, 0xFF, 0xFFFF, 0xFFFFFFFF)[index]
                    b = (0, MASK, 1, 1 << 63, 1, 64, 65, 127)[index]
                native_data = C.create_string_buffer(data, max(len(data), 1))
                expected = original(C.cast(native_data, C.c_void_p) if pointer else a, b)
                regs, memory_bytes, memory = lifted.execute(root_address, a, b, data, pointer)
                assert memory.fault == 0, (name, level, index, memory.fault, hex(memory.fault_pc))
                assert regs[0] == expected, (name, level, index, hex(regs[0]), hex(expected))
                if pointer:
                    assert memory_bytes[:len(data)] == native_data.raw[:len(data)], (name, level, index)
                if name == "lift_add":
                    observed = (C.c_uint64 * 2)()
                    native.native_add_flags(a, b, observed)
                    assert regs[0] == observed[0]
                    for reg, bit in ((17, 4), (18, 0), (20, 11), (21, 2), (22, 7), (23, 6)):
                        assert regs[reg] == ((observed[1] >> bit) & 1), (name, reg, a, b, regs[reg], observed[1])
                compared += 1
        total += compared
        summaries.append({"symbol": name, "cases": compared, "optimization_levels": [0, 2],
                          "input_sha256": report["source_sha256"], "semantics_sha256": report["lifting"]["semantics_sha256"],
                          "module_sha256": hashlib.sha256((output / "module.bc").read_bytes()).hexdigest()})

    # Runtime failures stop, retain the first fault, and never access host OOB.
    output = directory / "fault-store"
    report = cli(elf, "lift_store", output)
    shared = output / "fault.so"
    run([CLANG, "-O2", "-shared", "-fPIC", "-Wno-override-module", output / "module.bc", "-o", shared])
    lifted = Lifted(shared)
    regs, memory_bytes, memory = lifted.execute(int(report["lifting"]["entry"], 16), data=b"AB", pointer=True, size=1)
    assert memory.fault == 2 and memory.fault_address == BASE + 1 and memory.fault_width == 1
    assert memory_bytes[:2] == b"AB"
    _, _, memory = lifted.execute(int(report["lifting"]["entry"], 16), a=BASE - 1, size=SIZE)
    assert memory.fault == 1 and memory.fault_address == BASE - 1
    _, _, memory = lifted.execute(int(report["lifting"]["entry"], 16), a=MASK, size=SIZE)
    assert memory.fault == 1 and memory.fault_address == MASK

    output = directory / "fault-wide"
    report = cli(elf, "lift_unaligned", output)
    shared = output / "wide.so"
    run([CLANG, "-O2", "-shared", "-fPIC", "-Wno-override-module", output / "module.bc", "-o", shared])
    lifted = Lifted(shared)
    entry = int(report["lifting"]["entry"], 16)
    _, _, memory = lifted.execute(entry, data=bytes(16), pointer=True, size=8)
    assert memory.fault == 1 and memory.fault_address == BASE + 1 and memory.fault_width == 8
    _, _, memory = lifted.execute(entry, data=bytes(16), pointer=True, base=MASK - 3)
    assert memory.fault == 1 and memory.fault_width == 8

    output = directory / "budget"
    report = cli(elf, "lift_infinite", output)
    shared = output / "infinite.so"
    run([CLANG, "-O2", "-shared", "-fPIC", "-Wno-override-module", output / "module.bc", "-o", shared])
    _, _, memory = Lifted(shared).execute(int(report["lifting"]["entry"], 16), budget=11)
    assert memory.fault == 3 and memory.steps_left == 0

    for name in ("lift_indirect", "lift_syscall", "lift_rep", "lift_external", "lift_truncated", "lift_overlap", "lift_cpuid"):
        output = directory / ("negative-" + name)
        report = cli(elf, name, output, expected=1)
        assert report["diagnostics"][-1]["code"] in {
            "E_UNRESOLVED_EDGE", "E_UNSUPPORTED_INSTRUCTION", "E_DECODE", "E_FUNCTION_AMBIGUOUS", "E_EXTERNAL_UNMODELED"}
    cli(elf, "missing_function", directory / "missing", expected=1)
    cli(elf, "lift_sum", directory / "too-many", expected=1, extra=("--max-instructions", "2"))

    # Reusing an owned output removes stale IR before a new attempt. A failed
    # lift must never leave the prior module looking like its own output.
    output = directory / "reused-output"
    first = cli(elf, "lift_add", output)
    first_hash = hashlib.sha256((output / "module.bc").read_bytes()).hexdigest()
    second = cli(elf, "lift_add", output)
    assert hashlib.sha256((output / "module.bc").read_bytes()).hexdigest() == first_hash
    assert first["lifting"] == second["lifting"]
    failed = cli(elf, "lift_indirect", output, expected=1)
    assert failed["artifacts"] == [] and failed["diagnostics"][-1]["pc"] is not None
    unowned = directory / "unowned"
    unowned.mkdir()
    (unowned / "module.ll").write_text("user data\n")
    result = subprocess.run([EXE, "lift", str(elf), "--symbol", "lift_add", "--out", str(unowned), "--json"],
                            capture_output=True, text=True, timeout=30)
    assert result.returncode == 2 and json.loads(result.stdout)["diagnostics"][-1]["code"] == "E_OUTPUT"
    assert (unowned / "module.ll").read_text() == "user data\n"

    # Stripped code still supports a user-provided address+size contract.
    if strip := shutil.which("strip"):
        original_report = cli(elf, "lift_add", directory / "address-source")
        selected = original_report["functions"][0]
        stripped = directory / "stripped.so"
        shutil.copyfile(elf, stripped)
        run([strip, "--strip-all", stripped])
        # Remove section metadata too, so no dynsym boundary can be used.
        raw = bytearray(stripped.read_bytes())
        phoff=struct.unpack_from("<Q",raw,32)[0]
        phnum=struct.unpack_from("<H",raw,56)[0]
        for index in range(phnum):
            at=phoff+56*index
            if struct.unpack_from("<I",raw,at)[0]==2:
                struct.pack_into("<I",raw,at,0)
        struct.pack_into("<Q", raw, 40, 0)
        struct.pack_into("<HHH", raw, 58, 0, 0, 0)
        stripped.write_bytes(raw)
        output = directory / "address-only"
        result = run([EXE, "lift", stripped, "--address", selected["address"], "--size", selected["size"], "--out", output, "--json"])
        report = json.loads(result.stdout)
        assert report["status"] == "LIFTED"
        assert report["functions"][0]["discovery_evidence"] == ["user_range"]

    # C compiler-generated stack frames and loops, built at four optimization levels.
    c_source = directory / "native.c"
    c_source.write_text("unsigned long compiled_sum(const unsigned char*p,unsigned long n){unsigned long s=0; for(unsigned long i=0;i<n;i++)s+=p[i];return s;}\n")
    for level in (0, 1, 2, 3):
        elf_c = directory / f"native-c-o{level}.so"
        run([CC, "-O" + str(level), "-fno-tree-vectorize", "-shared", "-fPIC", c_source, "-o", elf_c])
        native_c = C.CDLL(str(elf_c)).compiled_sum
        native_c.argtypes = [C.c_void_p, C.c_uint64]
        native_c.restype = C.c_uint64
        output = directory / f"compiled-o{level}"
        report = cli(elf_c, "compiled_sum", output)
        shared = output / "recompiled.so"
        run([CLANG, "-O2", "-shared", "-fPIC", "-Wno-override-module", output / "module.bc", "-o", shared])
        lifted = Lifted(shared)
        rng = random.Random(SEED)
        for index in range(1000):
            data = rng.randbytes(index % 80)
            original_data = C.create_string_buffer(data, max(len(data), 1))
            expected = native_c(original_data, len(data))
            regs, _, memory = lifted.execute(int(report["lifting"]["entry"], 16), b=len(data), data=data, pointer=True)
            assert memory.fault == 0 and regs[0] == expected == sum(data)
        total += 1000
        summaries.append({"symbol": "compiled_sum", "source_optimization": level, "cases": 1000,
                          "input_sha256": report["source_sha256"], "semantics_sha256": report["lifting"]["semantics_sha256"],
                          "module_sha256": hashlib.sha256((output / "module.bc").read_bytes()).hexdigest()})

    # Exercise finite indirect-target recovery under ASan/UBSan as well. The
    # larger compiler/native matrix runs separately in the release worker suite.
    switch = directory / "bounded-switch.so"
    run([CC, "-O2", "-shared", "-fPIC", ROOT / "tests/fixtures/switch.c", "-o", switch])
    switch_report = cli(switch, "program_switch", directory / "bounded-switch")
    assert switch_report["lifting"]["indirect_resolution"]
    assert len(switch_report["lifting"]["indirect_resolution"][0]["targets"]) == 8

    summary = {"schema_version": "0.1", "seed": SEED, "compared_cases": total,
               "static_bounded_switch_tables": 1,
               "fixture_source_sha256": hashlib.sha256(assembly.read_bytes()).hexdigest(),
               "mismatches": 0, "functions": summaries,
               "scope": "Trusted fixtures; explicit ABI return, selected defined flags and input memory. Not a proof for arbitrary ELF."}
    result_file = Path(RESULT)
    result_file.parent.mkdir(parents=True, exist_ok=True)
    result_file.write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps({"compared_cases": total, "mismatches": 0, "function_variants": len(summaries)}))


if __name__ == "__main__":
    doctor = json.loads(run([EXE, "doctor", "--json"]).stdout)
    assert doctor["capabilities"]["remill"] and doctor["capabilities"]["llvm_lifting"]
    with tempfile.TemporaryDirectory(prefix="zvril-lifting-test-") as temp:
        exercise(Path(temp))
