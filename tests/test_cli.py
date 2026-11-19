"""Black-box ELF/CLI regression. Compiles fixtures but never executes them.

Uses the standard library only. Checks report contract invariants against the
published schema's required fields; this is not a full JSON Schema validator.
"""
import copy
import hashlib
import json
from pathlib import Path
import random
import re
import shutil
import struct
import subprocess
import sys
import tempfile


EXE = Path(sys.argv[1]).resolve()
CC = sys.argv[2]
ROOT = Path(sys.argv[3])
SCHEMA = json.loads((ROOT / "schemas/report.schema.json").read_text())
COUNTS = {"cli_invocations": 0, "malformed_cases": 0, "real_fixtures": 0}


def invoke(*args, expected=0):
    result = subprocess.run([str(EXE), *map(str, args), "--json"],
                            capture_output=True, text=True, timeout=8)
    COUNTS["cli_invocations"] += 1
    assert result.returncode == expected, (args, result.returncode, result.stdout, result.stderr)
    assert not result.stderr, (args, result.stderr)
    value = json.loads(result.stdout)
    if "functions" in value:
        check_contract(value)
    return value


def check_contract(report):
    assert set(SCHEMA["required"]) <= report.keys()
    assert report["schema_version"] == "0.1"
    assert report["backend"] in {"none", "remill"}
    assert report["status"] in {"INSPECTED", "BLOCKED", "LIFTED"}
    assert isinstance(report["timings"], dict)
    assert isinstance(report["resources"], dict)
    for function in report["functions"]:
        assert set(SCHEMA["$defs"]["function"]["required"]) <= function.keys()
        assert function["status"] in {"INSPECTED", "BLOCKED", "LIFTED"}
        if function["status"] == "LIFTED":
            assert function["instruction_count"] > 0 and function["llvm_verified"] is True
        else:
            assert function["instruction_count"] is None and function["llvm_verified"] is False
        assert function["tested_cases"] == 0
        for field in ("address", "size"):
            assert re.fullmatch(r"0x[0-9a-f]{1,16}", function[field])
    for diagnostic in report["diagnostics"]:
        assert set(SCHEMA["$defs"]["diagnostic"]["required"]) <= diagnostic.keys()
        assert diagnostic["severity"] in {"warning", "error", "info"}
        assert diagnostic["code"].startswith(("E_", "W_"))


def stable(report):
    result = copy.deepcopy(report)
    result.pop("timings")
    return result


def synth():
    """ELF with PT_LOAD, executable .text, STRTAB, and two function symbols."""
    data = bytearray(640)
    ident = b"\x7fELF\x02\x01\x01" + bytes(9)
    struct.pack_into("<16sHHIQQQIHHHHHH", data, 0, ident, 2, 62, 1,
                     0x400100, 64, 384, 0, 64, 56, 1, 64, 4, 0)
    struct.pack_into("<IIQQQQQQ", data, 64, 1, 5, 0, 0x400000, 0,
                     len(data), len(data) + 32, 4096)
    data[256] = 0xC3
    data[272:281] = b"\x00target\x00\x00"
    # NULL + defined function + zero-size alias at the same address.
    struct.pack_into("<IBBHQQ", data, 312, 1, 0x12, 0, 1, 0x400100, 1)
    struct.pack_into("<IBBHQQ", data, 336, 1, 0x22, 0, 1, 0x400100, 0)
    struct.pack_into("<IIQQQQIIQQ", data, 448, 0, 1, 6, 0x400100, 256, 1, 0, 0, 1, 0)
    struct.pack_into("<IIQQQQIIQQ", data, 512, 0, 3, 0, 0, 272, 9, 0, 0, 1, 0)
    struct.pack_into("<IIQQQQIIQQ", data, 576, 0, 2, 0, 0, 288, 72, 2, 1, 8, 24)
    return data


def exercise(directory):
    doctor = invoke("doctor")
    assert doctor["capabilities"]["elf_inspection"] is True
    has_remill = doctor["capabilities"]["remill"]
    assert doctor["capabilities"]["native_execution"] == (has_remill and not doctor['capabilities']['sanitized_build'])
    demo = invoke("demo")
    assert len(demo["cases"]) in {3,6}
    assert all(not case["input_executed"] for case in demo["cases"][:3])
    for case in demo["cases"][3:]:assert case['status']=='TESTED' and case['validation']['passed']>0

    source = ROOT / "tests/fixtures/analysis.c"
    fixtures = []
    compilers = []
    for compiler in (CC, shutil.which("gcc"), shutil.which("clang")):
        if compiler and Path(compiler).resolve() not in {Path(c).resolve() for c in compilers}:
            compilers.append(compiler)
    for ci, compiler in enumerate(compilers):
        for opt in (0, 1, 2, 3):
            path = directory / f"fixture-{ci}-o{opt}.so"
            subprocess.run([compiler, f"-O{opt}", "-shared", "-fPIC", str(source), "-o", str(path)],
                           check=True, capture_output=True)
            fixtures.append(path)
    for label, flag in (("exec", "-no-pie"), ("pie", "-pie")):
        path = directory / label
        subprocess.run([CC, "-O2", flag, str(source), "-o", str(path)], check=True, capture_output=True)
        fixtures.append(path)

    for path in fixtures:
        before = path.read_bytes()
        result = invoke("inspect", path)
        COUNTS["real_fixtures"] += 1
        assert result["status"] == "INSPECTED"
        assert result["source_sha256"] == hashlib.sha256(before).hexdigest()
        assert any(f["name"] == "target" for f in result["functions"])
        assert any(f["name"] == "target_alias" for f in result["functions"])
        assert any(f["name"] == "local_helper" for f in result["functions"])
        assert any(i["name"] == "puts" for i in result["imports"])
        assert result["relocations"] and all(not r["applied"] for r in result["relocations"])
        assert any(int(s["zero_fill_size"], 16) > 0 for s in result["segments"])
        assert stable(result) == stable(invoke("functions", path))
        # Independent symbol metadata oracle when readelf is installed.
        if readelf := shutil.which("readelf"):
            symbols = subprocess.run([readelf, "-Ws", str(path)], check=True,
                                     capture_output=True, text=True).stdout
            for f in result["functions"]:
                if not any(s.startswith(("symtab:", "dynsym:")) for s in f["discovery_evidence"]):
                    continue
                assert any(int(match[1], 16) == int(f["address"], 16) and
                           int(match[2]) == int(f["size"], 16) and match[3] == f["name"]
                           for match in re.finditer(
                               r"\d+:\s+([0-9a-f]+)\s+(\d+)\s+FUNC\s+\S+\s+\S+\s+\S+\s+(\S+)", symbols)), f
        assert path.read_bytes() == before

    # Static glibc emits .rela.plt with sh_link == 0 and IRELATIVE entries.
    # The parser must accept the reserved null symbol table instead of treating
    # every relocation section as symbol-linked.
    static = directory / "static-exec"
    subprocess.run([CC, "-O1", "-static", "-no-pie", str(source), "-o", str(static)],
                   check=True, capture_output=True, timeout=60)
    result = invoke("inspect", static)
    assert result["status"] == "INSPECTED" and not result["diagnostics"]
    assert any(f["name"] == "target" for f in result["functions"])
    assert any(r["type"] == 37 for r in result["relocations"])  # R_X86_64_IRELATIVE
    COUNTS["real_fixtures"] += 1

    if strip := shutil.which("strip"):
        stripped = directory / "stripped.so"
        shutil.copyfile(fixtures[0], stripped)
        subprocess.run([strip, "--strip-all", str(stripped)], check=True)
        result = invoke("functions", stripped)
        assert any(f["name"] == "target" for f in result["functions"])
        assert not any(f["name"] == "local_helper" for f in result["functions"])
        COUNTS["real_fixtures"] += 1

    fixture = directory / "synthetic.elf"
    original = synth()
    fixture.write_bytes(original)
    result = invoke("inspect", fixture)
    assert len(result["functions"]) == 2
    assert {f["boundary_known"] for f in result["functions"]} == {True, False}
    if has_remill:
        discovered = invoke("inspect", fixture, "--discover-calls")
        assert discovered["code_discovery"]["decoded_instructions"] == 1
        assert discovered["code_discovery"]["new_call_candidates"] == 0
    else:
        unavailable = invoke("inspect", fixture, "--discover-calls", expected=1)
        assert unavailable["diagnostics"][-1]["code"] == "E_BACKEND_UNAVAILABLE"

    # A relocation section must link a valid symbol table and symbol index.
    with_relocation = bytearray(original) + bytearray(64)
    struct.pack_into("<H", with_relocation, 60, 5)
    struct.pack_into("<QQq", with_relocation, 360, 0x400100, (1 << 32) | 1, -4)
    struct.pack_into("<IIQQQQIIQQ", with_relocation, 640,
                     0, 4, 0, 0, 360, 24, 3, 1, 8, 24)
    fixture.write_bytes(with_relocation)
    result = invoke("inspect", fixture)
    assert len(result["relocations"]) == 1
    assert result["relocations"][0]["symbol"] == "target"
    assert result["relocations"][0]["addend"] == "-4"
    for offset, form, value in ((368, "Q", (99 << 32) | 1),
                                (680, "I", 1), (696, "Q", 23)):
        malformed = bytearray(with_relocation)
        struct.pack_into("<" + form, malformed, offset, value)
        fixture.write_bytes(malformed)
        invoke("inspect", fixture, expected=3)
        COUNTS["malformed_cases"] += 1

    overlap = bytearray(original)
    struct.pack_into("<H", overlap, 56, 2)
    struct.pack_into("<IIQQQQQQ", overlap, 120, 1, 4, 128, 0x400080, 0, 64, 64, 1)
    fixture.write_bytes(overlap)
    invoke("inspect", fixture, expected=3)
    COUNTS["malformed_cases"] += 1

    unterminated = bytearray(original)
    unterminated[272:281] = b"A" * 9
    fixture.write_bytes(unterminated)
    invoke("inspect", fixture, expected=3)
    COUNTS["malformed_cases"] += 1

    # ELF extended section/program counts via section zero.
    extended = bytearray(original)
    struct.pack_into("<H", extended, 56, 0xFFFF)
    struct.pack_into("<H", extended, 60, 0)
    struct.pack_into("<Q", extended, 384 + 32, 4)
    struct.pack_into("<I", extended, 384 + 44, 1)
    struct.pack_into("<H", extended, 62, 0xFFFF)
    struct.pack_into("<I", extended, 384 + 40, 2)
    fixture.write_bytes(extended)
    assert len(invoke("inspect", fixture)["functions"]) == 2

    # Remove all section information: code can still exist, discovery incomplete.
    sectionless = bytearray(original)
    struct.pack_into("<Q", sectionless, 40, 0)
    struct.pack_into("<H", sectionless, 60, 0)
    fixture.write_bytes(sectionless)
    result = invoke("inspect", fixture)
    assert all(f["discovery_evidence"] == ["elf_entry"] for f in result["functions"])
    assert {d["code"] for d in result["diagnostics"]} == {"W_SECTIONLESS", "W_NO_FUNCTION_SYMBOLS"}

    # Non-UTF8 symbol strings must remain valid JSON and preserve original bytes.
    nonutf = bytearray(original)
    nonutf[273] = 0xFF
    fixture.write_bytes(nonutf)
    result = invoke("inspect", fixture)
    assert result["functions"][0]["name_raw_hex"] == "ff6172676574"

    # Every truncation of the sized synthetic file must be rejected safely.
    for length in range(len(original)):
        fixture.write_bytes(original[:length])
        invoke("inspect", fixture, expected=3)
        COUNTS["malformed_cases"] += 1

    mutations = [
        (4, "B", 1), (5, "B", 2), (6, "B", 0),
        (16, "H", 1), (18, "H", 3), (20, "I", 0), (52, "H", 63),
        (32, "Q", (1 << 64) - 1), (40, "Q", (1 << 64) - 1),
        (54, "H", 55), (58, "H", 63), (62, "H", 99),
        (64 + 32, "Q", len(original) + 33),  # filesz > memsz
        (64 + 16, "Q", (1 << 64) - 10),
        (64 + 48, "Q", 3),
        (576 + 24, "Q", (1 << 64) - 1),
        (576 + 32, "Q", (1 << 64) - 1),
        (576 + 40, "I", 99),
        (576 + 56, "Q", 23),
        (312, "I", 99), (312 + 6, "H", 99),
        (312 + 8, "Q", 0x500000), (312 + 16, "Q", 65535),
    ]
    for offset, form, value in mutations:
        malformed = bytearray(original)
        struct.pack_into("<" + form, malformed, offset, value)
        fixture.write_bytes(malformed)
        invoke("inspect", fixture, expected=3)
        COUNTS["malformed_cases"] += 1

    extended_symbol = bytearray(original)
    struct.pack_into("<H", extended_symbol, 312 + 6, 0xFFFF)
    fixture.write_bytes(extended_symbol)
    result = invoke("inspect", fixture, expected=3)
    assert result["diagnostics"][-1]["code"] == "E_ELF_INVALID"
    extended_symbol.extend(bytes(76))
    struct.pack_into('<H',extended_symbol,60,5)
    struct.pack_into('<IIQQQQIIQQ',extended_symbol,640,0,18,0,0,704,12,3,0,4,4)
    struct.pack_into('<III',extended_symbol,704,0,1,0)
    fixture.write_bytes(extended_symbol)
    result=invoke('inspect',fixture)
    assert any(f['name']=='target' and f['section_index']==1 for f in result['functions'])

    rng = random.Random(3619)
    for _ in range(64):
        garbage = rng.randbytes(rng.randrange(0, 1024))
        fixture.write_bytes(garbage)
        invoke("inspect", fixture, expected=3)
        COUNTS["malformed_cases"] += 1

    fixture.write_bytes(original)
    report_dir = directory / "output"
    result = invoke("inspect", fixture, "--out", report_dir)
    assert json.loads((report_dir / "report.json").read_text()) == result
    result = invoke("inspect", fixture, "--max-bytes", 32, expected=1)
    assert result["diagnostics"][-1]["code"] == "E_RESOURCE_LIMIT"
    invoke("inspect", directory, expected=3)
    invoke("inspect", directory / "absent", expected=3)

    for iteration, (command, tail) in enumerate((("lift", ("--symbol", "target")),
                          ("lift", ("--address", "0x400100")),
                          ("batch", ("--jobs", "2")))):
        command_output = directory / f"command-{iteration}"
        lifted = has_remill
        result = invoke(command, fixture, *tail, "--out", command_output, expected=0 if lifted else 1)
        assert result["status"] == ("LIFTED" if lifted else "BLOCKED")
        if not lifted:
            assert result["diagnostics"][-1]["code"] == ("E_BATCH_INCOMPLETE" if command=="batch" else "E_BACKEND_UNAVAILABLE")
        artifacts=command_output/"function-0" if command=="batch" else command_output
        assert (artifacts / "module.ll").exists() == lifted
        assert (artifacts / "module.bc").exists() == lifted
        assert fixture.read_bytes() == original

    invalid_options = [(), ("unknown",), ("inspect",), ("inspect", fixture, "--unknown"),
                       ("inspect", fixture, "--max-bytes", "-1"),
                       ("inspect", fixture, "--max-bytes", "18446744073709551616"),
                       ("inspect", fixture, "--out"), ("doctor", "--symbol", "x"),
                       ("demo", fixture), ("lift", fixture, "--out", report_dir),
                       ("lift", fixture, "--symbol", "target", "--address", "1", "--out", report_dir),
                       ("lift", fixture, "--symbol", "target", "--out", report_dir, "--strict", "--allow-partial"),
                       ("batch", fixture, "--out", report_dir, "--jobs", "0"),
                       ("verify", fixture, "--symbol", "target", "--cases", directory)]
    for args in invalid_options:
        result = invoke(*args, expected=3)
        assert result["diagnostics"][-1]["code"] == "E_CLI"

    # A valid ELF named report.json must not be replaced by its output.
    named_report = directory / "report.json"
    named_report.write_bytes(original)
    result = invoke("inspect", named_report, "--out", directory, expected=2)
    assert result["diagnostics"][-1]["code"] == "E_OUTPUT"
    assert named_report.read_bytes() == original

    symlink_dir = directory / "symlink-output"
    symlink_dir.mkdir()
    (symlink_dir / "report.json").symlink_to(fixture)
    invoke("inspect", fixture, "--out", symlink_dir, expected=2)
    assert fixture.read_bytes() == original

    for args in (("--help",), ("--version",), ("inspect", "--help")):
        result = subprocess.run([str(EXE), *args], capture_output=True, text=True, timeout=8)
        assert result.returncode == 0 and result.stdout and not result.stderr

    print(json.dumps(COUNTS, sort_keys=True))


if __name__ == "__main__":
    with tempfile.TemporaryDirectory(prefix="zvril-regression-") as temp:
        exercise(Path(temp))
