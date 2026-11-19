"""Small, explicit compatibility layer for Remill's pinned LLVM-22 build.

Only build copies are changed. Architecture selection is restricted to XED x86;
the machine instruction semantics and decoder sources are never modified.
"""
from pathlib import Path
import sys

source, output = map(Path, sys.argv[1:])
for name in ("lib/Arch/Arch.cpp", "lib/BC/Util.cpp"):
    text = (source / name).read_text()
    if name.endswith("Arch.cpp"):
        begin = text.index("auto Arch::GetArchByName(")
        end = text.index("\nauto Arch::Build(", begin)
        text = text[:begin] + '''auto Arch::GetArchByName(llvm::LLVMContext *context_, OSName os_name_,
                         ArchName arch_name_) -> ArchPtr {
  switch (arch_name_) {
    case kArchX86: case kArchX86_AVX: case kArchX86_AVX512:
    case kArchAMD64: case kArchAMD64_AVX: case kArchAMD64_AVX512:
      return GetX86(context_, os_name_, arch_name_);
    default: return nullptr;
  }
}
''' + text[end:]
    else:
        # LLVM removed the MMX primitive type; modern x86 semantics use vectors.
        text = text.replace("    case llvm::Type::X86_MMXTyID: return llvm::Type::getX86_MMXTy(context);", "")
        text = text.replace("    case llvm::Type::X86_MMXTyID:", "")
    target = output / name
    target.parent.mkdir(parents=True, exist_ok=True)
    if not target.exists() or target.read_text() != text:
        target.write_text(text)
