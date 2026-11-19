#include "zvril/ir/image.h"
#include <algorithm>
#include <elf.h>
#include <map>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/Module.h>

namespace zvril {
void emit_image(llvm::Module &module, const Image &image,
                std::set<std::string> &exports) {
  if (!image.unsupported_loader_features.empty())
    throw Error("E_RELOCATION",
                "Unmodeled loader feature: " +
                    image.unsupported_loader_features.front(),
                1);
  if (!image.dynamic_complete &&
      std::any_of(image.metadata.begin(), image.metadata.end(),
                  [](const auto &m) { return m.type == PT_DYNAMIC; }))
    throw Error("E_RELOCATION",
                "Dynamic loader metadata could not be recovered completely", 1);
  using namespace llvm;
  auto &c = module.getContext();
  auto *i64 = Type::getInt64Ty(c);
  auto *i32 = Type::getInt32Ty(c);
  auto *ptr = PointerType::get(c, 0);
  auto *f = llvm::Function::Create(FunctionType::get(i32, {ptr, i64}, false),
                                   GlobalValue::ExternalLinkage,
                                   "zvril_init_image", module);
  exports.insert("zvril_init_image");
  IRBuilder<> b(BasicBlock::Create(c, "entry", f));
  auto *failed = BasicBlock::Create(c, "failed", f);
  auto *runtime = f->getArg(0);
  auto *bias = f->getArg(1);
  const auto u64 = [&](std::uint64_t v) { return ConstantInt::get(i64, v); };
  const auto require = [&](Value *condition) {
    auto *next = BasicBlock::Create(c, "next", f);
    b.CreateCondBr(condition, next, failed);
    b.SetInsertPoint(next);
  };
  if (image.type == ET_EXEC)
    require(b.CreateICmpEQ(bias, u64(0)));
  b.CreateCall(module.getFunction("zvril_runtime_set_bias"), {runtime, bias});
  for (const auto &segment : image.segments)
    if (segment.memory_size) {
      require(b.CreateICmpULE(
          bias, u64(UINT64_MAX - segment.address - (segment.memory_size - 1))));
      auto bytes = ArrayRef<std::uint8_t>(image.bytes)
                       .slice(segment.offset, segment.file_size);
      auto *constant = ConstantDataArray::get(c, bytes);
      auto *data = new GlobalVariable(module, constant->getType(), true,
                                      GlobalValue::PrivateLinkage, constant,
                                      "elf.segment");
      unsigned permissions = ((segment.flags & PF_R) ? 1 : 0) |
                             ((segment.flags & PF_W) ? 2 : 0) |
                             ((segment.flags & PF_X) ? 4 : 0);
      auto *result = b.CreateCall(
          module.getFunction("zvril_runtime_map"),
          {runtime, b.CreateAdd(bias, u64(segment.address)),
           u64(segment.memory_size), ConstantInt::get(i32, permissions | 2),
           data, u64(segment.file_size), ConstantInt::get(i32, 1)});
      require(b.CreateICmpNE(result, ConstantInt::get(i32, 0)));
    }
  auto *slot = b.CreateAlloca(i64);
  std::uint64_t tls_extent = 0;
  bool has_tls = false;
  for (const auto &t : image.metadata)
    if (t.type == PT_TLS) {
      if (has_tls || t.alignment > 4096)
        throw Error("E_RELOCATION", "Unsupported TLS layout", 1);
      has_tls = true;
      const auto alignment = std::max<std::uint64_t>(t.alignment, 1);
      tls_extent = (t.memory_size + alignment - 1) & ~(alignment - 1);
      auto bytes =
          ArrayRef<std::uint8_t>(image.bytes).slice(t.offset, t.file_size);
      auto *constant = ConstantDataArray::get(c, bytes);
      auto *data =
          new GlobalVariable(module, constant->getType(), true,
                             GlobalValue::PrivateLinkage, constant, "elf.tls");
      auto *result = b.CreateCall(module.getFunction("zvril_runtime_tls"),
                                  {runtime, u64(t.memory_size), u64(alignment),
                                   data, u64(t.file_size)});
      require(b.CreateICmpNE(result, ConstantInt::get(i32, 0)));
    }
  std::vector<const Relocation *> ordered;
  std::map<std::uint64_t, unsigned> relocation_spans;
  for (const auto &r : image.relocations) if (r.active_dynamic && r.type) {
    const unsigned width = r.type == R_X86_64_TLSDESC ? 16 :
        (r.type == R_X86_64_PC32 || r.type == R_X86_64_PLT32 ||
         r.type == R_X86_64_32 || r.type == R_X86_64_32S) ? 4 : 8;
    if (r.offset > UINT64_MAX - width)
      throw Error("E_RELOCATION", "Relocation target wraps the address space", 1);
    auto next = relocation_spans.lower_bound(r.offset);
    if ((next != relocation_spans.end() && next->first - r.offset < width) ||
        (next != relocation_spans.begin() && r.offset - std::prev(next)->first < std::prev(next)->second))
      throw Error("E_RELOCATION", "Overlapping active relocation writes", 1);
    relocation_spans.emplace(r.offset, width);
  }
  for (const auto &r : image.relocations)
    if (r.source == "DT_RELR")
      ordered.push_back(&r);
  for (const auto &r : image.relocations)
    if (r.source != "DT_RELR")
      ordered.push_back(&r);
  for (const auto *relocation : ordered) {
    const auto &r = *relocation;
    if (!r.active_dynamic)
      continue;
    for (const auto &s : image.segments)
      if ((s.flags & PF_X) && r.offset >= s.address &&
          r.offset - s.address < s.memory_size)
        throw Error("E_RELOCATION",
                    "Text relocations require instruction re-decoding and are "
                    "unsupported",
                    1);
    if (!r.type)
      continue;
    if (r.symbol_type == STT_GNU_IFUNC)
      throw Error(
          "E_RELOCATION",
          "IFUNC resolver execution is not permitted in static image loading",
          1);
    const auto width = (r.type == R_X86_64_PC32 || r.type == R_X86_64_PLT32 ||
                        r.type == R_X86_64_32 || r.type == R_X86_64_32S) ? 4u : 8u;
    Value *addend = u64(r.addend);
    if (!r.explicit_addend && r.type != R_X86_64_GLOB_DAT &&
        r.type != R_X86_64_JUMP_SLOT && r.type != R_X86_64_DTPMOD64) {
      if (r.type == R_X86_64_TLSDESC)
        throw Error("E_RELOCATION", "TLSDESC requires an explicit addend", 1);
      b.CreateStore(u64(0), slot);
      auto *read = b.CreateCall(module.getFunction("zvril_runtime_read"),
          {runtime, b.CreateAdd(bias, u64(r.offset)), slot, u64(width)});
      require(b.CreateICmpNE(read, ConstantInt::get(i32, 0)));
      addend = b.CreateLoad(i64, slot);
      if (width == 4 && r.type != R_X86_64_32)
        addend = b.CreateSExt(b.CreateTrunc(addend, i32), i64);
    }
    Value *symbol = u64(r.symbol_value);
    if (r.symbol_section == SHN_UNDEF) {
      if (r.symbol_binding == STB_WEAK)
        symbol = u64(0);
      else {
        // Stable, guest-only import identities. Calls are resolved separately.
        std::uint64_t hash = UINT64_C(1469598103934665603);
        for (unsigned char v : r.symbol) {
          hash ^= v;
          hash *= UINT64_C(1099511628211);
        }
        symbol = u64(UINT64_C(0xffff800000000000) |
                     (hash & UINT64_C(0x00007fffffffffff)));
      }
    } else if (r.symbol_section != SHN_ABS)
      symbol = b.CreateAdd(bias, symbol);
    Value *value = nullptr;
    switch (r.type) {
    case R_X86_64_TLSDESC:
      if (!has_tls || (r.symbol_index && r.symbol_section == SHN_UNDEF) ||
          r.symbol_value + std::uint64_t(r.addend) >= tls_extent)
        throw Error("E_RELOCATION",
                    "TLSDESC symbol is outside the local TLS image", 1);
      value = u64(UINT64_C(0xffff80000000fd00));
      break;
    case R_X86_64_DTPMOD64:
      if (!has_tls || (!r.symbol.empty() && r.symbol_section == SHN_UNDEF))
        throw Error("E_RELOCATION", "External TLS modules are unsupported", 1);
      value = u64(1);
      break;
    case R_X86_64_DTPOFF64:
    case R_X86_64_TPOFF64:
      if (!has_tls || (r.symbol_index && r.symbol_section == SHN_UNDEF))
        throw Error("E_RELOCATION", "Unresolved TLS symbol", 1);
      value = b.CreateAdd(u64(r.symbol_value -
                  (r.type == R_X86_64_TPOFF64 ? tls_extent : 0)), addend);
      break;
    case R_X86_64_RELATIVE:
      value = b.CreateAdd(bias, addend);
      break;
    case R_X86_64_64:
      value = b.CreateAdd(symbol, addend);
      break;
    case R_X86_64_GLOB_DAT:
    case R_X86_64_JUMP_SLOT:
      value = symbol;
      break;
    case R_X86_64_PC32:
    case R_X86_64_PLT32:
      value = b.CreateSub(b.CreateAdd(symbol, addend),
                          b.CreateAdd(bias, u64(r.offset)));
      require(
          b.CreateICmpEQ(value, b.CreateSExt(b.CreateTrunc(value, i32), i64)));
      break;
    case R_X86_64_32:
    case R_X86_64_32S:
      value = b.CreateAdd(symbol, addend);
      require(b.CreateICmpEQ(value, r.type == R_X86_64_32
          ? b.CreateZExt(b.CreateTrunc(value, i32), i64)
          : b.CreateSExt(b.CreateTrunc(value, i32), i64)));
      break;
    default:
      throw Error("E_RELOCATION",
                  "Unmodeled dynamic relocation type " + std::to_string(r.type),
                  1);
    }
    b.CreateStore(value, slot);
    auto *written = b.CreateCall(
        module.getFunction("zvril_runtime_write"),
        {runtime, b.CreateAdd(bias, u64(r.offset)), slot, u64(width)});
    require(b.CreateICmpNE(written, ConstantInt::get(i32, 0)));
    if (r.type == R_X86_64_TLSDESC) {
      b.CreateStore(u64(r.symbol_value + r.addend - tls_extent), slot);
      auto *tail = b.CreateCall(
          module.getFunction("zvril_runtime_write"),
          {runtime, b.CreateAdd(bias, u64(r.offset + 8)), slot, u64(8)});
      require(b.CreateICmpNE(tail, ConstantInt::get(i32, 0)));
    }
  }
  for (const auto &s : image.segments)
    if (s.memory_size) {
      unsigned p = ((s.flags & PF_R) ? 1 : 0) | ((s.flags & PF_W) ? 2 : 0) |
                   ((s.flags & PF_X) ? 4 : 0);
      auto *changed =
          b.CreateCall(module.getFunction("zvril_runtime_protect"),
                       {runtime, b.CreateAdd(bias, u64(s.address)),
                        u64(s.memory_size), ConstantInt::get(i32, p)});
      require(b.CreateICmpNE(changed, ConstantInt::get(i32, 0)));
    }
  for (const auto &r : image.metadata)
    if (r.type == PT_GNU_RELRO && r.memory_size) {
      auto *changed =
          b.CreateCall(module.getFunction("zvril_runtime_protect"),
                       {runtime, b.CreateAdd(bias, u64(r.address)),
                        u64(r.memory_size), ConstantInt::get(i32, 1)});
      require(b.CreateICmpNE(changed, ConstantInt::get(i32, 0)));
    }
  b.CreateRet(ConstantInt::get(i32, 1));
  b.SetInsertPoint(failed);
  b.CreateRet(ConstantInt::get(i32, 0));
}
} // namespace zvril
