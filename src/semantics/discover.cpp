#include "zvril/lift.h"
#include <algorithm>
#include <elf.h>
#include <map>
#include <set>
#include <sstream>
#ifdef ZVRIL_HAS_REMILL
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>
#include <llvm/IRReader/IRReader.h>
#include <llvm/Support/SourceMgr.h>
#include <remill/Arch/Arch.h>
#include <remill/Arch/Instruction.h>
#endif
namespace zvril {
llvm::json::Object discover_calls(Image &image, std::uint64_t limit,
                                  std::uint64_t function_limit) {
#ifndef ZVRIL_HAS_REMILL
  (void)image; (void)limit; (void)function_limit;
  throw Error("E_BACKEND_UNAVAILABLE", "Call discovery requires the Remill decoder", 1);
#else
  llvm::LLVMContext context;
  auto arch = remill::Arch::Get(context, "linux", "amd64");
  llvm::SMDiagnostic error;
  auto semantics = llvm::parseIRFile(default_semantics_path().string(), error, context);
  if (!semantics)
    throw Error("E_BACKEND_UNAVAILABLE", "Cannot initialize call-discovery decoder: " + error.getMessage().str(), 1);
  arch->PrepareModule(semantics.get());
  arch->InitFromSemanticsModule(semantics.get());
  std::map<std::uint64_t, std::uint64_t> pending, decoded;
  std::set<std::uint64_t> known;
  std::uint64_t invalid = 0, added = 0;
  const auto extent = [&](std::uint64_t pc) -> std::uint64_t {
    for (const auto &s : image.segments)
      if ((s.flags & PF_X) && pc >= s.address && pc - s.address < s.file_size)
        return s.address + s.file_size;
    return 0;
  };
  for (const auto &f : image.functions) {
    known.insert(f.address);
    if (const auto end = extent(f.address))
      pending.emplace(f.address, f.size && f.size < end - f.address
                                     ? f.address + f.size : end);
  }
  if (known.size() > function_limit)
    throw Error("E_RESOURCE_LIMIT", "Initial call-discovery candidates exceed function budget", 1);
  const auto queue = [&](std::uint64_t pc, std::uint64_t end) {
    if (pc < end && extent(pc) && !decoded.contains(pc))
      pending.emplace(pc, std::min(end, extent(pc)));
  };
  llvm::json::Array evidence;
  const auto address_string = [](std::uint64_t value) {
    std::ostringstream out; out << "0x" << std::hex << value; return out.str();
  };
  while (!pending.empty()) {
    auto [pc, end] = *pending.begin(); pending.erase(pending.begin());
    if (decoded.contains(pc)) continue;
    if (decoded.size() >= limit)
      throw Error("E_RESOURCE_LIMIT", "Call-discovery instruction budget exceeded", 1);
    auto next = decoded.lower_bound(pc);
    if (next != decoded.begin()) {
      auto previous = std::prev(next);
      if (pc - previous->first < previous->second) { invalid++; continue; }
    }
    std::string_view bytes;
    for (const auto &s : image.segments)
      if ((s.flags & PF_X) && pc >= s.address && pc - s.address < s.file_size) {
        bytes = {reinterpret_cast<const char *>(image.bytes.data() + s.offset + pc - s.address),
                 std::size_t(std::min<std::uint64_t>(15, end - pc))};
        break;
      }
    remill::Instruction inst;
    bool valid = false;
    for (std::size_t n = 1; n <= bytes.size(); n++)
      if (arch->DecodeInstruction(pc, bytes.substr(0, n), inst, arch->CreateInitialContext())) {
        valid = true; break;
      }
    if (!valid || !inst.IsValid() || inst.bytes.empty() ||
        (next != decoded.end() && inst.bytes.size() > next->first - pc)) {
      invalid++; continue;
    }
    decoded.emplace(pc, inst.bytes.size());
    using I = remill::Instruction;
    if (inst.category == I::kCategoryDirectFunctionCall) {
      const auto target = inst.branch_taken_pc, target_end = extent(target);
      if (target_end && known.insert(target).second) {
        ++added;
        if (known.size() > function_limit)
          throw Error("E_RESOURCE_LIMIT", "Call-discovery candidate budget exceeded", 1);
        std::ostringstream name, source;
        name << "call_" << std::hex << target;
        source << "direct_call:" << std::hex << pc;
        image.functions.push_back({name.str(), source.str(), target, 0, 0, 0});
        evidence.push_back(llvm::json::Object{{"call_pc", address_string(pc)}, {"target", address_string(target)},
                                              {"boundary_known", false}});
        queue(target, target_end);
      }
      queue(inst.next_pc, end);
    } else if (inst.category == I::kCategoryConditionalBranch) {
      queue(inst.branch_taken_pc, end); queue(inst.branch_not_taken_pc, end);
    } else if (inst.category == I::kCategoryDirectJump)
      queue(inst.branch_taken_pc, end);
    else if (inst.category == I::kCategoryNormal || inst.category == I::kCategoryNoOp)
      queue(inst.next_pc, end);
    else if (inst.category == I::kCategoryIndirectFunctionCall)
      queue(inst.next_pc, end);
  }
  std::sort(image.functions.begin(), image.functions.end(), [](const auto &a, const auto &b) {
    return std::tie(a.address, a.name, a.source) < std::tie(b.address, b.name, b.source);
  });
  return llvm::json::Object{{"decoded_instructions", decoded.size()},
                            {"new_call_candidates", added}, {"decode_stops", invalid},
                            {"evidence", std::move(evidence)},
                            {"scope", "Reachable direct-call candidates; boundaries are not inferred and indirect targets remain unknown"}};
#endif
}
} // namespace zvril
