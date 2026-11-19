#pragma once
#include "zvril/elf/image.h"
#include <llvm/Support/JSON.h>
#include <map>
#include <memory>
#include <remill/Arch/Arch.h>
#include <remill/Arch/Instruction.h>
#include <set>
namespace zvril {
struct IndirectTargets {
  std::set<std::uint64_t> targets;
  std::vector<std::pair<std::uint64_t, std::uint64_t>> predecessors;
  llvm::json::Object evidence;
};
std::optional<IndirectTargets> resolve_bounded_indirect(
    const Image &, const remill::Arch &,
    const std::map<std::uint64_t, std::unique_ptr<remill::Instruction>> &,
    const remill::Instruction &, std::uint64_t owner_start);
} // namespace zvril
