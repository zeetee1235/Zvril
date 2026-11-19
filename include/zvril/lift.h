#pragma once
#include "zvril/elf/image.h"
#include <llvm/Support/JSON.h>
#include <optional>
#include <string_view>

namespace zvril {
struct LiftOptions {
  std::string symbol;
  std::optional<std::uint64_t> address;
  std::optional<std::uint64_t> size;
  std::uint64_t max_instructions = 100000;
  std::uint64_t max_functions = 4096, max_blocks = 100000;
  std::filesystem::path semantics;
  std::filesystem::path output;
  std::filesystem::path abi_contract;
  std::string architecture = "amd64";
  bool allow_partial = false;
};
bool remill_available();
llvm::json::Object discover_calls(Image &, std::uint64_t max_instructions = 100000,
                                  std::uint64_t max_functions = 4096);
std::filesystem::path
default_semantics_path(std::string_view architecture = "amd64");
llvm::json::Object lift(const Image &, const LiftOptions &);
} // namespace zvril
