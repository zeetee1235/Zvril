#pragma once
#include "zvril/elf/image.h"
#include <functional>
#include <llvm/Support/JSON.h>
namespace zvril {
struct BatchResult {
  llvm::json::Array functions;
  std::uint64_t lifted = 0, blocked = 0;
};
BatchResult
batch(const Image &, const std::filesystem::path &, unsigned jobs,
      std::uint64_t timeout, const std::vector<std::string> &selection,
      std::function<int(const Function &, const std::filesystem::path &,
                        llvm::json::Object &)>);
} // namespace zvril
