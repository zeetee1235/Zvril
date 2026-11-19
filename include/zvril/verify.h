#pragma once
#include "zvril/elf/image.h"
#include <llvm/Support/JSON.h>
namespace zvril {
struct Verification {
  llvm::json::Object report;
  int exit_code;
};
Verification verify(const Image &, const std::filesystem::path &original,
                    const std::filesystem::path &output,
                    const std::filesystem::path &cases,
                    const std::string &symbol, std::uint64_t timeout_ms = 5000,
                    bool native_trace = false);
bool sandbox_available();
bool ptrace_available();
unsigned native_rep_fault_profile();
void restrict_worker(const std::filesystem::path &original,
                     std::uint64_t timeout_ms);
} // namespace zvril
