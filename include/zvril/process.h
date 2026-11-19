#pragma once
#include "zvril/elf/image.h"
#include <llvm/Support/JSON.h>
namespace zvril {
struct ProcessOptions {
  std::filesystem::path output;
  std::filesystem::path sysroot;
  std::string architecture = "amd64";
  std::vector<std::string> arguments, environment;
  std::vector<std::uint8_t> standard_input;
  std::uint64_t max_steps = 1000000, max_modules = 4096;
  std::uint64_t resident_modules = 128;
  std::uint64_t memory_bytes = 64 * 1024 * 1024, timeout_ms = 30000;
};
struct ProcessResult {
  llvm::json::Object report;
  int exit_code = 0;
};
ProcessResult execute_process(const Image &, const ProcessOptions &);
} // namespace zvril
