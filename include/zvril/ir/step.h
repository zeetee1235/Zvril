#pragma once
#include "zvril/elf/image.h"
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>
#include <llvm/Support/JSON.h>
#include <memory>
#include <span>

namespace zvril {
/* A dynamic process instruction is a separate verified LLVM module. Its caller
 * must check the current executable bytes before entering the compiled step.
 * This API does not establish a statically closed whole-program CFG. */
struct StepModule {
  std::unique_ptr<llvm::Module> module;
  llvm::json::Object evidence;
};
class StepCompiler {
  struct Impl;
  std::unique_ptr<Impl> impl;

public:
  explicit StepCompiler(const std::string &architecture);
  ~StepCompiler();
  StepModule image(const Image &);
  StepModule instruction(std::uint64_t pc, std::span<const std::uint8_t> bytes);
  llvm::LLVMContext &context();
};
} // namespace zvril
