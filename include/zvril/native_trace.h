#pragma once
#include <cstdint>
#include <llvm/Support/JSON.h>
#include <memory>
#include <set>
#include <sys/types.h>
#include <vector>
#include "zvril/elf/image.h"
namespace zvril {
// Only the native child may enable TRACEME. The tracer never executes guest
// code in its own address space, and never bypasses a failed kernel check.
class NativeTrace {
  struct Impl;
  std::unique_ptr<Impl> impl;

public:
  explicit NativeTrace(const Image&,const std::set<std::uint64_t> &pcs,
                       std::size_t stack_bytes,std::size_t limit = 4096);
  ~NativeTrace();
  void enable_child();
  void metadata_child(std::uint64_t image_base,
                      const std::vector<std::uint64_t> &buffers);
  bool stopped(pid_t, int status);
  llvm::json::Object result() const;
};
llvm::json::Object compare_instruction_traces(const llvm::json::Object &native,
                                              const llvm::json::Object &lifted);
} // namespace zvril
