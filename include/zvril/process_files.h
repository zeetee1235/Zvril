#pragma once
#include "zvril/runtime.h"
#include <array>
#include <filesystem>
#include <llvm/Support/JSON.h>
#include <memory>
#include <optional>
#include <vector>
namespace zvril {
std::filesystem::path process_host_path(const std::filesystem::path &root,
                                        const std::string &guest);
class ProcessFiles {
  struct Impl;
  std::unique_ptr<Impl> impl;

public:
  ProcessFiles(ZvrilRuntime *, const std::filesystem::path &root,
               const std::vector<std::uint8_t> &input,
               const std::string &executable);
  ~ProcessFiles();
  std::optional<std::uint64_t> call(std::uint64_t,
                                    const std::array<std::uint64_t, 6> &);
  bool mapping(std::uint64_t fd, std::uint64_t offset, std::uint64_t size,
               std::vector<std::uint8_t> &initial);
  const std::vector<std::uint8_t> &output(bool error) const;
  llvm::json::Object report() const;
};
} // namespace zvril
