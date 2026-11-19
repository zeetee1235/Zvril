#pragma once
#include "zvril/runtime.h"
#include <array>
#include <cstdint>
#include <llvm/Support/JSON.h>
#include <optional>
#include <vector>
namespace zvril {
struct SignalFrame {
  std::vector<std::uint8_t> state;
  std::array<std::uint8_t, 512> floating{};
  std::uint64_t address = 0, valid_flags = 0, old_alt_sp = 0, old_alt_size = 0,
                old_alt_flags = 2;
};
struct SignalTask {
  std::uint64_t mask = 0, pending = 0, alt_sp = 0, alt_size = 0, alt_flags = 2;
  std::array<int, 65> pending_code{};
  std::optional<std::uint64_t> suspended_mask;
  bool suspend_wait = false;
  std::vector<SignalFrame> frames;
};
class ProcessSignals {
public:
  using Get = std::uint64_t (*)(void *, std::uint32_t);
  using Set = void (*)(void *, std::uint32_t, std::uint64_t);
  ProcessSignals(ZvrilRuntime *, Get, Set, const llvm::json::Array &layout);
  std::optional<std::uint64_t> call(std::uint64_t,
                                    const std::array<std::uint64_t, 6> &,
                                    SignalTask &, std::vector<std::uint8_t> &,
                                    std::uint64_t &valid);
  bool deliver(SignalTask &, std::vector<std::uint8_t> &, std::uint64_t &valid,
               unsigned signal, int code = 0, std::uint64_t address = 0,
               unsigned trap = 0, unsigned error = 0);
  bool pending(SignalTask &, std::vector<std::uint8_t> &, std::uint64_t &valid);
  bool restartable(unsigned signal) const;
  llvm::json::Object report() const;

private:
  struct Action {
    std::uint64_t handler = 0, flags = 0, restorer = 0, mask = 0;
  };
  std::array<Action, 65> actions{};
  ZvrilRuntime *memory;
  Get get;
  Set set;
  std::array<std::uint64_t, 16> xmm{};
  std::uint64_t mxcsr = 0;
  std::uint64_t delivered = 0, returned = 0;
  bool read(std::uint64_t, void *, std::uint64_t);
  bool write(std::uint64_t, const void *, std::uint64_t);
};
} // namespace zvril
