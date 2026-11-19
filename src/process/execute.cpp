#include "remill_license.h"
#include "zvril/ir/process_runtime.h"
#include "zvril/ir/step.h"
#include "zvril/process.h"
#include "zvril/process_files.h"
#include "zvril/process_signals.h"
#include "zvril/runtime.h"
#include <algorithm>
#include <array>
#include <chrono>
#include <cmath>
#include <cstring>
#include <elf.h>
#include <fstream>
#include <llvm/Bitcode/BitcodeWriter.h>
#include <llvm/ExecutionEngine/ExecutionEngine.h>
#include <llvm/ExecutionEngine/MCJIT.h>
#include <llvm/ExecutionEngine/SectionMemoryManager.h>
#include <llvm/IR/Verifier.h>
#include <llvm/IRReader/IRReader.h>
#include <llvm/Support/DynamicLibrary.h>
#include <llvm/Support/FormatVariadic.h>
#include <llvm/Support/SHA256.h>
#include <llvm/Support/SourceMgr.h>
#include <llvm/Support/TargetSelect.h>
#include <llvm/Support/raw_ostream.h>
#include <map>
#include <memory>
#include <set>
#include <sstream>

namespace zvril {
namespace {
using llvm::json::Array;
using llvm::json::Object;
// Host ABI wrappers for the libm calls that Remill's semantics emit from
// __builtin_* (for example SQRTSD -> sqrt when errno preservation prevents the
// LLVM intrinsic). These are only registered for process execution; static
// lifting still rejects unmodeled external calls.
#define ZVRIL_HOST_MATH_LIST(X)                                                \
  X(fabs, double) X(fabsf, float) X(fabsl, long double)                        \
  X(sqrt, double) X(sqrtf, float) X(sqrtl, long double)                        \
  X(cos, double) X(cosf, float) X(cosl, long double)                           \
  X(sin, double) X(sinf, float) X(sinl, long double)                           \
  X(tan, double) X(tanf, float) X(tanl, long double)                           \
  X(atan, double) X(atanf, float) X(atanl, long double)                        \
  X(exp2, double) X(exp2f, float) X(exp2l, long double)                        \
  X(log2, double) X(log2f, float) X(log2l, long double)                        \
  X(nearbyint, double) X(nearbyintf, float) X(nearbyintl, long double)         \
  X(trunc, double) X(truncf, float) X(truncl, long double)                     \
  X(round, double) X(roundf, float) X(roundl, long double)                     \
  X(ceil, double) X(ceilf, float) X(ceill, long double)                        \
  X(floor, double) X(floorf, float) X(floorl, long double)
#define ZVRIL_DEFINE_HOST_MATH(name, type)                                     \
  extern "C" type zvril_host_##name(type value) { return ::name(value); }
ZVRIL_HOST_MATH_LIST(ZVRIL_DEFINE_HOST_MATH)
#undef ZVRIL_DEFINE_HOST_MATH
std::string hex(std::uint64_t n) { return llvm::formatv("0x{0:x-}", n).str(); }
std::string bytes_hex(const std::vector<std::uint8_t> &bytes) {
  std::string result;
  for (auto b : bytes) {
    result += "0123456789abcdef"[b >> 4];
    result += "0123456789abcdef"[b & 15];
  }
  return result;
}
struct Jit {
  std::unique_ptr<llvm::ExecutionEngine> engine;
  explicit Jit(std::unique_ptr<llvm::Module> module) {
    std::string error;
    engine.reset(llvm::EngineBuilder(std::move(module))
                     .setEngineKind(llvm::EngineKind::JIT)
                     .setErrorStr(&error)
                     .setMCJITMemoryManager(
                         std::make_unique<llvm::SectionMemoryManager>())
                     .create());
    if (!engine)
      throw Error("E_LLVM_JIT", error, 2);
    engine->finalizeObject();
  }
  template <class T> T get(const char *name) {
    auto address = engine->getFunctionAddress(name);
    if (!address)
      throw Error("E_LLVM_JIT", std::string("Missing process symbol: ") + name,
                  2);
    return reinterpret_cast<T>(address);
  }
};
void save_module(llvm::Module &module, const std::filesystem::path &base) {
  std::error_code error;
  llvm::raw_fd_ostream bc((base.string() + ".bc"), error);
  if (error)
    throw Error("E_OUTPUT", error.message(), 2);
  llvm::WriteBitcodeToFile(module, bc);
  bc.flush();
  if (bc.has_error())
    throw Error("E_OUTPUT", "Cannot finish process bitcode", 2);
  llvm::raw_fd_ostream ir((base.string() + ".ll"), error);
  if (error)
    throw Error("E_OUTPUT", error.message(), 2);
  module.print(ir, nullptr);
  ir.flush();
  if (ir.has_error())
    throw Error("E_OUTPUT", "Cannot finish process IR", 2);
}
struct Thread {
  SignalTask signals;
  std::uint64_t blocked_pc = 0, blocked_number = 0;
  std::uint64_t robust_head = 0;
  std::vector<std::uint8_t> state;
  std::uint64_t tid = 0, clear_tid = 0, wait_address = 0, valid_flags = 0xcd5;
  bool exited = false, waiting = false;
  bool wait_private = false;
};
struct CachedStep {
  // MCJIT must be destroyed before its context. A separate context also lets
  // eviction reclaim named LLVM types created by bitcode reloads.
  std::unique_ptr<llvm::LLVMContext> context;
  std::unique_ptr<Jit> jit;
  using Entry = ZvrilRuntime *(*)(void *, std::uint64_t, ZvrilRuntime *);
  Entry entry = nullptr;
  std::uint64_t last_use = 0;
};
std::string module_digest(const std::filesystem::path &path) {
  std::ifstream file(path, std::ios::binary | std::ios::ate);
  auto size = file.tellg();
  if (!file || size < 0 || size > 4 * 1024 * 1024)
    throw Error("E_PROCESS_CACHE", "Invalid cached module extent", 2);
  std::vector<std::uint8_t> data(static_cast<std::size_t>(size));
  file.seekg(0);
  file.read(reinterpret_cast<char *>(data.data()), data.size());
  if (!file)
    throw Error("E_PROCESS_CACHE", "Cannot read cached module", 2);
  auto digest = llvm::SHA256::hash(data);
  return bytes_hex({digest.begin(), digest.end()});
}
struct StepArtifact {
  std::string name, digest;
};
class Process {
  const Image &image;
  const ProcessOptions &options;
  StepCompiler compiler;
  std::unique_ptr<Jit> bootstrap;
  std::unique_ptr<ProcessFiles> files;
  std::unique_ptr<ProcessSignals> signals;
  std::vector<std::unique_ptr<Jit>> loaded_images;
  std::uint64_t interpreter_bias = 0;
  std::optional<Image> interpreter;
  std::unique_ptr<ZvrilRuntime, decltype(&zvril_runtime_destroy)> memory{
      nullptr, &zvril_runtime_destroy};
  using Get = std::uint64_t (*)(void *, std::uint32_t);
  using Set = void (*)(void *, std::uint32_t, std::uint64_t);
  Get get = nullptr;
  Set set = nullptr;
  std::vector<Thread> threads;
  std::map<std::pair<std::uint64_t, std::vector<std::uint8_t>>, CachedStep>
      cache;
  std::map<std::pair<std::uint64_t, std::vector<std::uint8_t>>, StepArtifact>
      artifacts;
  std::uint64_t cache_clock = 0, cache_evictions = 0, cache_reloads = 0,
                cache_peak = 0;
  std::map<std::uint64_t, std::set<std::vector<std::uint8_t>>> versions;
  std::uint64_t mmap_next = 0x400000000000, break_base = 0, break_end = 0,
                break_mapped = 0;
  Array modules, syscalls;
  std::uint64_t instructions = 0, modified_code = 0, syscall_count = 0;
  int process_exit = 0;
  bool group_exited = false;
  std::uint64_t random_position = 0;
  std::chrono::steady_clock::time_point deadline;

  std::uint64_t reg(Thread &thread, unsigned id) {
    return get(thread.state.data(), id);
  }
  void reg(Thread &thread, unsigned id, std::uint64_t value) {
    set(thread.state.data(), id, value);
  }
  static std::uint64_t neg(unsigned error) { return std::uint64_t(0) - error; }
  bool copy_in(std::uint64_t address, void *data, std::uint64_t size) {
    if (zvril_runtime_read(memory.get(), address, data, size))
      return true;
    zvril_runtime_clear_fault(memory.get());
    return false;
  }
  bool copy_out(std::uint64_t address, const void *data, std::uint64_t size) {
    if (zvril_runtime_write(memory.get(), address, data, size))
      return true;
    zvril_runtime_clear_fault(memory.get());
    return false;
  }
  std::uint64_t flags(Thread &thread) {
    static const unsigned bits[] = {4, 0, 10, 11, 2, 7, 6};
    std::uint64_t result = 0x202;
    for (unsigned i = 0; i < 7; i++)
      result |= (reg(thread, 17 + i) & 1) << bits[i];
    return result;
  }
  void wake(std::uint64_t address, bool private_key, std::uint64_t count,
            std::uint64_t &woken) {
    for (auto &thread : threads)
      if (count && thread.waiting && thread.wait_address == address &&
          thread.wait_private == private_key) {
        thread.waiting = false;
        thread.blocked_pc = 0;
        --count;
        ++woken;
      }
  }
  void finish_thread(Thread &thread) {
    if (thread.robust_head) {
      std::uint64_t head[3]{};
      if (copy_in(thread.robust_head, head, 24)) {
        const auto owner_die = [&](std::uint64_t tagged) {
          if (!tagged)
            return;
          if (tagged & 1)
            throw Error("E_PROCESS_FUTEX",
                        "PI robust-futex exit is not implemented", 1);
          auto address = tagged + head[1];
          std::uint32_t value = 0;
          if (copy_in(address, &value, 4) &&
              (value & 0x3fffffff) == thread.tid) {
            value = (value & 0x80000000) | 0x40000000;
            if (copy_out(address, &value, 4)) {
              std::uint64_t ignored = 0;
              wake(address, false, 1, ignored);
              wake(address, true, 1, ignored);
            }
          }
        };
        auto node = head[0];
        for (unsigned count = 0;
             count < 2048 && (node & ~UINT64_C(1)) != thread.robust_head &&
             node;
             count++) {
          std::uint64_t next = 0;
          if (!copy_in(node & ~UINT64_C(1), &next, 8))
            break;
          owner_die(node);
          node = next;
        }
        owner_die(head[2]);
      }
    }
    thread.exited = true;
    if (thread.clear_tid) {
      std::uint32_t zero = 0;
      // Linux ignores a failed clear_child_tid store but still exits the task.
      copy_out(thread.clear_tid, &zero, 4);
      std::uint64_t ignored = 0;
      wake(thread.clear_tid, false, UINT64_MAX, ignored);
    }
  }
  std::uint64_t syscall(Thread &thread, std::uint64_t number,
                        const std::array<std::uint64_t, 6> &a) {
    if (auto result = files->call(number, a))
      return *result;
    if (auto result = signals->call(number, a, thread.signals, thread.state,
                                    thread.valid_flags))
      return *result;
    switch (number) {
    case 273:
      if (a[1] != 24)
        return neg(22);
      thread.robust_head = a[0];
      return 0;
    case 274: {
      for (auto &target : threads)
        if (!target.exited && (!a[0] || target.tid == a[0])) {
          if (!a[0] && target.tid != thread.tid)
            continue;
          std::uint64_t size = 24;
          return copy_out(a[1], &target.robust_head, 8) &&
                         copy_out(a[2], &size, 8)
                     ? 0
                     : neg(14);
        }
      return neg(3);
    }
    case 435: {
      if (a[1] < 64)
        return neg(22);
      if (a[1] > 4096)
        return neg(7);
      std::vector<std::uint8_t> bytes(a[1]);
      if (!copy_in(a[0], bytes.data(), bytes.size()))
        return neg(14);
      std::array<std::uint64_t, 11> args{};
      std::memcpy(args.data(), bytes.data(),
                  std::min<std::size_t>(88, bytes.size()));
      if (bytes.size() > 88 && std::any_of(bytes.begin() + 88, bytes.end(),
                                           [](auto b) { return b != 0; }))
        return neg(7);
      if (args[4] || args[8] || args[9] || args[10])
        throw Error(
            "E_PROCESS_CLONE",
            "clone3 exit signal/set_tid/cgroup extensions are not modeled", 1);
      if (!args[5] || !args[6] || args[5] >= 0x800000000000 ||
          args[6] > 0x800000000000 - args[5])
        return neg(22);
      return syscall(
          thread, 56,
          {args[0], args[5] + args[6], args[3], args[2], args[7], 0});
    }
    case 62:
    case 200:
    case 234: {
      std::uint64_t tid = number == 234 ? a[1] : number == 200 ? a[0] : 0;
      auto signal = std::uint32_t(number == 234 ? a[2] : a[1]);
      if (signal > 64)
        return neg(22);
      if (number == 234 && a[0] != 1000)
        return neg(3);
      if (number == 62 && std::int64_t(a[0]) != 1000 &&
          std::int64_t(a[0]) != 0 && std::int64_t(a[0]) != -1000)
        return neg(3);
      for (auto &target : threads)
        if (!target.exited && (!tid || target.tid == tid)) {
          if (!signal)
            return 0;
          if (signal >= 32)
            throw Error("E_PROCESS_SIGNAL",
                        "Realtime queued-signal delivery is not implemented",
                        1);
          target.signals.pending |= UINT64_C(1) << (signal - 1);
          target.signals.pending_code[signal] = number == 62 ? 0 : -6;
          if (!(target.signals.mask & (UINT64_C(1) << (signal - 1))) &&
              target.waiting) {
            if (!target.signals.suspend_wait && target.blocked_pc) {
              if (signals->restartable(signal)) {
                reg(target, 16, target.blocked_pc);
                reg(target, 0, target.blocked_number);
              } else
                reg(target, 0, neg(4));
            }
            target.waiting = false;
            target.blocked_pc = 0;
          }
          return 0;
        }
      return neg(3);
    }
    case 63: {
      std::array<char, 65 * 6> data{};
      const char *fields[] = {"Linux", "zvril",  "6.1.0",
                              "#1",    "x86_64", "(none)"};
      for (unsigned i = 0; i < 6; i++)
        std::strcpy(data.data() + 65 * i, fields[i]);
      return copy_out(a[0], data.data(), data.size()) ? 0 : neg(14);
    }
    case 102:
    case 104:
    case 107:
    case 108:
      return 1000;
    case 110:
      return 999;
    case 96:
    case 201:
    case 228: {
      if (number == 228 && a[0] != 0 && a[0] != 1 && a[0] != 4 && a[0] != 5 &&
          a[0] != 6)
        return neg(22);
      const auto ns = instructions * 1000;
      std::uint64_t stamp[2] = {ns / 1000000000, ns % 1000000000};
      if (number == 201)
        return !a[0] || copy_out(a[0], stamp, 8) ? stamp[0] : neg(14);
      if (number == 96) {
        stamp[1] /= 1000;
        std::uint64_t zone = 0;
        if (a[0] && !copy_out(a[0], stamp, 16))
          return neg(14);
        return !a[1] || copy_out(a[1], &zone, 8) ? 0 : neg(14);
      }
      return copy_out(a[1], stamp, 16) ? 0 : neg(14);
    }
    case 302: { // prlimit64; limits belong to this virtual process.
      if (a[0] && a[0] != 1000)
        return neg(3);
      if (a[1] >= 16)
        return neg(22);
      if (a[2])
        throw Error("E_PROCESS_RESOURCE",
                    "Changing virtual resource limits is not implemented", 1);
      std::uint64_t values[2] = {UINT64_MAX, UINT64_MAX};
      if (a[1] == 3)
        values[0] = values[1] = 1024 * 1024;
      if (a[1] == 7)
        values[0] = values[1] = 1024;
      if (a[1] == 9)
        values[0] = values[1] = options.memory_bytes;
      return !a[3] || copy_out(a[3], values, 16) ? 0 : neg(14);
    }
    case 318: {
      if (a[2] & ~std::uint64_t(3))
        return neg(22);
      const auto size = std::min<std::uint64_t>(a[1], 1024 * 1024);
      std::vector<std::uint8_t> bytes(size);
      for (auto &b : bytes) {
        auto v = ++random_position * UINT64_C(0x9e3779b97f4a7c15);
        b = (v ^ (v >> 31)) >> 24;
      }
      return copy_out(a[0], bytes.data(), size) ? size : neg(14);
    }
    case 334:
      // The declared virtual-kernel profile has rseq disabled. Record the
      // capability probe; this is not counted as implemented rseq semantics.
      return neg(38);
    case 9: { // anonymous mmap; no host pointers or file mappings.
      const auto length = a[1], protection = a[2], flags = a[3];
      if (!length || length > UINT64_MAX - 4095 || protection > 7 ||
          (a[5] & 4095))
        return neg(22);
      if ((flags & 3) != 2 ||
          (flags & ~std::uint64_t(0x22 | 0x10 | 0x100000 | 0x800 | 0x1000 |
                                  0x20000 | 0x4000)))
        throw Error("E_PROCESS_SYSCALL",
                    "mmap requires private mappings; unsupported flags=" +
                        hex(flags),
                    1);
      auto size = (length + 4095) & ~std::uint64_t(4095);
      std::vector<std::uint8_t> initial;
      if (!(flags & 0x20) && !files->mapping(a[4], a[5], size, initial))
        return neg(9);
      const auto map = [&](std::uint64_t address) {
        return zvril_runtime_map(memory.get(), address, size, protection,
                                 initial.empty() ? nullptr : initial.data(),
                                 initial.size(), 1);
      };
      auto address = a[0] & ~std::uint64_t(4095);
      if ((flags & (0x10 | 0x100000)) && (a[0] & 4095))
        return neg(22);
      if (!address)
        address = mmap_next;
      if (address < 4096 || address >= 0x800000000000 ||
          size > 0x800000000000 - address)
        return neg(12);
      if ((flags & 0x10) && !(flags & 0x100000)) {
        if (!zvril_runtime_unmap(memory.get(), address, size))
          return neg(12);
      }
      if (!map(address)) {
        if (flags & 0x100000)
          return neg(17);
        if (flags & 0x10)
          return neg(12);
        address = mmap_next;
        bool mapped = false;
        for (unsigned attempt = 0;
             attempt < 1024 && size <= 0x800000000000 - address;
             attempt++, address += size + 4096)
          if (map(address)) {
            mapped = true;
            break;
          }
        if (!mapped)
          return neg(12);
      }
      mmap_next = std::max(mmap_next, address + size + 4096);
      return address;
    }
    case 10:   // mprotect
    case 11: { // munmap
      if ((a[0] & 4095) || !a[1] || a[1] > UINT64_MAX - 4095)
        return neg(22);
      auto size = (a[1] + 4095) & ~std::uint64_t(4095);
      if (a[0] >= 0x800000000000 || size > 0x800000000000 - a[0])
        return neg(22);
      if (number == 10) {
        if (a[2] > 7)
          return neg(22);
        return zvril_runtime_protect(memory.get(), a[0], size, a[2]) ? 0
                                                                     : neg(12);
      }
      return zvril_runtime_unmap(memory.get(), a[0], size) ? 0 : neg(12);
    }
    case 12: { // brk; failure returns the unchanged break.
      if (!a[0])
        return break_end;
      if (a[0] < break_base || a[0] >= 0x800000000000)
        return break_end;
      auto end = (a[0] + 4095) & ~std::uint64_t(4095);
      if (end > break_mapped &&
          !zvril_runtime_map(memory.get(), break_mapped, end - break_mapped, 3,
                             nullptr, 0, 1))
        return break_end;
      if (end < break_mapped &&
          !zvril_runtime_unmap(memory.get(), end, break_mapped - end))
        return break_end;
      break_mapped = end;
      break_end = a[0];
      return break_end;
    }
    case 28: { // madvise; advisory except the discard advice, which zeroes
               // writable mapped pages so subsequent reads observe the kernel
               // contract instead of stale bytes.
      if (a[1] > UINT64_MAX - a[0] || a[0] >= 0x800000000000)
        return neg(22);
      const auto advice = a[2];
      const bool discard = advice == 4 || advice == 8;
      switch (advice) {
      case 0:  // MADV_NORMAL
      case 1:  // MADV_RANDOM
      case 2:  // MADV_SEQUENTIAL
      case 3:  // MADV_WILLNEED
      case 4:  // MADV_DONTNEED
      case 8:  // MADV_FREE
      case 12: // MADV_MERGEABLE
      case 13: // MADV_UNMERGEABLE
      case 14: // MADV_HUGEPAGE
      case 15: // MADV_NOHUGEPAGE
      case 16: // MADV_DONTDUMP
      case 17: // MADV_DODUMP
      case 18: // MADV_WIPEONFORK
      case 19: // MADV_KEEPONFORK
      case 20: // MADV_COLD
      case 21: // MADV_PAGEOUT
      case 22: // MADV_POPULATE_READ
      case 23: // MADV_POPULATE_WRITE
        break;
      default:
        return neg(22);
      }
      if (!a[1])
        return 0;
      if (!zvril_runtime_probe(memory.get(), a[0], a[1], 0))
        return neg(12);
      if (discard) {
        const std::array<std::uint8_t, 4096> zero{};
        auto begin = a[0] & ~std::uint64_t(4095);
        auto end = (a[0] + a[1] + 4095) & ~std::uint64_t(4095);
        for (auto page = begin; page < end; page += 4096)
          if (writable(page, std::min<std::uint64_t>(4096, end - page)))
            copy_out(page, zero.data(),
                     std::min<std::uint64_t>(4096, end - page));
      }
      return 0;
    }
    case 24:
      return 0; // sched_yield: dispatcher already schedules one instruction at
                // a time.
    case 39:
      return 1000; // virtual pid
    case 56: {     // clone sharing an address space; cooperative user task
                   // semantics.
      constexpr std::uint64_t mandatory = 0x100 | 0x400 | 0x800 | 0x10000;
      constexpr std::uint64_t supported = mandatory | 0x200 | 0x400 | 0x40000 |
                                          0x80000 | 0x100000 | 0x200000 |
                                          0x1000000;
      if ((a[0] & mandatory) != mandatory || (a[0] & ~supported) || !a[1])
        throw Error(
            "E_PROCESS_CLONE",
            "Only explicit shared-address-space thread clone flags are modeled",
            1);
      if (threads.size() >= 64)
        throw Error("E_PROCESS_RESOURCE", "Process exceeds 64 tasks", 1);
      Thread child = thread;
      child.tid = 1000 + threads.size();
      child.clear_tid = (a[0] & 0x200000) ? a[3] : 0;
      child.waiting = false;
      child.signals.pending = 0;
      child.signals.frames.clear();
      child.signals.suspend_wait = false;
      child.signals.suspended_mask.reset();
      child.signals.alt_sp = 0;
      child.signals.alt_size = 0;
      child.signals.alt_flags = 2;
      child.robust_head = 0;
      child.wait_address = 0;
      reg(child, 0, 0);
      reg(child, 4, a[1]);
      if (a[0] & 0x80000)
        reg(child, 24, a[4]);
      std::uint32_t id = child.tid;
      // Probe both stores before either one becomes observable.
      if ((a[0] & 0x100000) && !writable(a[2], 4))
        return neg(14);
      if ((a[0] & 0x1000000) && !writable(a[3], 4))
        return neg(14);
      if (a[0] & 0x100000)
        copy_out(a[2], &id, 4);
      if (a[0] & 0x1000000)
        copy_out(a[3], &id, 4);
      threads.push_back(std::move(child));
      return id;
    }
    case 60:
      // Linux exit(2) terminates the calling task. Only the initial task's
      // status is the process status; a worker's exit must not overwrite it.
      if (thread.tid == 1000)
        process_exit = a[0] & 255;
      finish_thread(thread);
      return 0;
    case 158: // arch_prctl
      if (a[0] == 0x1001 || a[0] == 0x1002) {
        if (a[1] >= 0x800000000000)
          return neg(1);
        reg(thread, a[0] == 0x1002 ? 24 : 25, a[1]);
        return 0;
      }
      if (a[0] == 0x1003 || a[0] == 0x1004) {
        auto base = reg(thread, a[0] == 0x1003 ? 24 : 25);
        return copy_out(a[1], &base, 8) ? 0 : neg(14);
      }
      return neg(22);
    case 157: // prctl; process-local capability and naming probes only.
      switch (a[0]) {
      case 1: // PR_SET_PDEATHSIG
      case 4: // PR_SET_DUMPABLE
      case 15: // PR_SET_NAME
      case 20: // PR_SET_SECUREBITS
      case 25: // PR_SET_TIMERSLACK
      case 29: // PR_SET_THP_DISABLE
      case 33: // PR_SET_CHILD_SUBREAPER
      case 38: // PR_SET_NO_NEW_PRIVS
        return 0;
      case 2: { // PR_GET_PDEATHSIG
        const std::uint32_t signal = 0;
        return !a[1] || copy_out(a[1], &signal, sizeof(signal)) ? 0 : neg(14);
      }
      case 3: // PR_GET_DUMPABLE
        return 1;
      case 16: { // PR_GET_NAME
        std::array<char, 16> name{};
        std::memcpy(name.data(), "zvril", 5);
        return !a[1] || copy_out(a[1], name.data(), name.size()) ? 0 : neg(14);
      }
      case 21: // PR_GET_SECUREBITS
      case 26: // PR_GET_TIMERSLACK
      case 30: // PR_GET_THP_DISABLE
      case 34: // PR_GET_CHILD_SUBREAPER
      case 39: // PR_GET_NO_NEW_PRIVS
        return 0;
      case 23: // PR_CAPBSET_READ
        return a[1] <= 40 ? 1 : neg(22);
      case 24: // PR_CAPBSET_DROP
        return a[1] <= 40 ? 0 : neg(22);
      default:
        return neg(22);
      }
    case 186:
      return thread.tid;
    case 203: { // sched_setaffinity; the virtual process has one CPU.
      if (a[0] && a[0] != 1000)
        return neg(3);
      if (!a[2] || !a[1])
        return neg(22);
      std::uint64_t mask = 0;
      if (!copy_in(a[2], &mask, std::min<std::uint64_t>(a[1], 8)))
        return neg(14);
      return (mask & 1) ? 0 : neg(22);
    }
    case 204: { // sched_getaffinity
      if (a[0] && a[0] != 1000)
        return neg(3);
      if (a[1] < 8)
        return neg(22);
      const std::uint64_t mask = 1;
      return copy_out(a[2], &mask, sizeof(mask)) ? 8 : neg(14);
    }
    case 202: { // futex WAIT/WAKE with no timeout, default full bitset.
      if ((a[0] & 3))
        return neg(22);
      // FUTEX_PRIVATE_FLAG (128) selects the key space; FUTEX_CLOCK_REALTIME
      // (256) only changes the timeout clock, which is currently absent.
      auto operation = a[1] & ~std::uint64_t(128 | 256);
      if (operation == 0 || operation == 9) {
        if (a[3] || a[4] || (operation == 9 && a[5] != 0xffffffff))
          throw Error("E_PROCESS_FUTEX",
                      "Timed/bitset futex waiting is not modeled", 1);
        std::uint32_t value = 0;
        if (!copy_in(a[0], &value, 4))
          return neg(14);
        if (value != std::uint32_t(a[2]))
          return neg(11);
        thread.waiting = true;
        thread.wait_address = a[0];
        thread.wait_private = (a[1] & 128) != 0;
        return 0;
      }
      if (operation == 1 || operation == 10) {
        if (operation == 10 && a[5] != 0xffffffff)
          throw Error("E_PROCESS_FUTEX",
                      "Partial futex bitsets are not modeled", 1);
        if (a[2] > INT32_MAX)
          return neg(22);
        std::uint64_t count = 0;
        wake(a[0], (a[1] & 128) != 0, a[2], count);
        return count;
      }
      throw Error("E_PROCESS_FUTEX", "Unmodeled futex operation " + hex(a[1]),
                  1);
    }
    case 218:
      thread.clear_tid = a[0];
      return thread.tid;
    case 221: // fadvise64; advisory and no host page-cache interaction.
      if (a[0] > INT32_MAX)
        return neg(9);
      if (a[3] > 5)
        return neg(22);
      return 0;
    case 231:
      process_exit = a[0] & 255;
      group_exited = true;
      for (auto &task : threads)
        finish_thread(task);
      return 0;
    default:
      throw Error("E_PROCESS_SYSCALL",
                  "Unmodeled x86-64 syscall " + std::to_string(number), 1);
    }
  }
  bool writable(std::uint64_t address, std::uint64_t size) {
    return zvril_runtime_probe(memory.get(), address, size, ZVRIL_W);
  }
  std::uint64_t initial_stack(std::uint64_t entry, std::uint64_t bias) {
    constexpr std::uint64_t base = 0x7fffff000000, size = 1024 * 1024;
    if (!zvril_runtime_map(memory.get(), base, size, 3, nullptr, 0, 1))
      throw Error("E_PROCESS_STACK", "Cannot map process stack", 1);
    auto top = base + size;
    const auto put = [&](const void *data, std::uint64_t n) {
      if (n > top - base)
        throw Error("E_PROCESS_STACK", "Argument/environment stack overflow",
                    1);
      top -= n;
      if (!zvril_runtime_write(memory.get(), top, data, n))
        throw Error("E_PROCESS_STACK", "Cannot initialize process stack", 1);
      return top;
    };
    std::vector<std::uint64_t> argv, envp;
    std::uint64_t input_bytes = 0;
    for (const auto *list : {&options.arguments, &options.environment})
      for (const auto &s : *list) {
        input_bytes += s.size() + 1;
        if (s.find('\0') != std::string::npos || input_bytes > 256 * 1024)
          throw Error("E_PROCESS_STACK",
                      "Invalid/oversized argument or environment strings", 1);
      }
    for (const auto &s : options.arguments)
      argv.push_back(put(s.c_str(), s.size() + 1));
    for (const auto &s : options.environment)
      envp.push_back(put(s.c_str(), s.size() + 1));
    const char platform[] = "x86_64";
    auto platform_address = put(platform, sizeof(platform));
    // Deterministic entropy is explicitly reported; this runner is a validation
    // environment and does not offer the kernel's randomness contract.
    const std::array<std::uint8_t, 16> random = {
        0x19, 0x26, 0x51, 0x73, 0x82, 0x95, 0xa1, 0xbc,
        0xd8, 0xe4, 0xf0, 0x16, 0x32, 0x54, 0x76, 0x98};
    auto random_address = put(random.data(), random.size());
    std::uint64_t phdr = 0;
    Elf64_Ehdr header{};
    std::memcpy(&header, image.bytes.data(), sizeof(header));
    for (const auto &segment : image.segments)
      if (header.e_phoff >= segment.offset &&
          header.e_phoff - segment.offset < segment.file_size &&
          image.program_header_count * header.e_phentsize <=
              segment.file_size - (header.e_phoff - segment.offset))
        phdr = segment.address + bias + header.e_phoff - segment.offset;
    // The auxiliary vector remains present even if no PT_LOAD contains PHDR.
    std::vector<std::uint64_t> words{argv.size()};
    words.insert(words.end(), argv.begin(), argv.end());
    words.push_back(0);
    words.insert(words.end(), envp.begin(), envp.end());
    words.push_back(0);
    const std::uint64_t aux[] = {AT_PHDR,     phdr,
                                 AT_PHENT,    header.e_phentsize,
                                 AT_PHNUM,    image.program_header_count,
                                 AT_PAGESZ,   4096,
                                 AT_BASE,     interpreter_bias,
                                 AT_FLAGS,    0,
                                 AT_ENTRY,    entry,
                                 AT_UID,      1000,
                                 AT_EUID,     1000,
                                 AT_GID,      1000,
                                 AT_EGID,     1000,
                                 AT_SECURE,   0,
                                 AT_PLATFORM, platform_address,
                                 AT_RANDOM,   random_address,
                                 AT_EXECFN,   argv.front(),
                                 AT_NULL,     0};
    words.insert(words.end(), std::begin(aux), std::end(aux));
    if (words.size() * 8 > top - base)
      throw Error("E_PROCESS_STACK", "Initial stack metadata overflow", 1);
    top = (top - words.size() * 8) & ~std::uint64_t(15);
    if (!zvril_runtime_write(memory.get(), top, words.data(), words.size() * 8))
      throw Error("E_PROCESS_STACK", "Cannot write initial stack", 1);
    return top;
  }

public:
  Process(const Image &source, const ProcessOptions &o)
      : image(source), options(o), compiler(o.architecture),
        deadline(std::chrono::steady_clock::now() +
                 std::chrono::milliseconds(o.timeout_ms)) {
    if (!options.resident_modules)
      throw Error("E_CLI", "Resident module limit must be positive", 3);
    if (options.arguments.empty())
      throw Error("E_PROCESS_ARGUMENTS", "argv[0] is required", 3);
    for (const auto &m : image.metadata)
      if (m.type == PT_INTERP) {
        if (options.sysroot.empty())
          throw Error("E_PROCESS_LOADER",
                      "PT_INTERP requires --sysroot for the original "
                      "interpreter and its DSOs",
                      1);
        auto bytes = std::span(image.bytes).subspan(m.offset, m.file_size);
        if (bytes.empty() || bytes.back() != 0 ||
            std::find(bytes.begin(), std::prev(bytes.end()), 0) !=
                std::prev(bytes.end()))
          throw Error("E_PROCESS_LOADER", "Invalid interpreter path", 1);
        std::string path(reinterpret_cast<const char *>(bytes.data()),
                         bytes.size() - 1);
        auto host = process_host_path(options.sysroot, path);
        if (host.empty())
          throw Error("E_PROCESS_LOADER",
                      "Interpreter is absent from sysroot: " + path, 1);
        interpreter = load(host);
        if (interpreter->type != ET_DYN)
          throw Error("E_PROCESS_LOADER", "Interpreter must be ET_DYN", 1);
        interpreter_bias = 0x30000000;
      }
    for (const auto &r : image.relocations)
      if (!interpreter && r.active_dynamic && r.symbol_index &&
          r.symbol_section == SHN_UNDEF && r.symbol_binding != STB_WEAK)
        throw Error("E_PROCESS_LOADER",
                    "Process has an unresolved DSO import: " + r.symbol, 1);
    std::ofstream license(options.output / "LICENSE.remill", std::ios::binary);
    license << kRemillLicense;
    license.close();
    if (!license)
      throw Error("E_OUTPUT", "Cannot write Remill license", 2);
    llvm::InitializeNativeTarget();
    llvm::InitializeNativeTargetAsmPrinter();
    llvm::InitializeNativeTargetAsmParser();
    llvm::sys::DynamicLibrary::LoadLibraryPermanently(nullptr);
#define ZVRIL_REGISTER_RUNTIME(name)                                           \
  llvm::sys::DynamicLibrary::AddSymbol(#name, reinterpret_cast<void *>(&name));
    ZVRIL_PROCESS_RUNTIME(ZVRIL_REGISTER_RUNTIME)
#undef ZVRIL_REGISTER_RUNTIME
#define ZVRIL_REGISTER_HOST_MATH(name, type)                                  \
  llvm::sys::DynamicLibrary::AddSymbol(                                       \
      #name, reinterpret_cast<void *>(&zvril_host_##name));
    ZVRIL_HOST_MATH_LIST(ZVRIL_REGISTER_HOST_MATH)
#undef ZVRIL_REGISTER_HOST_MATH
    auto initial = compiler.image(image);
    save_module(*initial.module, options.output / "image");
    bootstrap = std::make_unique<Jit>(std::move(initial.module));
    get = bootstrap->get<Get>("zvril_state_get");
    set = bootstrap->get<Set>("zvril_state_set");
    auto state_size = bootstrap->get<std::uint64_t (*)()>("zvril_state_size")();
    memory.reset(zvril_runtime_create(options.memory_bytes, options.max_steps));
    if (!memory)
      throw Error("E_PROCESS_RESOURCE", "Cannot allocate process runtime", 1);
    std::uint64_t bias = image.type == ET_DYN ? 0x20000000 : 0;
    if (!bootstrap->get<int (*)(ZvrilRuntime *, std::uint64_t)>(
            "zvril_init_image")(memory.get(), bias))
      throw Error("E_PROCESS_IMAGE", "ELF image initialization failed", 1);
    files = std::make_unique<ProcessFiles>(memory.get(), options.sysroot,
                                           options.standard_input,
                                           options.arguments.front());
    signals = std::make_unique<ProcessSignals>(
        memory.get(), get, set, *initial.evidence.getArray("registers"));
    if (interpreter) {
      auto loader = compiler.image(*interpreter);
      save_module(*loader.module, options.output / "interpreter");
      auto jit = std::make_unique<Jit>(std::move(loader.module));
      if (!jit->get<int (*)(ZvrilRuntime *, std::uint64_t)>("zvril_init_image")(
              memory.get(), interpreter_bias))
        throw Error("E_PROCESS_LOADER", "Cannot map ELF interpreter", 1);
      loaded_images.push_back(std::move(jit));
    }
    // Dynamic steps use absolute guest PCs; image relocations already include
    // bias.
    zvril_runtime_set_bias(memory.get(), 0);
    zvril_runtime_dynamic_code(memory.get(), 1);
    Thread main;
    main.state.resize(state_size);
    for (const auto &entry : *initial.evidence.getArray("registers"))
      if (auto *row = entry.getAsObject();
          row && row->getString("name").value_or("") == "MXCSR") {
        auto offset = std::uint64_t(row->getInteger("offset").value_or(0));
        std::uint32_t value = 0x1f80;
        if (offset + 4 <= main.state.size())
          std::memcpy(main.state.data() + offset, &value, 4);
      }
    main.tid = 1000;
    reg(main, 16,
        interpreter ? interpreter->entry + interpreter_bias
                    : image.entry + bias);
    reg(main, 4, initial_stack(image.entry + bias, bias));
    reg(main, 24, zvril_runtime_fsbase(memory.get()));
    threads.reserve(64);
    threads.push_back(std::move(main));
    for (const auto &s : image.segments) {
      auto end = s.address + bias + s.memory_size;
      if (end > UINT64_MAX - 4095)
        throw Error("E_PROCESS_IMAGE", "Image break overflow", 1);
      break_base = std::max(break_base, (end + 4095) & ~std::uint64_t(4095));
    }
    break_end = break_mapped = break_base;
  }
  ProcessResult run() {
    std::string blocked_code, blocked_message;
    std::uint64_t blocked_pc = 0;
    std::size_t current = threads.size() - 1;
    try {
      while (!group_exited) {
        if (std::chrono::steady_clock::now() >= deadline)
          throw Error("E_PROCESS_RESOURCE", "Process wall-time limit exceeded",
                      1);
        bool found = false, alive = false;
        for (std::size_t i = 0; i < threads.size(); i++) {
          current = (current + 1) % threads.size();
          if (threads[current].waiting &&
              threads[current].signals.suspend_wait &&
              (threads[current].signals.pending &
               ~threads[current].signals.mask))
            threads[current].waiting = false;
          alive |= !threads[current].exited;
          if (!threads[current].exited && !threads[current].waiting) {
            found = true;
            break;
          }
        }
        if (!found) {
          if (alive)
            throw Error("E_PROCESS_DEADLOCK",
                        "All remaining tasks are waiting on futexes", 1);
          break;
        }
        auto &thread = threads[current];
        if (signals->pending(thread.signals, thread.state, thread.valid_flags))
          continue;
        auto pc = reg(thread, 16);
        blocked_pc = pc;
        auto *status = zvril_runtime_status(memory.get());
        if (!status->steps_left)
          throw Error("E_PROCESS_RESOURCE",
                      "Process instruction budget exceeded", 1);
        std::vector<std::uint8_t> bytes;
        for (unsigned width = 0; width < 15 && pc <= UINT64_MAX - width;
             width++) {
          std::uint8_t byte = 0;
          if (!zvril_runtime_fetch(memory.get(), pc + width, &byte, 1))
            break;
          bytes.push_back(byte);
        }
        if (bytes.empty()) {
          bool mapped = zvril_runtime_probe(memory.get(), pc, 1, 0);
          if (signals->deliver(thread.signals, thread.state, thread.valid_flags,
                               11, mapped ? 2 : 1, pc, 14,
                               4 | 16 | (mapped ? 1 : 0)))
            continue;
          throw Error("E_PROCESS_FETCH",
                      "PC is outside initialized executable guest memory", 1);
        }
        ++instructions;
        if (bytes.size() >= 2 && bytes[0] == 0x0f &&
            (bytes[1] == 0x31 ||
             (bytes.size() >= 3 && bytes[1] == 0x01 && bytes[2] == 0xf9))) {
          --status->steps_left;
          auto ticks = instructions * 1000;
          reg(thread, 0, std::uint32_t(ticks));
          reg(thread, 2, ticks >> 32);
          if (bytes[1] == 0x01)
            reg(thread, 1, 0);
          reg(thread, 16, pc + (bytes[1] == 0x31 ? 2 : 3));
          continue;
        }
        if (bytes.size() >= 2 && bytes[0] == 0x0f && bytes[1] == 0xa2) {
          --status->steps_left;
          const auto leaf = std::uint32_t(reg(thread, 0));
          std::uint32_t eax = 0, ebx = 0, ecx = 0, edx = 0;
          if (leaf == 0) {
            eax = 1;
            ebx = 0x756e6547;
            edx = 0x49656e69;
            ecx = 0x6c65746e;
          }
          if (leaf == 1) {
            eax = 0x663;
            ebx = 8 << 8;
            ecx = 1 << 13;
            edx = (1u << 0) | (1u << 4) | (1u << 8) | (1u << 15) | (1u << 23) |
                  (1u << 24) | (1u << 25) | (1u << 26);
          }
          if (leaf == 0x80000000)
            eax = 0x80000001;
          if (leaf == 0x80000001)
            edx = (1u << 11) | (1u << 20) | (1u << 29);
          reg(thread, 0, eax);
          reg(thread, 3, ebx);
          reg(thread, 1, ecx);
          reg(thread, 2, edx);
          reg(thread, 16, pc + 2);
          continue;
        }
        if (bytes.size() >= 2 && bytes[0] == 0x0f && bytes[1] == 0x05) {
          --status->steps_left;
          status->fault_pc = pc;
          reg(thread, 1, pc + 2);
          reg(thread, 11, flags(thread));
          reg(thread, 16, pc + 2);
          const auto n = reg(thread, 0);
          std::array<std::uint64_t, 6> args = {reg(thread, 7), reg(thread, 6),
                                               reg(thread, 2), reg(thread, 10),
                                               reg(thread, 8), reg(thread, 9)};
          ++syscall_count;
          auto result = syscall(thread, n, args);
          reg(threads[current], 0, result);
          if (threads[current].signals.suspend_wait)
            threads[current].waiting = true;
          if (threads[current].waiting) {
            threads[current].blocked_pc = pc;
            threads[current].blocked_number = n;
          }
          Array values;
          for (auto value : args)
            values.push_back(hex(value));
          if (syscalls.size() < 4096)
            syscalls.push_back(Object{{"tid", threads[current].tid},
                                      {"pc", hex(pc)},
                                      {"number", n},
                                      {"arguments", std::move(values)},
                                      {"result", hex(result)}});
          continue;
        }
        auto existing = cache.end();
        auto artifact = artifacts.end();
        std::pair<std::uint64_t, std::vector<std::uint8_t>> key;
        for (const auto &encoding : versions[pc])
          if (encoding.size() <= bytes.size() &&
              std::equal(encoding.begin(), encoding.end(), bytes.begin())) {
            key = std::make_pair(pc, encoding);
            existing = cache.find(key);
            artifact = artifacts.find(key);
            break;
          }
        if (existing == cache.end()) {
          std::filesystem::path module_path;
          if (artifact == artifacts.end()) {
            if (artifacts.size() >= options.max_modules)
              throw Error("E_PROCESS_RESOURCE",
                          "Process dynamic module budget exceeded", 1);
            auto step = compiler.instruction(pc, bytes);
            auto name = "step-" + std::to_string(artifacts.size());
            auto *decoded =
                step.evidence.getObject("pcmap")->getArray("instructions");
            auto encoding = decoded->front()
                                .getAsObject()
                                ->getString("encoding")
                                .value_or("");
            if (encoding.empty() || encoding.size() / 2 > bytes.size())
              throw Error("E_INTERNAL", "Missing dynamic decode evidence", 2);
            bytes.resize(encoding.size() / 2);
            save_module(*step.module, options.output / name);
            auto digest = module_digest(options.output / (name + ".bc"));
            modules.push_back(Object{
                {"module", name + ".bc"},
                {"ir", name + ".ll"},
                {"pc", hex(pc)},
                {"source_bytes", bytes_hex(bytes)},
                {"instructions", std::move(*decoded)},
                {"llvm_verified", true},
                {"module_sha256", digest},
                {"runtime_linkage", "dispatcher-provided C ABI"},
                {"semantics_sha256", step.evidence.getString("semantics_sha256")
                                         .value_or("")
                                         .str()},
                {"runtime_sha256", step.evidence.getString("runtime_sha256")
                                       .value_or("")
                                       .str()}});
            if (!versions[pc].empty())
              ++modified_code;
            versions[pc].insert(bytes);
            key = std::make_pair(pc, bytes);
            artifacts.emplace(key, StepArtifact{name, digest});
            module_path = options.output / (name + ".bc");
          } else {
            auto path = options.output / (artifact->second.name + ".bc");
            if (module_digest(path) != artifact->second.digest)
              throw Error("E_PROCESS_CACHE",
                          "Cached bitcode changed after verification", 2);
            module_path = path;
            ++cache_reloads;
          }
          // Only independent instruction modules are evicted. The caller has
          // returned to the dispatcher, so no removed machine code is active.
          if (cache.size() >= options.resident_modules) {
            auto victim = std::min_element(
                cache.begin(), cache.end(), [](const auto &a, const auto &b) {
                  return a.second.last_use < b.second.last_use;
                });
            cache.erase(victim);
            ++cache_evictions;
          }
          CachedStep compiled;
          compiled.context = std::make_unique<llvm::LLVMContext>();
          llvm::SMDiagnostic diagnostic;
          auto module = llvm::parseIRFile(module_path.string(), diagnostic,
                                          *compiled.context);
          if (!module || llvm::verifyModule(*module))
            throw Error("E_PROCESS_CACHE", "Cannot load verified bitcode", 2);
          compiled.jit = std::make_unique<Jit>(std::move(module));
          compiled.entry =
              compiled.jit->get<CachedStep::Entry>("zvril_lifted_v2");
          existing = cache.emplace(std::move(key), std::move(compiled)).first;
          cache_peak = std::max<std::uint64_t>(cache_peak, cache.size());
        }
        existing->second.last_use = ++cache_clock;
        zvril_runtime_set_fsbase(memory.get(), reg(thread, 24));
        zvril_runtime_set_flags_valid(memory.get(), thread.valid_flags);
        existing->second.entry(thread.state.data(), pc, memory.get());
        thread.valid_flags = zvril_runtime_flags_valid(memory.get());
        if (status->fault && (status->fault == 1 || status->fault == 2 ||
                              status->fault == 5 || status->fault == 9)) {
          auto kind = status->fault, address = status->fault_address;
          unsigned signal = kind == 5 ? 8
                            : kind == 9 && bytes.size() >= 2 &&
                                    bytes[0] == 0x0f && bytes[1] == 0x0b
                                ? 4
                                : 11;
          unsigned trap = kind == 5 ? 0 : signal == 4 ? 6 : kind == 9 ? 13 : 14;
          unsigned fault_error =
              trap == 14
                  ? (4 | (kind == 2 ? 2 : 0) |
                     (zvril_runtime_probe(memory.get(), address, 1, 0) ? 1 : 0))
                  : 0;
          int code = signal == 8         ? 1
                     : signal == 4       ? 2
                     : trap == 13        ? 128
                     : (fault_error & 1) ? 2
                                         : 1;
          if (trap == 13)
            address = 0;
          zvril_runtime_clear_fault(memory.get());
          if (signals->deliver(thread.signals, thread.state, thread.valid_flags,
                               signal, code, address, trap, fault_error))
            continue;
          status->fault = kind;
          status->fault_address = address;
        }
        if (status->fault)
          throw Error("E_PROCESS_FAULT",
                      "Guest runtime fault " + std::to_string(status->fault) +
                          " at " + hex(status->fault_address),
                      1);
        if (zvril_runtime_unknown_flags(memory.get()))
          throw Error("E_PROCESS_FLAGS", "Guest consumed undefined flags", 1);
      }
    } catch (const Error &e) {
      if (e.exit_code != 1)
        throw;
      blocked_code = e.code;
      blocked_message = e.what();
    }
    const auto &output = files->output(false);
    const auto &error_output = files->output(true);
    Array task_records;
    for (auto &t : threads)
      task_records.push_back(Object{{"tid", t.tid},
                                    {"exited", t.exited},
                                    {"waiting", t.waiting},
                                    {"pc", hex(reg(t, 16))}});
    Object result{
        {"schema_version", "0.1"},
        {"mode", "dynamic-instruction-lifting"},
        {"status", blocked_code.empty() ? "EXECUTED" : "BLOCKED"},
        {"guest_exit_code", blocked_code.empty()
                                ? llvm::json::Value(process_exit)
                                : llvm::json::Value(nullptr)},
        {"instructions", instructions},
        {"compiled_modules", artifacts.size()},
        {"jit_resident_peak", cache_peak},
        {"jit_resident_limit", options.resident_modules},
        {"jit_evictions", cache_evictions},
        {"jit_reloads", cache_reloads},
        {"code_version_changes", modified_code},
        {"syscall_count", syscall_count},
        {"syscalls", std::move(syscalls)},
        {"modules", std::move(modules)},
        {"threads", std::move(task_records)},
        {"filesystem", files->report()},
        {"signals", signals->report()},
        {"interpreter_bias", hex(interpreter_bias)},
        {"stdout_hex", bytes_hex(output)},
        {"stderr_hex", bytes_hex(error_output)},
        {"initial_state", "SysV argc/argv/envp/auxv; virtual IDs 1000; "
                          "deterministic AT_RANDOM; empty env unless provided"},
        {"scheduling", "Cooperative single-host-thread, one guest instruction "
                       "per task; no parallel memory-order validation"},
        {"coverage_claim", "Observed execution only; unexecuted paths are not "
                           "statically lifted or verified"},
        {"virtual_cpu", "x86-64 SSE2/CX16; no AVX/XSAVE advertised"},
        {"virtual_kernel",
         "deterministic clock/random and IDs; rseq unavailable (-ENOSYS)"}};
    if (!blocked_code.empty())
      result["error"] = Object{{"code", blocked_code},
                               {"message", blocked_message},
                               {"pc", hex(blocked_pc)}};
    for (const auto &[name, data] :
         std::array<std::pair<const char *, const std::vector<std::uint8_t> *>,
                    2>{
             {{"stdout.bin", &output}, {"stderr.bin", &error_output}}}) {
      std::ofstream file(options.output / name, std::ios::binary);
      file.write(reinterpret_cast<const char *>(data->data()), data->size());
      file.close();
      if (!file)
        throw Error("E_OUTPUT", "Cannot write captured process output", 2);
    }
    return {std::move(result), blocked_code.empty() ? 0 : 1};
  }
};
} // namespace
ProcessResult execute_process(const Image &image,
                              const ProcessOptions &options) {
  Process process(image, options);
  return process.run();
}
} // namespace zvril
