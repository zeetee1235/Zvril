#include "zvril/native_trace.h"
#include "zvril/elf/image.h"
#include <cerrno>
#include <charconv>
#include <cstring>
#include <signal.h>
#include <sstream>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>

namespace zvril {
namespace {
using llvm::json::Array;
using llvm::json::Object;
using llvm::json::Value;
std::string hex(std::uint64_t v) {
  std::ostringstream s;
  s << "0x" << std::hex << v;
  return s.str();
}
std::uint64_t number(const Value &v) {
  if (auto n = v.getAsUINT64())
    return *n;
  if (auto s = v.getAsString()) {
    auto text = *s;
    if (text.starts_with("0x"))
      text = text.drop_front(2);
    std::uint64_t n = 0;
    auto r = std::from_chars(text.begin(), text.end(), n, 16);
    if (r.ec == std::errc() && r.ptr == text.end())
      return n;
  }
  throw Error("E_TRACE_PROTOCOL", "Invalid trace integer", 2);
}
struct Shared {
  std::uint64_t base = 0, buffers[16] = {};
};
} // namespace
struct NativeTrace::Impl {
  Shared *shared = nullptr;
  std::set<std::uint64_t> pcs;
  std::size_t limit;
  Array records;
  Array memory;
  std::vector<Segment> segments;
  std::size_t stack_bytes;
  std::string xmm;
  std::uint64_t return_pc = 0, mxcsr = 0;
  bool started = false, complete = false, truncated = false;
  std::string error;
  Impl(const Image &image, const std::set<std::uint64_t> &p,
       std::size_t stack, std::size_t l)
      : pcs(p), limit(l), segments(image.segments), stack_bytes(stack) {
    auto *memory = mmap(nullptr, sizeof(Shared), PROT_READ | PROT_WRITE,
                        MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (memory == MAP_FAILED)
      throw Error("E_RESOURCE_LIMIT", "Cannot allocate trace metadata channel",
                  1);
    shared = new (memory) Shared;
  }
  ~Impl() {
    if (shared)
      munmap(shared, sizeof(Shared));
  }
  bool snapshot(pid_t pid, const user_regs_struct &r) {
    constexpr char digits[] = "0123456789abcdef";
    const auto bytes = [&](std::uint64_t address, std::size_t size) {
      std::string encoded;
      encoded.reserve(size * 2);
      for (std::size_t i = 0; i < size; i += sizeof(long)) {
        errno = 0;
        auto word = ptrace(PTRACE_PEEKDATA, pid,
                           reinterpret_cast<void *>(address + i), nullptr);
        if (word == -1 && errno)
          throw Error("E_TRACE_PROTOCOL", "Cannot snapshot native memory", 1);
        for (unsigned j = 0; j < sizeof(long) && i + j < size; j++) {
          auto v = (static_cast<unsigned long>(word) >> (j * 8)) & 255;
          encoded.push_back(digits[v >> 4]);
          encoded.push_back(digits[v & 15]);
        }
      }
      return encoded;
    };
    try {
      std::size_t total = stack_bytes + 136;
      for (const auto &s : segments) {
        if (!(s.flags & 2) || !s.memory_size)
          continue;
        if ((s.flags & 1) || s.memory_size > 1048576 ||
            total > 1048576 - s.memory_size)
          throw Error("E_TRACE_PROTOCOL", "Writable image snapshot exceeds trace contract", 1);
        total += s.memory_size;
        memory.push_back(Object{{"address", hex(shared->base + s.address)},
                                {"hex", bytes(shared->base + s.address, s.memory_size)},
                                {"kind", "image"}});
      }
      memory.push_back(Object{{"address", hex(r.rsp - 128)},
                              {"hex", bytes(r.rsp - 128, 136 + stack_bytes)},
                              {"kind", "stack"}});
      errno = 0;
      return_pc = ptrace(PTRACE_PEEKDATA, pid,
                         reinterpret_cast<void *>(r.rsp), nullptr);
      if (return_pc == UINT64_MAX && errno)
        throw Error("E_TRACE_PROTOCOL", "Cannot read native return PC", 1);
      user_fpregs_struct fp{};
      if (ptrace(PTRACE_GETFPREGS, pid, nullptr, &fp))
        throw Error("E_TRACE_PROTOCOL", "Cannot read native SSE state", 1);
      const auto *data = reinterpret_cast<const unsigned char *>(fp.xmm_space);
      for (unsigned i = 0; i < sizeof(fp.xmm_space); i++) {
        xmm.push_back(digits[data[i] >> 4]);
        xmm.push_back(digits[data[i] & 15]);
      }
      mxcsr = fp.mxcsr;
      return true;
    } catch (const Error &e) {
      error = e.what();
      return false;
    }
  }
};
NativeTrace::NativeTrace(const Image &image, const std::set<std::uint64_t> &pcs,
                         std::size_t stack, std::size_t limit)
    : impl(std::make_unique<Impl>(image, pcs, stack, limit)) {}
NativeTrace::~NativeTrace() = default;
void NativeTrace::enable_child() {
  if (ptrace(PTRACE_TRACEME, 0, nullptr, nullptr))
    throw Error("E_TRACE_UNAVAILABLE", "Kernel denied PTRACE_TRACEME", 1);
}
void NativeTrace::metadata_child(std::uint64_t base,
                                 const std::vector<std::uint64_t> &buffers) {
  impl->shared->base = base;
  for (std::size_t i = 0; i < buffers.size() && i < 16; i++)
    impl->shared->buffers[i] = buffers[i];
}
bool NativeTrace::stopped(pid_t pid, int status) {
  if (!WIFSTOPPED(status))
    return false;
  const auto resume = [&](bool step, int signal) {
    if (ptrace(step ? PTRACE_SINGLESTEP : PTRACE_CONT, pid, nullptr,
               reinterpret_cast<void *>(std::uintptr_t(signal)))) {
      impl->error = "Cannot resume traced child";
      return false;
    }
    return true;
  };
  if (ptrace(PTRACE_SETOPTIONS, pid, nullptr,
             reinterpret_cast<void *>(PTRACE_O_EXITKILL))) {
    impl->error = "Cannot install tracer exit policy";
    return false;
  }
  int signal = WSTOPSIG(status);
  if (signal != SIGTRAP) {
    impl->complete = impl->started;
    return resume(false, signal);
  }
  user_regs_struct r{};
  if (ptrace(PTRACE_GETREGS, pid, nullptr, &r)) {
    impl->error = "Cannot read native registers";
    return false;
  }
  const auto base = impl->shared->base;
  if (r.rip >= base && impl->pcs.contains(r.rip - base)) {
    if (!impl->started && !impl->snapshot(pid, r))
      return resume(false, 0);
    impl->started = true;
    if (impl->records.size() >= impl->limit) {
      impl->truncated = true;
      return resume(false, 0);
    }
    const std::uint64_t gpr[] = {r.rax, r.rcx, r.rdx, r.rbx, r.rsp, r.rbp,
                                 r.rsi, r.rdi, r.r8,  r.r9,  r.r10, r.r11,
                                 r.r12, r.r13, r.r14, r.r15, r.rip};
    Array regs;
    for (auto v : gpr)
      regs.push_back(hex(v));
    impl->records.push_back(Object{{"pc", hex(r.rip - base)},
                                   {"gpr", std::move(regs)},
                                   {"flags", hex(r.eflags)}});
  } else if (impl->started) {
    impl->complete = true;
    return resume(false, 0);
  }
  return resume(true, 0);
}
Object NativeTrace::result() const {
  Array buffers;
  for (auto value : impl->shared->buffers)
    buffers.push_back(hex(value));
  return Object{{"records", Array(impl->records)},
                {"image_base", hex(impl->shared->base)},
                {"buffer_bases", std::move(buffers)},
                {"memory", Array(impl->memory)},
                {"initial_xmm", impl->xmm},
                {"initial_mxcsr", hex(impl->mxcsr)},
                {"return_pc", hex(impl->return_pc)},
                {"truncated", impl->truncated},
                {"complete", impl->complete},
                {"error", impl->error}};
}
Object compare_instruction_traces(const Object &native, const Object &lifted) {
  auto *a = native.getArray("records");
  auto *b = lifted.getArray("records");
  if (!a || !b || !native.getString("error").value_or("").empty() ||
      native.getBoolean("truncated").value_or(true) ||
      lifted.getBoolean("truncated").value_or(true) ||
      !native.getBoolean("complete").value_or(false))
    return Object{{"status", "UNKNOWN"},
                  {"reason", "Trace unavailable, incomplete or truncated"}};
  const auto mismatch = [&](std::size_t i, const std::string &field,
                            const Value &expected, const Value &actual) {
    return Object{{"status", "MISMATCH"},
                  {"instruction_index", i},
                  {"field", field},
                  {"native", expected},
                  {"lifted", actual}};
  };
  for (std::size_t i = 0; i < std::min(a->size(), b->size()); i++) {
    auto *left = (*a)[i].getAsObject();
    auto *right = (*b)[i].getAsObject();
    if (!left || !right || !left->get("pc") || !right->get("pc") ||
        !left->get("flags") || !right->get("flags") || !right->get("flags_valid"))
      throw Error("E_TRACE_PROTOCOL", "Malformed trace row", 2);
    if (*left->get("pc") != *right->get("pc"))
      return mismatch(i, "pc", *left->get("pc"), *right->get("pc"));
    auto *x = left->getArray("gpr");
    auto *y = right->getArray("gpr");
    if (!x || !y || x->size() != 17 || y->size() != 17)
      throw Error("E_TRACE_PROTOCOL", "Malformed GPR trace", 2);
    for (unsigned j = 0; j < 17; j++)
      if (number((*x)[j]) != number((*y)[j]))
        return mismatch(i, "gpr[" + std::to_string(j) + "]", (*x)[j], (*y)[j]);
    const auto valid = number(*right->get("flags_valid"));
    auto f = number(*left->get("flags")), g = number(*right->get("flags"));
    if ((f ^ g) & valid)
      return mismatch(i, "defined_flags", Value(hex(f & valid)),
                      Value(hex(g & valid)));
  }
  if (a->size() != b->size())
    return mismatch(std::min(a->size(), b->size()), "instruction_count",
                    Value(a->size()), Value(b->size()));
  return Object{{"status", "PASS"}, {"compared_instructions", a->size()}};
}
} // namespace zvril
