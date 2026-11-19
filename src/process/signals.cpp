#include "zvril/elf/image.h"
#include "zvril/process_signals.h"
#include <algorithm>
#include <cstring>
#include <string>

namespace zvril {
namespace {
constexpr std::uint64_t unblockable = (UINT64_C(1) << 8) | (UINT64_C(1) << 18);
constexpr std::uint64_t restorer_flag = 0x4000000, onstack_flag = 0x8000000,
                        nodefer_flag = 0x40000000, reset_flag = 0x80000000;
std::uint64_t error(unsigned e) { return std::uint64_t(0) - e; }
// Linux x86-64 ucontext/sigcontext wire layout, independent of libc's larger
// ucontext_t storage. The offsets are public kernel ABI, not host pointers.
constexpr unsigned frame_uc = 8, uc_context = 40, uc_mask = 296,
                   frame_info = 312;
constexpr unsigned context_regs[] = {8, 9, 10, 11, 12, 13, 14, 15, 7,
                                     6, 5, 3,  2,  0,  1,  4,  16};
constexpr unsigned flag_bits[] = {4, 0, 10, 11, 2, 7, 6};
void put(std::uint8_t *data, std::size_t offset, std::uint64_t value) {
  std::memcpy(data + offset, &value, 8);
}
std::uint64_t take(const std::uint8_t *data, std::size_t offset) {
  std::uint64_t value;
  std::memcpy(&value, data + offset, 8);
  return value;
}
bool inside(std::uint64_t sp, const SignalTask &task) {
  return !(task.alt_flags & 2) && sp >= task.alt_sp &&
         sp - task.alt_sp < task.alt_size;
}
} // namespace
ProcessSignals::ProcessSignals(ZvrilRuntime *r, Get g, Set s,
                               const llvm::json::Array &layout)
    : memory(r), get(g), set(s) {
  xmm.fill(UINT64_MAX);
  for (const auto &entry : layout) {
    auto *row = entry.getAsObject();
    if (!row)
      continue;
    auto name = row->getString("name").value_or("");
    auto offset = row->getInteger("offset");
    if (!offset)
      continue;
    if (name == "MXCSR")
      mxcsr = *offset;
    for (unsigned i = 0; i < 16; i++)
      if (name == "XMM" + std::to_string(i))
        xmm[i] = *offset;
  }
}
bool ProcessSignals::read(std::uint64_t address, void *data,
                          std::uint64_t size) {
  if (zvril_runtime_read(memory, address, data, size))
    return true;
  zvril_runtime_clear_fault(memory);
  return false;
}
bool ProcessSignals::write(std::uint64_t address, const void *data,
                           std::uint64_t size) {
  if (zvril_runtime_write(memory, address, data, size))
    return true;
  zvril_runtime_clear_fault(memory);
  return false;
}
bool ProcessSignals::restartable(unsigned signal) const {
  return signal < actions.size() && (actions[signal].flags & 0x10000000);
}
std::optional<std::uint64_t>
ProcessSignals::call(std::uint64_t n, const std::array<std::uint64_t, 6> &a,
                     SignalTask &task, std::vector<std::uint8_t> &state,
                     std::uint64_t &valid) {
  switch (n) {
  case 13: {
    auto signal = std::uint32_t(a[0]);
    if (!signal || signal > 64 || signal == 9 || signal == 19 || a[3] != 8)
      return error(22);
    Action replacement;
    if (a[1]) {
      if (!read(a[1], &replacement, 32))
        return error(14);
      constexpr std::uint64_t supported = 4 | restorer_flag | onstack_flag |
                                          0x10000000 | nodefer_flag |
                                          reset_flag | 1 | 2;
      if (replacement.flags & ~supported)
        throw Error("E_PROCESS_SIGNAL", "Unmodeled sigaction flags", 1);
      replacement.mask &= ~unblockable;
    }
    if (a[2] && !write(a[2], &actions[signal], 32))
      return error(14);
    if (a[1])
      actions[signal] = replacement;
    return 0;
  }
  case 14: {
    if (a[3] != 8)
      return error(22);
    std::uint64_t replacement = 0;
    if (a[1] && !read(a[1], &replacement, 8))
      return error(14);
    if (a[1] && a[0] > 2)
      return error(22);
    if (a[2] && !write(a[2], &task.mask, 8))
      return error(14);
    if (a[1])
      task.mask = (a[0] == 0   ? task.mask | replacement
                   : a[0] == 1 ? task.mask & ~replacement
                               : replacement) &
                  ~unblockable;
    return 0;
  }
  case 15: {
    auto sp = get(state.data(), 4);
    if (task.frames.empty() || sp != task.frames.back().address + 8)
      throw Error("E_PROCESS_SIGNAL",
                  "rt_sigreturn does not reference a live signal frame", 1);
    auto saved = std::move(task.frames.back());
    task.frames.pop_back();
    std::array<std::uint8_t, 304> context{};
    if (!read(sp, context.data(), context.size()))
      throw Error("E_PROCESS_SIGNAL", "Unreadable sigreturn context", 1);
    if (take(context.data(), 0) & 1)
      throw Error("E_PROCESS_SIGNAL",
                  "XSAVE sigreturn frames are not implemented", 1);
    auto new_pc = take(context.data(), uc_context + 16 * 8),
         new_sp = take(context.data(), uc_context + 15 * 8);
    if (new_pc >= 0x800000000000 || new_sp >= 0x800000000000)
      throw Error("E_PROCESS_SIGNAL", "Noncanonical sigreturn PC/SP", 1);
    auto floating_address = take(context.data(), uc_context + 184);
    std::array<std::uint8_t, 512> floating = saved.floating;
    if (floating_address &&
        !read(floating_address, floating.data(), floating.size()))
      throw Error("E_PROCESS_SIGNAL", "Unreadable FP signal state", 1);
    auto expected = saved.floating;
    // The baseline CPU exposes legacy SSE state. Explicitly refuse edits to
    // x87/control fields that are not mapped by the current Remill adapter.
    std::fill(expected.begin() + 24, expected.begin() + 28, 0);
    std::fill(expected.begin() + 160, expected.begin() + 416, 0);
    auto observed = floating;
    std::fill(observed.begin() + 24, observed.begin() + 28, 0);
    std::fill(observed.begin() + 160, observed.begin() + 416, 0);
    if (observed != expected)
      throw Error("E_PROCESS_SIGNAL",
                  "Modified x87/unsupported FP signal context", 1);
    auto fs = get(state.data(), 24), gs = get(state.data(), 25);
    state = std::move(saved.state);
    set(state.data(), 24, fs);
    set(state.data(), 25, gs);
    for (unsigned i = 0; i < 17; i++)
      set(state.data(), context_regs[i],
          take(context.data(), uc_context + 8 * i));
    auto flags = take(context.data(), uc_context + 17 * 8);
    for (unsigned i = 0; i < 7; i++)
      set(state.data(), 17 + i, (flags >> flag_bits[i]) & 1);
    for (unsigned i = 0; i < 16; i++)
      if (xmm[i] != UINT64_MAX && xmm[i] + 16 <= state.size())
        std::memcpy(state.data() + xmm[i], floating.data() + 160 + 16 * i, 16);
    if (mxcsr && mxcsr + 4 <= state.size())
      std::memcpy(state.data() + mxcsr, floating.data() + 24, 4);
    task.mask = take(context.data(), uc_mask) & ~unblockable;
    task.alt_sp = take(context.data(), 16);
    task.alt_flags =
        std::uint32_t(take(context.data(), 24)) & ~std::uint64_t(1);
    task.alt_size = take(context.data(), 32);
    valid = saved.valid_flags;
    task.suspend_wait = false;
    ++returned;
    return get(state.data(), 0);
  }
  case 127:
    if (a[1] != 8)
      return error(22);
    {
      auto mask = task.pending & task.mask;
      return write(a[0], &mask, 8) ? 0 : error(14);
    }
  case 130: {
    if (a[1] != 8)
      return error(22);
    std::uint64_t mask;
    if (!read(a[0], &mask, 8))
      return error(14);
    task.suspended_mask = task.mask;
    task.mask = mask & ~unblockable;
    task.suspend_wait = true;
    return error(4);
  }
  case 131: {
    std::uint64_t previous[3] = {task.alt_sp, task.alt_flags, task.alt_size};
    bool active = inside(get(state.data(), 4), task);
    if (active)
      previous[1] |= 1;
    std::uint64_t next[3]{};
    if (a[0]) {
      if (!read(a[0], next, 24))
        return error(14);
      if (active)
        return error(1);
      if (next[1] != 0 && next[1] != 2 && next[1] != 0x80000000)
        return error(22);
      if (!(next[1] & 2) && (next[2] < 2048 || next[0] >= 0x800000000000 ||
                             next[2] > 0x800000000000 - next[0]))
        return error(next[2] < 2048 ? 12 : 22);
    }
    if (a[1] && !write(a[1], previous, 24))
      return error(14);
    if (a[0]) {
      task.alt_sp = next[0];
      task.alt_flags = next[1];
      task.alt_size = next[2];
    }
    return 0;
  }
  default:
    return {};
  }
}
bool ProcessSignals::deliver(SignalTask &task, std::vector<std::uint8_t> &state,
                             std::uint64_t &valid, unsigned signal, int code,
                             std::uint64_t address, unsigned trap,
                             unsigned fault_error) {
  if (!signal || signal > 64 || (task.mask & (UINT64_C(1) << (signal - 1))))
    return false;
  auto action = actions[signal];
  if (action.handler < 2)
    return false;
  if (!(action.flags & restorer_flag) || !action.restorer)
    throw Error("E_PROCESS_SIGNAL",
                "x86-64 signal handler requires SA_RESTORER", 1);
  if (task.frames.size() >= 32)
    throw Error("E_PROCESS_SIGNAL", "Signal nesting exceeds 32 frames", 1);
  auto original_sp = get(state.data(), 4),
       top = original_sp >= 128 ? original_sp - 128 : 0;
  if ((action.flags & onstack_flag) && !(task.alt_flags & 2) &&
      !inside(original_sp, task))
    top = task.alt_sp + task.alt_size;
  if (top < 512 + 440 + 64)
    throw Error("E_PROCESS_SIGNAL", "Insufficient signal stack", 1);
  auto fp = (top - 512) & ~std::uint64_t(63),
       frame = ((fp - 440) & ~std::uint64_t(15)) - 8;
  if (!zvril_runtime_probe(memory, frame, fp + 512 - frame, ZVRIL_W))
    throw Error("E_PROCESS_SIGNAL", "Signal stack is not writable", 1);
  SignalFrame saved;
  saved.state = state;
  saved.address = frame;
  saved.valid_flags = valid;
  saved.old_alt_sp = task.alt_sp;
  saved.old_alt_size = task.alt_size;
  saved.old_alt_flags = task.alt_flags;
  auto &floating = saved.floating;
  floating[0] = 0x7f;
  floating[1] = 3;
  std::uint32_t mx = 0x1f80, mask = 0xffff;
  if (mxcsr && mxcsr + 4 <= state.size()) {
    std::memcpy(&mx, state.data() + mxcsr, 4);
    if (!mx)
      mx = 0x1f80;
  }
  std::memcpy(floating.data() + 24, &mx, 4);
  std::memcpy(floating.data() + 28, &mask, 4);
  for (unsigned i = 0; i < 16; i++)
    if (xmm[i] != UINT64_MAX && xmm[i] + 16 <= state.size())
      std::memcpy(floating.data() + 160 + 16 * i, state.data() + xmm[i], 16);
  std::array<std::uint8_t, 440> bytes{};
  put(bytes.data(), 0, action.restorer);
  put(bytes.data(), frame_uc, 6);
  put(bytes.data(), frame_uc + 16, task.alt_sp);
  put(bytes.data(), frame_uc + 24,
      task.alt_flags | (inside(original_sp, task) ? 1 : 0));
  put(bytes.data(), frame_uc + 32, task.alt_size);
  for (unsigned i = 0; i < 17; i++)
    put(bytes.data(), frame_uc + uc_context + 8 * i,
        get(state.data(), context_regs[i]));
  std::uint64_t flags = 0x202;
  for (unsigned i = 0; i < 7; i++)
    flags |= (get(state.data(), 17 + i) & 1) << flag_bits[i];
  put(bytes.data(), frame_uc + uc_context + 136, flags);
  put(bytes.data(), frame_uc + uc_context + 144, UINT64_C(0x002b000000000033));
  put(bytes.data(), frame_uc + uc_context + 152, fault_error);
  put(bytes.data(), frame_uc + uc_context + 160, trap);
  auto old_mask = task.suspended_mask.value_or(task.mask);
  task.suspended_mask.reset();
  put(bytes.data(), frame_uc + uc_context + 168, old_mask);
  put(bytes.data(), frame_uc + uc_context + 176, address);
  put(bytes.data(), frame_uc + uc_context + 184, fp);
  put(bytes.data(), frame_uc + uc_mask, old_mask);
  std::int32_t signo = signal;
  std::memcpy(bytes.data() + frame_info, &signo, 4);
  std::memcpy(bytes.data() + frame_info + 8, &code, 4);
  put(bytes.data(), frame_info + 16, address);
  if (code <= 0) {
    std::uint32_t pid = 1000, uid = 1000;
    std::memcpy(bytes.data() + frame_info + 16, &pid, 4);
    std::memcpy(bytes.data() + frame_info + 20, &uid, 4);
  }
  if (!write(frame, bytes.data(), bytes.size()) ||
      !write(fp, floating.data(), floating.size()))
    throw Error("E_PROCESS_SIGNAL", "Cannot create signal frame", 1);
  task.frames.push_back(std::move(saved));
  task.mask |= action.mask;
  if (!(action.flags & nodefer_flag))
    task.mask |= UINT64_C(1) << (signal - 1);
  task.mask &= ~unblockable;
  task.suspend_wait = false;
  if ((action.flags & onstack_flag) && (task.alt_flags & 0x80000000))
    task.alt_flags = 2;
  if (action.flags & reset_flag)
    actions[signal] = {};
  set(state.data(), 4, frame);
  set(state.data(), 16, action.handler);
  set(state.data(), 0, 0);
  set(state.data(), 7, signal);
  set(state.data(), 6, frame + frame_info);
  set(state.data(), 2, frame + frame_uc);
  set(state.data(), 19, 0);
  valid |= 0x400;
  ++delivered;
  return true;
}
bool ProcessSignals::pending(SignalTask &task, std::vector<std::uint8_t> &state,
                             std::uint64_t &valid) {
  auto available = task.pending & ~task.mask;
  for (unsigned signal = 1; signal <= 64; signal++)
    if (available & (UINT64_C(1) << (signal - 1))) {
      task.pending &= ~(UINT64_C(1) << (signal - 1));
      if (actions[signal].handler == 1 ||
          (!actions[signal].handler &&
           (signal == 17 || signal == 23 || signal == 28)))
        return false;
      if (!actions[signal].handler)
        throw Error("E_PROCESS_SIGNAL",
                    "Unhandled pending signal " + std::to_string(signal), 1);
      if (signal >= 32)
        throw Error("E_PROCESS_SIGNAL",
                    "Realtime queued-signal semantics are not implemented", 1);
      return deliver(task, state, valid, signal, task.pending_code[signal]);
    }
  return false;
}
llvm::json::Object ProcessSignals::report() const {
  return llvm::json::Object{
      {"delivered", delivered},
      {"sigreturns", returned},
      {"frame_abi", "Linux x86-64 legacy FP; modified x87/XSAVE rejected"}};
}
} // namespace zvril
