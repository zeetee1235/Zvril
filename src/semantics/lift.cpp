#include "zvril/lift.h"
#include "zvril/abi.h"
#include <elf.h>

#ifdef ZVRIL_HAS_REMILL
#include "remill_license.h"
#include "zvril/analysis/indirect.h"
#include "zvril/ir/image.h"
#include "zvril/ir/process_runtime.h"
#include "zvril/ir/step.h"
#include <llvm/Bitcode/BitcodeWriter.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Verifier.h>
#include <llvm/IRReader/IRReader.h>
#include <llvm/Linker/Linker.h>
#include <llvm/Passes/PassBuilder.h>
#include <llvm/Support/FileSystem.h>
#include <llvm/Support/Path.h>
#include <llvm/Support/SHA256.h>
#include <llvm/Support/SourceMgr.h>
#include <llvm/Transforms/IPO/AlwaysInliner.h>
#include <llvm/Transforms/IPO/GlobalDCE.h>
#include <llvm/Transforms/Utils/BasicBlockUtils.h>
#include <llvm/Transforms/Utils/Cloning.h>
#include <remill/Arch/Arch.h>
#include <remill/Arch/Instruction.h>
#include <remill/BC/ABI.h>
#include <remill/BC/Util.h>
#endif

#include <algorithm>
#include <array>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <map>
#include <set>
#include <sstream>

namespace zvril {
namespace {
using llvm::json::Array;
using llvm::json::Object;
[[maybe_unused]] std::string hx(std::uint64_t v) {
  std::ostringstream s;
  s << "0x" << std::hex << v;
  return s.str();
}

#ifdef ZVRIL_HAS_REMILL
using namespace llvm;
using Inst = remill::Instruction;

std::string repeat_base(StringRef name) {
  for (auto prefix : {"REP_", "REPE_", "REPNE_"})
    if (name.starts_with(prefix))
      return name.drop_front(std::strlen(prefix)).str();
  return {};
}
bool string_operation(StringRef name) {
  return std::set<StringRef>{"MOVSB", "MOVSW", "MOVSD", "MOVSQ", "STOSB",
                             "STOSW", "STOSD", "STOSQ", "LODSB", "LODSW",
                             "LODSD", "LODSQ", "CMPSB", "CMPSW", "CMPSD",
                             "CMPSQ", "SCASB", "SCASW", "SCASD", "SCASQ"}
      .contains(name);
}

// Remill builds its x86 semantics with the host C++ compiler. Builtins such as
// __builtin_sqrt are emitted as libm calls when errno preservation prevents the
// LLVM intrinsic folding. Process execution registers bounded host wrappers for
// these exact names; static lifting continues to reject them.
bool math_bridge(StringRef name) {
  static const std::set<StringRef> names{
      "fabs",    "fabsf",   "fabsl",   "sqrt",    "sqrtf",   "sqrtl",
      "cos",     "cosf",    "cosl",    "sin",     "sinf",    "sinl",
      "tan",     "tanf",    "tanl",    "atan",    "atanf",   "atanl",
      "exp2",    "exp2f",   "exp2l",   "log2",    "log2f",   "log2l",
      "nearbyint", "nearbyintf", "nearbyintl", "trunc", "truncf", "truncl",
      "round",   "roundf",  "roundl",  "ceil",    "ceilf",   "ceill",
      "floor",   "floorf",  "floorl"};
  return names.contains(name);
}

[[noreturn]] void fail(const std::string &code, std::uint64_t pc,
                       const std::string &text) {
  Error error(code, hx(pc) + ": " + text, 1);
  error.pc = pc;
  throw error;
}

Function select(const Image &image, const LiftOptions &options) {
  std::optional<Function> chosen;
  for (const auto &f : image.functions) {
    if ((!options.symbol.empty() && f.name == options.symbol) ||
        (options.address && f.address == *options.address)) {
      if (chosen && (chosen->address != f.address ||
                     (chosen->size && f.size && chosen->size != f.size)))
        fail("E_FUNCTION_AMBIGUOUS", f.address,
             "Conflicting function candidates");
      if (!chosen || f.size)
        chosen = f;
    }
  }
  if (!chosen && options.address && options.size)
    chosen = Function{"address_" + hx(*options.address),
                      "user_range",
                      *options.address,
                      *options.size,
                      0,
                      0};
  if (!chosen)
    throw Error("E_FUNCTION_NOT_FOUND",
                "No matching function; address-only lifting requires --size "
                "when no sized symbol exists",
                1);
  if (options.size) {
    if (chosen->size && chosen->size != *options.size)
      fail("E_FUNCTION_AMBIGUOUS", chosen->address,
           "--size conflicts with symbol size");
    chosen->size = *options.size;
  }
  if (!chosen->size || chosen->size > UINT64_MAX - chosen->address)
    fail("E_FUNCTION_AMBIGUOUS", chosen->address,
         "A nonempty, bounded function range is required");
  return *chosen;
}

struct Graph {
  std::map<std::uint64_t, Function> functions;
  std::map<std::uint64_t, std::unique_ptr<Inst>> instructions;
  std::set<std::uint64_t> return_sites;
  Array edges;
  std::map<std::uint64_t, std::string> external_calls;
  std::map<std::uint64_t, std::string> external_requests;
  std::map<std::uint64_t, std::string> unresolved;
  std::map<std::uint64_t, std::uint64_t> resolved_calls;
  std::map<std::uint64_t, std::uint64_t> constant_predecessors;
  std::map<std::uint64_t, std::set<std::uint64_t>> indirect_targets;
  std::vector<std::pair<std::uint64_t, std::uint64_t>> table_predecessors;
  Array indirect_evidence;
};

std::string_view executable_bytes(const Image &image, std::uint64_t pc,
                                  std::uint64_t max) {
  for (const auto &s : image.segments) {
    if (!(s.flags & 1) || pc < s.address)
      continue;
    const auto delta = pc - s.address;
    if (delta < s.file_size) {
      const auto count = std::min(max, s.file_size - delta);
      return {
          reinterpret_cast<const char *>(image.bytes.data() + s.offset + delta),
          static_cast<std::size_t>(count)};
    }
  }
  fail("E_ELF_RANGE", pc,
       "Instruction is outside file-backed executable memory");
}

Graph recover(const Image &image, const Function &root,
              const remill::Arch &arch, llvm::Module &module,
              const LiftOptions &options, bool process_step = false) {
  auto limit = std::min(options.max_instructions, options.max_blocks);
  auto partial = options.allow_partial;
  Graph graph;
  graph.functions.emplace(root.address, root);
  std::set<std::uint64_t> pending{root.address};
  const auto owner = [&](std::uint64_t pc) -> const Function * {
    for (const auto &[_, f] : graph.functions)
      if (pc >= f.address && pc - f.address < f.size)
        return &f;
    return nullptr;
  };
  const auto add_target = [&](std::uint64_t from, std::uint64_t target,
                              const std::string &kind) {
    if (!owner(target)) {
      std::optional<Function> candidate;
      for (const auto &f : image.functions)
        if (f.address == target && f.size) {
          if (candidate && candidate->size != f.size)
            fail("E_FUNCTION_AMBIGUOUS", target, "Conflicting callee bounds");
          candidate = f;
        }
      if (!candidate)
        fail("E_UNRESOLVED_EDGE", from,
             "Unresolved " + kind + " target " + hx(target));
      if (graph.functions.size() >= options.max_functions)
        fail("E_RESOURCE_LIMIT", from,
             "Function closure exceeds --max-functions");
      for (const auto &[_, f] : graph.functions)
        if (candidate->address < f.address + f.size &&
            f.address < candidate->address + candidate->size)
          fail("E_FUNCTION_AMBIGUOUS", target,
               "Overlapping function ranges in call closure");
      graph.functions.emplace(candidate->address, *candidate);
    }
    graph.edges.push_back(
        Object{{"from", hx(from)}, {"to", hx(target)}, {"kind", kind}});
    pending.insert(target);
  };
  const auto import_at = [&](std::uint64_t got) -> std::string {
    for (const auto &r : image.relocations)
      if (r.active_dynamic && r.offset == got && (r.type == 6 || r.type == 7)) {
        if (const auto *v = symbol_version(image, r)) {
          if (!r.symbol_section &&
              (!v->version.starts_with("GLIBC_") ||
               v->version == "GLIBC_PRIVATE" ||
               !std::set<std::string>{"libc.so.6", "libm.so.6",
                                      "libpthread.so.0", "libdl.so.2",
                                      "librt.so.1", "ld-linux-x86-64.so.2"}
                    .contains(v->provider)))
            fail("E_EXTERNAL_UNMODELED", got,
                 "No ABI model for " + r.symbol + "@" + v->version + " from " +
                     v->provider);
          return r.symbol + "@" + v->version;
        }
        return r.symbol;
      }
    return {};
  };
  const auto plt = [&](std::uint64_t target) -> std::string {
    auto code = executable_bytes(image, target, 16);
    std::size_t at = 0;
    if (code.size() >= 4 &&
        code.substr(0, 4) == std::string_view("\xf3\x0f\x1e\xfa", 4))
      at = 4;
    if (at < code.size() && static_cast<unsigned char>(code[at]) == 0xf2)
      at++;
    if (code.size() < at + 6 || static_cast<unsigned char>(code[at]) != 0xff ||
        static_cast<unsigned char>(code[at + 1]) != 0x25)
      return {};
    std::int32_t displacement;
    std::memcpy(&displacement, code.data() + at + 2, 4);
    return import_at(target + at + 6 + displacement);
  };
  const auto external = [&](std::uint64_t pc, const std::string &symbol) {
    for (const auto &r : image.relocations)
      if (r.active_dynamic &&
          (symbol_version(image, r)
               ? r.symbol + "@" + symbol_version(image, r)->version
               : r.symbol) == symbol &&
          r.symbol_section && r.symbol_type == STT_FUNC) {
        add_target(pc, r.symbol_value, "self_binding");
        graph.resolved_calls[pc] = r.symbol_value;
        return;
      }
    static const std::set<std::string> allowed{
        "memcpy",        "memmove",        "memset",  "memcmp",
        "strlen",        "strcmp",         "strncmp", "malloc",
        "calloc",        "realloc",        "free",    "__tls_get_addr",
        "__ctype_b_loc", "__zvril_tlsdesc"};
    auto model = symbol.substr(0, symbol.find('@'));
    if (!allowed.contains(model))
      fail("E_EXTERNAL_UNMODELED", pc, "No guest ABI bridge for " + symbol);
    graph.external_calls.emplace(pc, model);
    graph.external_requests.emplace(pc, symbol);
    graph.edges.push_back(Object{
        {"from", hx(pc)}, {"external", symbol}, {"kind", "external_call"}});
  };
  const auto constant_target =
      [&](std::uint64_t pc,
          const Inst &branch) -> std::optional<std::uint64_t> {
    auto previous = graph.instructions.lower_bound(pc);
    if (previous == graph.instructions.begin())
      return std::nullopt;
    --previous;
    const auto &definition = *previous->second;
    if (definition.next_pc != pc ||
        definition.category != Inst::kCategoryNormal)
      return std::nullopt;
    std::string target_register;
    for (const auto &op : branch.operands)
      if (op.type == remill::Operand::kTypeRegister &&
          op.action == remill::Operand::kActionRead && op.size == 64) {
        target_register = op.reg.name;
        break;
      }
    bool writes = false;
    for (const auto &op : definition.operands)
      if (op.type == remill::Operand::kTypeRegister &&
          op.action == remill::Operand::kActionWrite && op.size == 64 &&
          op.reg.name == target_register)
        writes = true;
    if (!writes)
      return std::nullopt;
    for (const auto &op : definition.operands) {
      std::optional<std::uint64_t> target;
      if (definition.function.starts_with("LEA_") &&
          op.type == remill::Operand::kTypeAddress &&
          op.addr.index_reg.name.empty() &&
          (op.addr.base_reg.name == "NEXT_PC" ||
           op.addr.base_reg.name == "RIP" || op.addr.base_reg.name == "PC"))
        target = definition.next_pc + op.addr.displacement;
      if (image.type == ET_EXEC && definition.function.starts_with("MOV_") &&
          op.type == remill::Operand::kTypeImmediate)
        target = op.imm.val;
      if (target) {
        graph.constant_predecessors[pc] = previous->first;
        return target;
      }
    }
    return std::nullopt;
  };
  while (!pending.empty()) {
    const auto pc = *pending.begin();
    pending.erase(pending.begin());
    if (graph.instructions.contains(pc))
      continue;
    if (graph.instructions.size() >= limit)
      fail("E_RESOURCE_LIMIT", pc, "Instruction budget exceeded");
    try {
      const auto *f = owner(pc);
      if (!f)
        fail("E_UNRESOLVED_EDGE", pc, "No bounded owner for instruction");
      auto inst = std::make_unique<Inst>();
      const auto bytes = executable_bytes(
          image, pc, std::min<std::uint64_t>(15, f->size - (pc - f->address)));
      bool decoded = false;
      // Decode the shortest valid instruction to avoid Remill's call/pop idiom
      // fusion.
      for (std::size_t width = 1; width <= bytes.size(); ++width) {
        if (arch.DecodeInstruction(pc, bytes.substr(0, width), *inst,
                                   arch.CreateInitialContext())) {
          decoded = true;
          break;
        }
      }
      if (!decoded || !inst->IsValid() || inst->bytes.empty())
        fail("E_DECODE", pc, "Invalid or truncated x86 instruction");
      if (inst->function.starts_with("CPUID") ||
          inst->function.starts_with("RDTSC") ||
          inst->function.starts_with("RDMSR") ||
          inst->function.starts_with("WRMSR"))
        fail("E_EXTERNAL_UNMODELED", pc,
             "Instruction requires an explicit host/system model: " +
                 inst->function);
      // FXSAVE/FXRSTOR have no Remill semantics, but process execution models
      // the architectural save area directly in the per-instruction step.
      const bool fxsave = process_step &&
                          (inst->function.starts_with("FXSAVE") ||
                           inst->function.starts_with("FXRSTOR"));
      if (!fxsave && !module.getGlobalVariable("ISEL_" + inst->function, true))
        fail("E_UNSUPPORTED_INSTRUCTION", pc,
             "No Remill semantics for " + inst->function);
      auto next = graph.instructions.lower_bound(pc);
      if (next != graph.instructions.end() &&
          pc + inst->bytes.size() > next->first)
        fail("E_FUNCTION_AMBIGUOUS", pc, "Overlapping instruction decode");
      if (next != graph.instructions.begin()) {
        const auto &previous = *std::prev(next);
        if (previous.first + previous.second->bytes.size() > pc)
          fail("E_FUNCTION_AMBIGUOUS", pc, "Branch into an instruction body");
      }
      const auto repeated = repeat_base(inst->function);
      const bool string = string_operation(inst->function) ||
                          (!repeated.empty() && string_operation(repeated));
      if ((!process_step && inst->is_atomic_read_modify_write) ||
          (!repeated.empty() && !string) ||
          (string && (inst->segment_override ||
                      inst->bytes.find(char(0x67)) != std::string::npos)) ||
          (!process_step && inst->segment_override &&
           (inst->segment_override->name == "GS" ||
            (inst->segment_override->name == "FS" &&
             std::none_of(image.metadata.begin(), image.metadata.end(),
                          [](const auto &m) { return m.type == PT_TLS; })))))
        fail("E_UNSUPPORTED_INSTRUCTION", pc,
             "Atomic, address-size/segment string or TLS semantics require a "
             "separate runtime "
             "contract: " +
                 inst->function);
      if (process_step) {
        if (inst->category != Inst::kCategoryNormal &&
            inst->category != Inst::kCategoryNoOp &&
            inst->category != Inst::kCategoryConditionalBranch &&
            inst->category != Inst::kCategoryDirectJump &&
            inst->category != Inst::kCategoryIndirectJump &&
            inst->category != Inst::kCategoryDirectFunctionCall &&
            inst->category != Inst::kCategoryIndirectFunctionCall &&
            inst->category != Inst::kCategoryFunctionReturn &&
            inst->function != "UD2")
          fail("E_PROCESS_INSTRUCTION", pc,
               "Process boundary requires an explicit model: " +
                   inst->function);
        graph.instructions.emplace(pc, std::move(inst));
        continue;
      }
      switch (inst->category) {
      case Inst::kCategoryNormal:
      case Inst::kCategoryNoOp:
        if (inst->next_pc >= f->address + f->size)
          fail("E_UNRESOLVED_EDGE", pc, "Fallthrough leaves function bounds");
        add_target(pc, inst->next_pc, "fallthrough");
        break;
      case Inst::kCategoryConditionalBranch:
        add_target(pc, inst->branch_taken_pc, "taken");
        add_target(pc, inst->branch_not_taken_pc, "fallthrough");
        break;
      case Inst::kCategoryDirectJump:
        if (auto symbol = plt(inst->branch_taken_pc); !symbol.empty())
          external(pc, symbol);
        else
          add_target(pc, inst->branch_taken_pc, "jump");
        break;
      case Inst::kCategoryDirectFunctionCall:
        if (inst->next_pc >= f->address + f->size)
          fail("E_UNRESOLVED_EDGE", pc,
               "Call return site leaves function bounds");
        graph.return_sites.insert(inst->next_pc);
        add_target(pc, inst->next_pc, "return_site");
        if (auto symbol = plt(inst->branch_taken_pc); !symbol.empty())
          external(pc, symbol);
        else
          add_target(pc, inst->branch_taken_pc, "call");
        break;
      case Inst::kCategoryIndirectFunctionCall:
      case Inst::kCategoryIndirectJump: {
        std::string symbol;
        for (const auto &op : inst->operands)
          if (op.type == remill::Operand::kTypeAddress &&
              op.addr.IsMemoryAccess() &&
              (op.addr.base_reg.name == "RIP" ||
               op.addr.base_reg.name == "NEXT_PC" ||
               op.addr.base_reg.name == "PC") &&
              op.addr.index_reg.name.empty())
            symbol = import_at(inst->next_pc + op.addr.displacement);
        auto target = constant_target(pc, *inst);
        if (symbol.empty() &&
            inst->category == Inst::kCategoryIndirectFunctionCall) {
          bool descriptor_call = false;
          for (const auto &o : inst->operands)
            if (o.type == remill::Operand::kTypeAddress &&
                o.addr.IsMemoryAccess() && o.addr.base_reg.name == "RAX" &&
                o.addr.index_reg.name.empty() && !o.addr.displacement)
              descriptor_call = true;
          auto previous = graph.instructions.lower_bound(pc);
          if (descriptor_call && previous != graph.instructions.begin()) {
            --previous;
            const auto &definition = *previous->second;
            bool writes_rax = false;
            for (const auto &o : definition.operands)
              if (o.type == remill::Operand::kTypeRegister &&
                  o.action == remill::Operand::kActionWrite &&
                  o.reg.name == "RAX")
                writes_rax = true;
            if (writes_rax && definition.next_pc == pc &&
                definition.function.starts_with("LEA_"))
              for (const auto &o : definition.operands)
                if (o.type == remill::Operand::kTypeAddress &&
                    o.addr.index_reg.name.empty() &&
                    (o.addr.base_reg.name == "NEXT_PC" ||
                     o.addr.base_reg.name == "RIP" ||
                     o.addr.base_reg.name == "PC")) {
                  auto address = definition.next_pc + o.addr.displacement;
                  for (const auto &relocation : image.relocations)
                    if (relocation.active_dynamic &&
                        relocation.type == R_X86_64_TLSDESC &&
                        relocation.offset == address) {
                      symbol = "__zvril_tlsdesc";
                      graph.constant_predecessors[pc] = previous->first;
                    }
                }
          }
        }
        std::optional<IndirectTargets> table;
        if (symbol.empty() && !target)
          table = resolve_bounded_indirect(image, arch, graph.instructions,
                                           *inst, f->address);
        if (symbol.empty() && !target && !table)
          fail("E_UNRESOLVED_EDGE", pc,
               "Indirect call has no relocation-proven target");
        if (inst->category == Inst::kCategoryIndirectFunctionCall) {
          graph.return_sites.insert(inst->next_pc);
          add_target(pc, inst->next_pc, "return_site");
        }
        if (!symbol.empty())
          external(pc, symbol);
        else if (table) {
          for (auto to : table->targets)
            add_target(pc, to, "bounded_table");
          graph.indirect_targets[pc] = table->targets;
          graph.table_predecessors.insert(graph.table_predecessors.end(),
                                          table->predecessors.begin(),
                                          table->predecessors.end());
          table->evidence["pc"] = hx(pc);
          graph.indirect_evidence.push_back(std::move(table->evidence));
        } else {
          add_target(pc, *target, "single_predecessor_constant");
          graph.resolved_calls[pc] = *target;
        }
        break;
      }
      case Inst::kCategoryFunctionReturn:
        break;
      case Inst::kCategoryError:
        if (inst->function != "UD2")
          fail("E_UNSUPPORTED_INSTRUCTION", pc,
               "Unmodeled exception instruction");
        break;
      default:
        fail("E_UNRESOLVED_EDGE", pc,
             "Unsupported control transfer: " + inst->function);
      }
      graph.instructions.emplace(pc, std::move(inst));
    } catch (const Error &error) {
      if (!partial || error.exit_code != 1 || error.code == "E_RESOURCE_LIMIT")
        throw;
      graph.unresolved.emplace(pc, error.code + ": " + error.what());
      auto blocked = std::make_unique<Inst>();
      blocked->pc = pc;
      blocked->function = "ZVRIL_BLOCKED";
      graph.instructions.emplace(pc, std::move(blocked));
    }
  }
  auto proof_predecessors = graph.table_predecessors;
  for (const auto &pair : graph.constant_predecessors)
    proof_predecessors.push_back(pair);
  for (const auto &[pc, predecessor] : proof_predecessors) {
    unsigned incoming = 0;
    bool proved = true;
    for (const auto &edge : graph.edges)
      if (auto *e = edge.getAsObject();
          e && e->getString("to").value_or("") == hx(pc)) {
        incoming++;
        proved &= e->getString("from").value_or("") == hx(predecessor);
      }
    proved &= incoming == 1 && !graph.functions.contains(pc);
    if (!proved) {
      if (!partial)
        fail("E_UNRESOLVED_EDGE", pc,
             "Constant indirect target has an unproven predecessor");
      graph.unresolved[pc] = "E_UNRESOLVED_EDGE: Constant target does not "
                             "dominate indirect branch";
    }
  }
  return graph;
}

// Runtime v1: one caller-provided RW guest range, plus bounded instruction
// steps.
class Runtime {
  LLVMContext &c;
  Module &m;
  Type *i64;
  Type *ptr;

public:
  StructType *memory;
  explicit Runtime(Module &module)
      : c(module.getContext()), m(module), i64(Type::getInt64Ty(c)),
        ptr(PointerType::get(c, 0)) {
    memory =
        StructType::create(c, {ptr, i64, i64, i64, i64, i64, i64, i64, i64},
                           "struct.ZvrilMemory.v1");
  }
  Value *field(IRBuilder<> &b, Value *mem, unsigned index) {
    return b.CreateStructGEP(memory, mem, index);
  }
  Value *read(IRBuilder<> &b, Value *mem, unsigned index) {
    return b.CreateLoad(i64, field(b, mem, index));
  }
  void store(IRBuilder<> &b, Value *mem, unsigned index, Value *value) {
    b.CreateStore(value, field(b, mem, index));
  }
  Value *constant(std::uint64_t v) { return ConstantInt::get(i64, v); }

  void lower_memory(llvm::Function &f, bool write, std::uint64_t width) {
    f.setAttributes(AttributeList{});
    IRBuilder<> b(BasicBlock::Create(c, "entry", &f));
    auto *mem = f.getArg(0);
    auto *address = f.getArg(1);
    auto *type = write ? f.getArg(2)->getType() : f.getReturnType();
    auto *temp = b.CreateAlloca(type);
    b.CreateStore(write ? static_cast<Value *>(f.getArg(2))
                        : Constant::getNullValue(type),
                  temp);
    b.CreateCall(
        m.getFunction(write ? "zvril_runtime_write" : "zvril_runtime_read"),
        {mem, address, temp, constant(width)});
    if (write)
      b.CreateRet(mem);
    else
      b.CreateRet(b.CreateLoad(type, temp));
  }

  void lower_intrinsics() {
    for (auto &f : m) {
      if (!f.isDeclaration() || f.use_empty())
        continue;
      const auto name = f.getName();
      if (name.starts_with("__remill_compare_exchange_memory_")) {
        unsigned width = 0;
        if (name.drop_front(std::strlen("__remill_compare_exchange_memory_"))
                .getAsInteger(10, width) ||
            (width != 8 && width != 16 && width != 32 && width != 64 &&
             width != 128))
          continue;
        f.setAttributes(AttributeList{});
        IRBuilder<> b(BasicBlock::Create(c, "entry", &f));
        auto *type = IntegerType::get(c, width);
        auto *observed = b.CreateAlloca(type);
        b.CreateStore(ConstantInt::get(type, 0), observed);
        auto *expected = b.CreateAlignedLoad(type, f.getArg(2), Align(1));
        Value *desired = f.getArg(3);
        if (desired->getType()->isPointerTy())
          desired = b.CreateAlignedLoad(type, desired, Align(1));
        if (width == 128) {
          auto *aligned = BasicBlock::Create(c, "aligned", &f);
          auto *bad = BasicBlock::Create(c, "unaligned", &f);
          b.CreateCondBr(b.CreateICmpEQ(b.CreateAnd(f.getArg(1), constant(15)),
                                        constant(0)),
                         aligned, bad);
          b.SetInsertPoint(bad);
          b.CreateCall(m.getFunction("zvril_rt_fault"),
                       {f.getArg(0), constant(9), f.getArg(1), constant(16)});
          b.CreateRet(f.getArg(0));
          b.SetInsertPoint(aligned);
        }
        b.CreateCall(m.getFunction("zvril_runtime_read"),
                     {f.getArg(0), f.getArg(1), observed, constant(width / 8)});
        auto *value = b.CreateLoad(type, observed);
        // x86 performs the write cycle even on a failed comparison. A read-only
        // destination must fault in both cases, and the instruction transaction
        // rolls back registers and bytes on failure.
        b.CreateStore(
            b.CreateSelect(b.CreateICmpEQ(value, expected), desired, value),
            observed);
        b.CreateCall(m.getFunction("zvril_runtime_write"),
                     {f.getArg(0), f.getArg(1), observed, constant(width / 8)});
        b.CreateAlignedStore(value, f.getArg(2), Align(1));
        b.CreateRet(f.getArg(0));
      } else if (name == "__remill_read_memory_f80") {
        // Remill's f80 read takes a destination reference and returns Memory*.
        f.setAttributes(AttributeList{});
        IRBuilder<> b(BasicBlock::Create(c, "entry", &f));
        b.CreateCall(m.getFunction("zvril_runtime_read"),
                     {f.getArg(0), f.getArg(1), f.getArg(2), constant(10)});
        b.CreateRet(f.getArg(0));
      } else if (name == "__remill_read_memory_f128") {
        f.setAttributes(AttributeList{});
        IRBuilder<> b(BasicBlock::Create(c, "entry", &f));
        auto *slot = b.CreateAlloca(f.getReturnType());
        b.CreateMemSet(slot, b.getInt8(0),
                       m.getDataLayout().getTypeAllocSize(f.getReturnType()),
                       Align(1));
        b.CreateCall(m.getFunction("zvril_runtime_read"),
                     {f.getArg(0), f.getArg(1), slot, constant(16)});
        b.CreateRet(b.CreateLoad(f.getReturnType(), slot));
      } else if (name == "__remill_write_memory_f80") {
        f.setAttributes(AttributeList{});
        IRBuilder<> b(BasicBlock::Create(c, "entry", &f));
        b.CreateCall(m.getFunction("zvril_runtime_write"),
                     {f.getArg(0), f.getArg(1), f.getArg(2), constant(10)});
        b.CreateRet(f.getArg(0));
      } else if (name == "__remill_write_memory_f128") {
        f.setAttributes(AttributeList{});
        IRBuilder<> b(BasicBlock::Create(c, "entry", &f));
        Value *source = f.getArg(2);
        if (!source->getType()->isPointerTy()) {
          auto *slot = b.CreateAlloca(source->getType());
          b.CreateStore(source, slot);
          source = slot;
        }
        b.CreateCall(m.getFunction("zvril_runtime_write"),
                     {f.getArg(0), f.getArg(1), source, constant(16)});
        b.CreateRet(f.getArg(0));
      } else if (name.starts_with("__remill_read_memory_") ||
                 name.starts_with("__remill_write_memory_")) {
        const bool write = name.starts_with("__remill_write_memory_");
        auto *type = write ? f.getArg(2)->getType() : f.getReturnType();
        if (!type->isIntegerTy() && !type->isFloatingPointTy())
          continue;
        const auto bits = type->getPrimitiveSizeInBits().getFixedValue();
        if (bits != 8 && bits != 16 && bits != 32 && bits != 64 && bits != 128)
          continue;
        lower_memory(f, write, bits / 8);
      } else if (name.starts_with("__remill_flag_computation_") ||
                 name.starts_with("__remill_compare_")) {
        if (f.arg_empty() || f.getReturnType() != f.getArg(0)->getType())
          continue;
        f.setAttributes(AttributeList{});
        IRBuilder<> b(BasicBlock::Create(c, "entry", &f));
        b.CreateRet(f.getArg(0));
      } else if (name.starts_with("__remill_undefined_")) {
        f.setAttributes(AttributeList{});
        IRBuilder<> b(BasicBlock::Create(c, "entry", &f));
        b.CreateRet(Constant::getNullValue(f.getReturnType()));
      } else if (name.starts_with("__remill_barrier_") ||
                 name == "__remill_atomic_begin" ||
                 name == "__remill_atomic_end") {
        f.setAttributes(AttributeList{});
        IRBuilder<> b(BasicBlock::Create(c, "entry", &f));
        b.CreateRet(f.getArg(0));
      } else if (name == "__remill_error") {
        f.setAttributes(AttributeList{});
        IRBuilder<> b(BasicBlock::Create(c, "entry", &f));
        b.CreateCall(m.getFunction("zvril_rt_fault"),
                     {f.getArg(2), constant(5), f.getArg(1), constant(0)});
        b.CreateRet(f.getArg(2));
      } else if (name == "__remill_fpu_get_rounding") {
        // Guest MXCSR is modeled with the baseline round-to-nearest-even mode.
        // The Remill ABI exposes rounding as host fenv state, which does not
        // describe guest state, so pin the architectural baseline.
        f.setAttributes(AttributeList{});
        IRBuilder<> b(BasicBlock::Create(c, "entry", &f));
        b.CreateRet(ConstantInt::get(f.getReturnType(), 0));
      } else if (name == "__remill_fpu_set_rounding" ||
                 name == "__remill_fpu_exception_clear" ||
                 name == "__remill_fpu_exception_raise") {
        f.setAttributes(AttributeList{});
        IRBuilder<> b(BasicBlock::Create(c, "entry", &f));
        b.CreateRetVoid();
      } else if (name == "__remill_fpu_exception_test") {
        f.setAttributes(AttributeList{});
        IRBuilder<> b(BasicBlock::Create(c, "entry", &f));
        b.CreateRet(ConstantInt::get(f.getReturnType(), 0));
      }
    }
  }
};

std::uint64_t required_flags(llvm::StringRef name) {
  auto stem = name.take_until([](char c) { return c == '_'; });
  if (stem == "LAHF")
    return 0xd5;
  if (stem == "SALC")
    return 1;
  if (std::set<StringRef>{"MOVSB", "MOVSW", "MOVSD", "MOVSQ", "STOSB",
                          "STOSW", "STOSD", "STOSQ", "LODSB", "LODSW",
                          "LODSD", "LODSQ", "CMPSB", "CMPSW", "CMPSD",
                          "CMPSQ", "SCASB", "SCASW", "SCASD", "SCASQ"}
          .contains(stem) &&
      !name.contains("XMM"))
    return 0x400;
  if (stem == "ADOX")
    return 0x800;
  if (stem.starts_with("ADC") || stem.starts_with("SBB") || stem == "CMC" ||
      stem.starts_with("RCL") || stem.starts_with("RCR"))
    return 1;
  if (stem.starts_with("PUSHF"))
    return 0xcd5;
  if (stem.starts_with("CMOV"))
    stem = stem.drop_front(4);
  else if (stem.starts_with("SET"))
    stem = stem.drop_front(3);
  else if (stem.starts_with("J"))
    stem = stem.drop_front();
  else if (stem == "LOOPE" || stem == "LOOPNE")
    return 0x40;
  else
    return 0;
  if (stem == "Z" || stem == "NZ" || stem == "E" || stem == "NE")
    return 0x40;
  if (stem == "B" || stem == "NB" || stem == "C" || stem == "NC" ||
      stem == "AE")
    return 1;
  if (stem == "BE" || stem == "NBE" || stem == "A")
    return 0x41;
  if (stem == "L" || stem == "NL" || stem == "GE")
    return 0x880;
  if (stem == "LE" || stem == "NLE" || stem == "G")
    return 0x8c0;
  if (stem == "S" || stem == "NS")
    return 0x80;
  if (stem == "O" || stem == "NO")
    return 0x800;
  if (stem == "P" || stem == "NP" || stem == "PE" || stem == "PO")
    return 4;
  return 0;
}
llvm::Value *output_flags(Inst &inst, llvm::IRBuilder<> &b, llvm::Value *old,
                          llvm::Value *state, Runtime &rt) {
  llvm::StringRef n = inst.function;
  const auto keep = [&](std::uint64_t mask) {
    return b.CreateAnd(old, rt.constant(mask));
  };
  const auto defined = [&](std::uint64_t mask) {
    return b.CreateOr(keep(0x400), rt.constant(mask));
  };
  if (n.starts_with("ADCX"))
    return b.CreateOr(old, rt.constant(1));
  if (n.starts_with("ADOX"))
    return b.CreateOr(old, rt.constant(0x800));
  if (n.starts_with("ANDN"))
    return defined(0x8c1);
  if (n.starts_with("CMPXCHG8B") || n.starts_with("CMPXCHG16B"))
    return b.CreateOr(old, rt.constant(0x40));
  if (n.starts_with("BT_") || n.starts_with("BTS_") || n.starts_with("BTR_") ||
      n.starts_with("BTC_"))
    return b.CreateOr(keep(0x440), rt.constant(1));
  if (n.starts_with("FUCOMI") || n.starts_with("FCOMI"))
    return defined(0x8d5);
  if (n.contains("XMM") || n.contains("YMM") || n.contains("ZMM")) {
    if (n.starts_with("COMI") || n.starts_with("UCOMI") ||
        n.starts_with("VCOMI") || n.starts_with("VUCOMI") ||
        n.starts_with("PTEST") || n.starts_with("VTEST"))
      return defined(0x8d5);
    return old;
  }
  if (n.starts_with("ADD") || n.starts_with("ADC") || n.starts_with("SUB") ||
      n.starts_with("SBB") || n.starts_with("CMP") || n.starts_with("XADD") ||
      n.starts_with("NEG") || n.starts_with("SCAS"))
    return defined(0x8d5);
  if (n.starts_with("AND") || n.starts_with("OR_") || n.starts_with("XOR") ||
      n.starts_with("TEST"))
    return defined(0x8c5);
  if (n.starts_with("INC") || n.starts_with("DEC"))
    return b.CreateOr(keep(0x401), rt.constant(0x8d4));
  if (n.starts_with("IMUL") || n.starts_with("MUL_") || n.starts_with("MUL_G"))
    return defined(0x801);
  if (n.starts_with("IDIV") || n.starts_with("DIV"))
    return keep(0x400);
  if (n.starts_with("SHLX") || n.starts_with("SHRX") || n.starts_with("SARX") ||
      n.starts_with("RORX") || n.starts_with("MULX"))
    return old;
  if (n.starts_with("SHL") || n.starts_with("SAL") || n.starts_with("SHR") ||
      n.starts_with("SAR") || n.starts_with("ROL") || n.starts_with("ROR")) {
    llvm::Value *count = rt.constant(1);
    for (const auto &op : inst.operands) {
      if (op.type == remill::Operand::kTypeImmediate)
        count = rt.constant(op.imm.val);
      if (op.type == remill::Operand::kTypeRegister && op.reg.name == "CL")
        count = b.CreateZExtOrTrunc(
            inst.GetLifter()->LoadRegValue(b.GetInsertBlock(), state, "CL"),
            b.getInt64Ty());
    }
    const unsigned width = n.ends_with("_64")   ? 64
                           : n.ends_with("_32") ? 32
                           : n.ends_with("_16") ? 16
                                                : 8;
    count = b.CreateAnd(count, rt.constant(width == 64 ? 63 : 31));
    llvm::Value *changed = nullptr;
    if (n.starts_with("ROL") || n.starts_with("ROR"))
      changed = b.CreateOr(keep(0x4d4),
                           b.CreateSelect(b.CreateICmpEQ(count, rt.constant(1)),
                                          rt.constant(0x801), rt.constant(1)));
    else
      changed = b.CreateOr(
          keep(0x400),
          b.CreateOr(
              rt.constant(0xc4),
              b.CreateOr(
                  b.CreateSelect(b.CreateICmpULT(count, rt.constant(width)),
                                 rt.constant(1), rt.constant(0)),
                  b.CreateSelect(b.CreateICmpEQ(count, rt.constant(1)),
                                 rt.constant(0x800), rt.constant(0)))));
    return b.CreateSelect(b.CreateICmpEQ(count, rt.constant(0)), old, changed);
  }
  if (n.starts_with("BSF") || n.starts_with("BSR"))
    return defined(0x40);
  if (n.starts_with("CLC") || n.starts_with("STC"))
    return b.CreateOr(old, rt.constant(1));
  if (n.starts_with("CLD") || n.starts_with("STD"))
    return b.CreateOr(old, rt.constant(0x400));
  if (n.starts_with("POPF"))
    return rt.constant(0xcd5);
  if (inst.category != Inst::kCategoryNormal || n.starts_with("MOV") ||
      n.starts_with("LEA") || n.starts_with("PUSH") || n.starts_with("POP") ||
      n.starts_with("CMOV") || n.starts_with("SET") || n.starts_with("BSWAP") ||
      n.starts_with("XCHG") || n.starts_with("NOT") || n.starts_with("LEAVE") ||
      n.starts_with("CBW") || n.starts_with("CWDE") || n.starts_with("CDQE") ||
      n.starts_with("CWD") || n.starts_with("CDQ") || n.starts_with("CQO") ||
      n.starts_with("V") || n.starts_with("P") || n.starts_with("STOS") ||
      n.starts_with("LODS") || n.starts_with("F"))
    return old;
  return keep(0x400); // Conservatively exclude unknown arithmetic flag effects.
}

const char *const registers[] = {
    "RAX", "RCX", "RDX", "RBX", "RSP", "RBP", "RSI",    "RDI",   "R8",
    "R9",  "R10", "R11", "R12", "R13", "R14", "R15",    "RIP",   "AF",
    "CF",  "DF",  "OF",  "PF",  "SF",  "ZF",  "FSBASE", "GSBASE"};

void state_api(Module &m, const remill::Arch &arch,
               std::set<std::string> &exports) {
  auto &c = m.getContext();
  auto *i64 = Type::getInt64Ty(c);
  auto *i32 = Type::getInt32Ty(c);
  auto *ptr = PointerType::get(c, 0);
  auto *size = llvm::Function::Create(FunctionType::get(i64, false),
                                      GlobalValue::ExternalLinkage,
                                      "zvril_state_size", m);
  IRBuilder<> sb(BasicBlock::Create(c, "entry", size));
  sb.CreateRet(ConstantInt::get(
      i64, m.getDataLayout().getTypeAllocSize(arch.StateStructType())));
  exports.insert("zvril_state_size");
  for (const bool write : {false, true}) {
    auto *f = llvm::Function::Create(
        FunctionType::get(write ? Type::getVoidTy(c) : i64,
                          write ? std::vector<Type *>{ptr, i32, i64}
                                : std::vector<Type *>{ptr, i32},
                          false),
        GlobalValue::ExternalLinkage,
        write ? "zvril_state_set" : "zvril_state_get", m);
    exports.insert(f->getName().str());
    auto *entry = BasicBlock::Create(c, "entry", f);
    auto *fallback = BasicBlock::Create(c, "invalid_register", f);
    IRBuilder<> b(entry);
    auto *dispatch =
        b.CreateSwitch(f->getArg(1), fallback, std::size(registers));
    for (unsigned index = 0; index < std::size(registers); ++index) {
      const auto *reg = arch.RegisterByName(registers[index]);
      if (!reg)
        throw Error("E_INTERNAL", "Missing Remill register accessor", 2);
      auto *block = BasicBlock::Create(c, registers[index], f);
      dispatch->addCase(ConstantInt::get(i32, index), block);
      b.SetInsertPoint(block);
      auto *address = reg->AddressOf(f->getArg(0), b);
      auto *type = IntegerType::get(c, reg->size * 8);
      if (write) {
        b.CreateAlignedStore(b.CreateZExtOrTrunc(f->getArg(2), type), address,
                             Align(1));
        b.CreateRetVoid();
      } else
        b.CreateRet(b.CreateZExtOrTrunc(
            b.CreateAlignedLoad(type, address, Align(1)), i64));
    }
    b.SetInsertPoint(fallback);
    if (write)
      b.CreateRetVoid();
    else
      b.CreateRet(ConstantInt::get(i64, 0));
  }
}

void dce(Module &module) {
  PassBuilder pb;
  LoopAnalysisManager lam;
  FunctionAnalysisManager fam;
  CGSCCAnalysisManager cam;
  ModuleAnalysisManager mam;
  pb.registerModuleAnalyses(mam);
  pb.registerCGSCCAnalyses(cam);
  pb.registerFunctionAnalyses(fam);
  pb.registerLoopAnalyses(lam);
  pb.crossRegisterProxies(lam, fam, cam, mam);
  ModulePassManager passes;
  passes.addPass(GlobalDCEPass());
  passes.run(module, mam);
}
void guard_division(Module &module) {
  std::vector<Instruction *> divisions;
  for (auto &f : module)
    for (auto &block : f)
      for (auto &instruction : block)
        if (instruction.getOpcode() == Instruction::SDiv ||
            instruction.getOpcode() == Instruction::SRem)
          divisions.push_back(&instruction);
  for (auto *instruction : divisions) {
    // Pointer differences in the C runtime divide by positive structure sizes.
    // Signed overflow is possible only when the divisor can be minus one.
    if (auto *divisor = dyn_cast<ConstantInt>(instruction->getOperand(1));
        divisor && !divisor->isMinusOne())
      continue;
    auto *f = instruction->getFunction();
    if (f->arg_size() < 2 || !f->getReturnType()->isPointerTy() ||
        !f->getArg(0)->getType()->isPointerTy() ||
        !f->getArg(1)->getType()->isPointerTy())
      throw Error("E_UNSUPPORTED_INSTRUCTION",
                  "Cannot guard a division outside Remill's memory/state ABI",
                  1);
    IRBuilder<> b(instruction);
    auto bits = instruction->getType()->getIntegerBitWidth();
    auto &c = module.getContext();
    auto *bad = b.CreateAnd(
        b.CreateICmpEQ(instruction->getOperand(0),
                       ConstantInt::get(c, APInt::getSignedMinValue(bits))),
        b.CreateICmpEQ(instruction->getOperand(1),
                       ConstantInt::get(c, APInt::getAllOnes(bits))));
    auto *end = SplitBlockAndInsertIfThen(bad, instruction, false);
    IRBuilder<> failure(end);
    auto *memory =
        failure.CreateCall(module.getFunction("__remill_error"),
                           {f->getArg(1), failure.getInt64(0), f->getArg(0)});
    failure.CreateRet(memory);
    end->eraseFromParent();
  }
}

std::string sha_file(const std::filesystem::path &path) {
  const auto data = MemoryBuffer::getFile(path.string());
  if (!data)
    throw Error("E_BACKEND_UNAVAILABLE", "Cannot read semantics file", 1);
  const auto bytes = (*data)->getBuffer();
  const auto digest = SHA256::hash(
      {reinterpret_cast<const std::uint8_t *>(bytes.data()), bytes.size()});
  std::ostringstream s;
  for (auto v : digest)
    s << std::hex << std::setw(2) << std::setfill('0') << unsigned(v);
  return s.str();
}

llvm::Value *extend_narrow(IRBuilder<> &b, llvm::Value *value,
                           const AbiType &type) {
  if (!type.narrow_integer())
    return value;
  auto *bits = b.CreateZExtOrTrunc(
      value, IntegerType::get(b.getContext(), type.size * 8));
  return b.CreateZExt(type.signed_integer()
                          ? b.CreateSExt(bits, b.getInt32Ty())
                          : b.CreateZExt(bits, b.getInt32Ty()),
                      b.getInt64Ty());
}

Object packet_wrapper(Module &m, const remill::Arch &arch,
                      const AbiSignature &signature, std::uint64_t entry,
                      std::set<std::string> &exports) {
  auto &c = m.getContext();
  auto *ptr = PointerType::get(c, 0);
  auto *i64 = Type::getInt64Ty(c);
  auto *i8 = Type::getInt8Ty(c);
  auto *f = llvm::Function::Create(
      FunctionType::get(Type::getInt32Ty(c), {ptr, ptr, ptr}, false),
      GlobalValue::ExternalLinkage, "zvril_invoke_packet", m);
  exports.insert("zvril_invoke_packet");
  IRBuilder<> b(BasicBlock::Create(c, "entry", f));
  auto *rt = f->getArg(0);
  auto *failed = BasicBlock::Create(c, "failed", f);
  const auto require = [&](llvm::Value *condition) {
    auto *next = BasicBlock::Create(c, "checked", f);
    b.CreateCondBr(condition, next, failed);
    b.SetInsertPoint(next);
  };
  auto *stack = b.CreateCall(m.getFunction("zvril_runtime_stack"), {rt});
  require(b.CreateICmpNE(stack, b.getInt64(0)));
  auto *state = b.CreateAlloca(arch.StateStructType());
  b.CreateMemSet(state, b.getInt8(0),
                 m.getDataLayout().getTypeAllocSize(arch.StateStructType()),
                 MaybeAlign(16));
  const auto reg = [&](const std::string &name) {
    return arch.RegisterByName(name)->AddressOf(state, b);
  };
  auto *sp = b.CreateAdd(
      stack,
      b.getInt64(((65536 - 16 - signature.stack_bytes) & ~UINT64_C(15)) + 8));
  constexpr std::uint64_t sentinel = UINT64_C(0xfffffffffffffff0);
  auto *scratch = b.CreateAlloca(i64);
  b.CreateStore(b.getInt64(sentinel), scratch);
  require(b.CreateICmpNE(b.CreateCall(m.getFunction("zvril_runtime_write"),
                                      {rt, sp, scratch, b.getInt64(8)}),
                         b.getInt32(0)));
  b.CreateStore(sp, reg("RSP"));
  b.CreateCall(m.getFunction("zvril_runtime_set_return"),
               {rt, b.getInt64(sentinel)});
  llvm::Value *result_address = nullptr;
  if (signature.result.memory()) {
    result_address =
        b.CreateCall(m.getFunction("zvril_runtime_return_area"), {rt});
    require(b.CreateICmpNE(result_address, b.getInt64(0)));
    b.CreateStore(result_address, reg("RDI"));
  }
  const char *gprs[] = {"RDI", "RSI", "RDX", "RCX", "R8", "R9"};
  for (unsigned i = 0; i < signature.arguments.size(); i++) {
    const auto &type = signature.arguments[i];
    const auto &location = signature.locations[i];
    auto *slot = b.CreateConstGEP1_64(i64, f->getArg(1), i);
    llvm::Value *data =
        type.aggregate ? b.CreateIntToPtr(b.CreateLoad(i64, slot), ptr) : slot;
    if (location.stack) {
      if (type.narrow_integer()) {
        auto *extended = b.CreateAlloca(i64);
        b.CreateStore(extend_narrow(b, b.CreateLoad(i64, slot), type),
                      extended);
        data = extended;
      }
      require(b.CreateICmpNE(
          b.CreateCall(m.getFunction("zvril_runtime_write"),
                       {rt, b.CreateAdd(sp, b.getInt64(8 + location.offset)),
                        data,
                        b.getInt64(type.narrow_integer() ? 8 : type.size)}),
          b.getInt32(0)));
    } else
      for (unsigned j = 0; j < type.classes.size(); j++) {
        if (type.classes[j] == AbiClass::None)
          continue;
        auto *chunk = b.CreateAlloca(i64);
        b.CreateStore(b.getInt64(0), chunk);
        b.CreateMemCpy(chunk, MaybeAlign(1),
                       b.CreateConstGEP1_64(i8, data, j * 8), MaybeAlign(1),
                       std::min<std::uint64_t>(8, type.size - j * 8));
        if (type.classes[j] == AbiClass::Integer)
          b.CreateStore(extend_narrow(b, b.CreateLoad(i64, chunk), type),
                        reg(gprs[location.registers[j]]));
        else
          b.CreateStore(b.CreateLoad(i64, chunk),
                        reg("XMM" + std::to_string(location.registers[j])));
      }
  }
  if (signature.variadic)
    b.CreateStore(b.getInt64(signature.sse_used), reg("RAX"));
  b.CreateCall(m.getFunction("zvril_runtime_set_flags_valid"),
               {rt, b.getInt64(0x400)});
  auto *pc =
      b.CreateAdd(b.getInt64(entry),
                  b.CreateCall(m.getFunction("zvril_runtime_bias"), {rt}));
  b.CreateCall(m.getFunction("zvril_lifted_v2"), {state, pc, rt});
  require(
      b.CreateICmpNE(b.CreateCall(m.getFunction("zvril_runtime_success"), {rt}),
                     b.getInt32(0)));
  if (signature.result.memory()) {
    require(b.CreateICmpNE(b.CreateCall(m.getFunction("zvril_runtime_read"),
                                        {rt, result_address, f->getArg(2),
                                         b.getInt64(signature.result.size)}),
                           b.getInt32(0)));
  } else {
    unsigned gp = 0, fp = 0;
    for (unsigned j = 0; j < signature.result.classes.size(); j++) {
      if (signature.result.classes[j] == AbiClass::None)
        continue;
      auto *source = signature.result.classes[j] == AbiClass::Integer
                         ? reg(gp++ ? "RDX" : "RAX")
                         : reg("XMM" + std::to_string(fp++));
      b.CreateMemCpy(b.CreateConstGEP1_64(i8, f->getArg(2), j * 8),
                     MaybeAlign(1), source, MaybeAlign(1),
                     std::min<std::uint64_t>(8, signature.result.size - j * 8));
    }
  }
  for (unsigned i = 0; i < signature.result.defined.size(); i++)
    if (!signature.result.defined[i])
      b.CreateStore(b.getInt8(0), b.CreateConstGEP1_64(i8, f->getArg(2), i));
  b.CreateRet(b.getInt32(1));
  b.SetInsertPoint(failed);
  b.CreateRet(b.getInt32(0));
  return Object{{"enabled", true},
                {"symbol", "zvril_invoke_packet"},
                {"pointer_contract",
                 "ZvrilRuntime*, host uint64 slot array, host result "
                 "packet; aggregate slots are host packet pointers "
                 "and embedded pointer fields are guest addresses"}};
}

Object typed_wrapper(Module &m, const remill::Arch &arch,
                     const std::filesystem::path &path, std::uint64_t entry,
                     std::set<std::string> &exports) {
  if (path.empty())
    return Object{{"enabled", false}};
  auto bytes = MemoryBuffer::getFile(path.string());
  if (!bytes || (*bytes)->getBufferSize() > 1024 * 1024)
    throw Error("E_ABI_UNKNOWN", "Cannot read ABI contract (limit 1 MiB)", 1);
  auto parsed = llvm::json::parse((*bytes)->getBuffer());
  if (!parsed)
    throw Error("E_ABI_UNKNOWN", toString(parsed.takeError()), 1);
  auto *object = parsed->getAsObject();
  if (!object)
    throw Error("E_ABI_UNKNOWN", "ABI contract must be an object", 1);
  if (auto *nested = object->getObject("signature"))
    object = nested;
  const auto signature = parse_abi(*object);
  if (signature.aggregate) {
    auto report = packet_wrapper(m, arch, signature, entry, exports);
    report["signature"] = Object(*object);
    report["sha256"] = sha_file(path);
    return report;
  }
  auto result = object->getString("return");
  auto *args = object->getArray("arguments");
  if (!result || !args || args->size() > 32)
    throw Error("E_ABI_UNKNOWN",
                "Expected a fixed scalar signature of at most 32 arguments", 1);
  const bool variadic = object->getBoolean("variadic").value_or(false);
  if (object->get("variadic") && !object->getBoolean("variadic"))
    throw Error("E_ABI_UNKNOWN", "variadic must be boolean", 1);
  if (variadic) {
    auto fixed = object->getInteger("fixed_arguments");
    if (!fixed || *fixed < 0 || std::uint64_t(*fixed) > args->size())
      throw Error("E_ABI_UNKNOWN",
                  "Invalid fixed_arguments for variadic contract", 1);
    for (unsigned i = *fixed; i < args->size(); i++)
      if ((*args)[i].getAsString().value_or("") == "f32")
        throw Error("E_ABI_UNKNOWN", "Promote variadic f32 to f64", 1);
  } else if (object->get("fixed_arguments"))
    throw Error("E_ABI_UNKNOWN", "fixed_arguments requires variadic=true", 1);
  auto &c = m.getContext();
  auto *i64 = Type::getInt64Ty(c);
  auto *ptr = PointerType::get(c, 0);
  const auto type = [&](StringRef name, bool returned) -> Type * {
    if (name == "u64" || name == "i64" || name == "ptr")
      return i64;
    if (name == "u32" || name == "i32")
      return Type::getInt32Ty(c);
    if (name == "u16" || name == "i16")
      return Type::getInt16Ty(c);
    if (name == "u8" || name == "i8")
      return Type::getInt8Ty(c);
    if (name == "f64")
      return Type::getDoubleTy(c);
    if (name == "f32")
      return Type::getFloatTy(c);
    if (name == "void" && returned)
      return Type::getVoidTy(c);
    throw Error("E_ABI_UNKNOWN", "Unsupported ABI type " + name.str(), 1);
  };
  auto *returned = type(*result, true);
  std::vector<Type *> parameters{ptr};
  for (const auto &a : *args) {
    auto name = a.getAsString();
    if (!name)
      throw Error("E_ABI_UNKNOWN", "Argument type must be a string", 1);
    parameters.push_back(type(*name, false));
  }
  auto *f =
      llvm::Function::Create(FunctionType::get(returned, parameters, false),
                             GlobalValue::ExternalLinkage, "zvril_typed", m);
  exports.insert("zvril_typed");
  for (unsigned i = 0; i < signature.arguments.size(); i++)
    if (signature.arguments[i].narrow_integer())
      f->addParamAttr(i + 1, signature.arguments[i].signed_integer()
                                 ? Attribute::SExt
                                 : Attribute::ZExt);
  if (signature.result.narrow_integer())
    f->addRetAttr(signature.result.signed_integer() ? Attribute::SExt
                                                    : Attribute::ZExt);
  IRBuilder<> b(BasicBlock::Create(c, "entry", f));
  auto *state = b.CreateAlloca(arch.StateStructType());
  const auto state_size =
      m.getDataLayout().getTypeAllocSize(arch.StateStructType());
  b.CreateMemSet(state, b.getInt8(0), state_size, MaybeAlign(16));
  auto *rt = f->getArg(0);
  auto *stack = b.CreateCall(m.getFunction("zvril_runtime_stack"), {rt});
  auto *execute = BasicBlock::Create(c, "execute", f);
  auto *failed = BasicBlock::Create(c, "failed", f);
  b.CreateCondBr(b.CreateICmpNE(stack, ConstantInt::get(i64, 0)), execute,
                 failed);
  b.SetInsertPoint(failed);
  if (returned->isVoidTy())
    b.CreateRetVoid();
  else
    b.CreateRet(Constant::getNullValue(returned));
  b.SetInsertPoint(execute);
  unsigned gpr = 0, sse = 0;
  std::vector<llvm::Value *> spilled;
  const char *regs[] = {"RDI", "RSI", "RDX", "RCX", "R8", "R9"};
  for (unsigned i = 0; i < args->size(); i++) {
    llvm::Value *value = f->getArg(i + 1);
    auto *t = value->getType();
    value = extend_narrow(b, value, signature.arguments[i]);
    if (t->isFloatingPointTy() && sse < 8) {
      auto *reg = arch.RegisterByName("XMM" + std::to_string(sse++));
      b.CreateStore(value, reg->AddressOf(state, b));
    } else if (t->isIntegerTy() && gpr < 6)
      b.CreateStore(b.CreateZExtOrTrunc(value, i64),
                    arch.RegisterByName(regs[gpr++])->AddressOf(state, b));
    else {
      if (t->isFloatingPointTy())
        value = b.CreateBitCast(
            value, Type::getIntNTy(c, t->getPrimitiveSizeInBits()));
      spilled.push_back(b.CreateZExtOrTrunc(value, i64));
    }
  }
  const auto offset = ((65536 - 16 - spilled.size() * 8) & ~UINT64_C(15)) + 8;
  auto *sp = b.CreateAdd(stack, ConstantInt::get(i64, offset));
  auto *slot = b.CreateAlloca(i64);
  const std::uint64_t sentinel = UINT64_C(0xfffffffffffffff0);
  b.CreateCall(m.getFunction("zvril_runtime_set_return"),
               {rt, ConstantInt::get(i64, sentinel)});
  for (unsigned i = 0; i <= spilled.size(); i++) {
    b.CreateStore(i ? spilled[i - 1] : ConstantInt::get(i64, sentinel), slot);
    b.CreateCall(m.getFunction("zvril_runtime_write"),
                 {rt, b.CreateAdd(sp, ConstantInt::get(i64, i * 8)), slot,
                  ConstantInt::get(i64, 8)});
  }
  b.CreateStore(sp, arch.RegisterByName("RSP")->AddressOf(state, b));
  if (variadic)
    b.CreateStore(ConstantInt::get(i64, sse),
                  arch.RegisterByName("RAX")->AddressOf(state, b));
  b.CreateCall(m.getFunction("zvril_runtime_set_flags_valid"),
               {rt, ConstantInt::get(i64, 0x400)});
  auto *pc =
      b.CreateAdd(ConstantInt::get(i64, entry),
                  b.CreateCall(m.getFunction("zvril_runtime_bias"), {rt}));
  b.CreateCall(m.getFunction("zvril_lifted_v2"), {state, pc, rt});
  if (returned->isVoidTy())
    b.CreateRetVoid();
  else if (returned->isFloatingPointTy())
    b.CreateRet(b.CreateLoad(returned,
                             arch.RegisterByName("XMM0")->AddressOf(state, b)));
  else
    b.CreateRet(b.CreateZExtOrTrunc(
        b.CreateLoad(i64, arch.RegisterByName("RAX")->AddressOf(state, b)),
        returned));
  return Object{{"enabled", true},
                {"symbol", "zvril_typed"},
                {"signature", Object(*object)},
                {"sha256", sha_file(path)},
                {"pointer_contract",
                 "ptr is a uint64 guest address; leading argument is "
                 "ZvrilRuntime*. Initialize the image before calling "
                 "and check runtime fault after every call."}};
}

void json_file(const std::filesystem::path &path, Object object) {
  std::error_code ec;
  raw_fd_ostream file(path.string(), ec);
  if (ec)
    throw Error("E_OUTPUT", "Cannot open artifact " + path.string(), 2);
  file << formatv("{0:2}\n", llvm::json::Value(std::move(object)));
  file.flush();
  if (file.has_error())
    throw Error("E_OUTPUT", "Cannot write artifact", 2);
}
#endif
} // namespace

bool remill_available() {
#ifdef ZVRIL_HAS_REMILL
  return true;
#else
  return false;
#endif
}

std::filesystem::path default_semantics_path(std::string_view architecture) {
#ifdef ZVRIL_HAS_REMILL
  // Installed binaries find their bundled semantics relative to the executable.
  llvm::SmallString<256> executable(llvm::sys::fs::getMainExecutable(
      nullptr, reinterpret_cast<void *>(&remill_available)));
  const auto installed = std::filesystem::path(executable.str().str())
                             .parent_path()
                             .parent_path() /
                         "share/zvril/semantics" /
                         (std::string(architecture) + ".bc");
  if (std::filesystem::is_regular_file(installed))
    return installed;
  return std::filesystem::path(ZVRIL_SEMANTICS_FILE).parent_path() /
         (std::string(architecture) + ".bc");
#else
  (void)architecture;
  return {};
#endif
}

static Object lift_impl(const Image &image, const LiftOptions &options
#ifdef ZVRIL_HAS_REMILL
                        ,
                        bool process_step = false,
                        LLVMContext *shared_context = nullptr,
                        Module *prepared = nullptr,
                        std::unique_ptr<Module> *compiled = nullptr
#endif
) {
#ifndef ZVRIL_HAS_REMILL
  (void)image;
  (void)options;
  throw Error("E_BACKEND_UNAVAILABLE", "This build has no Remill backend", 1);
#else
  const auto root = select(image, options);
  LLVMContext local_context;
  LLVMContext &context = shared_context ? *shared_context : local_context;
  SMDiagnostic error;
  const auto path = options.semantics.empty()
                        ? default_semantics_path(options.architecture)
                        : options.semantics;
  const auto semantics_sha = sha_file(path);
  auto module = prepared ? CloneModule(*prepared)
                         : parseIRFile(path.string(), error, context);
  if (!module)
    throw Error("E_BACKEND_UNAVAILABLE",
                "Cannot parse semantics bitcode: " + error.getMessage().str(),
                1);
  auto arch = remill::Arch::Get(context, "linux", options.architecture);
  if (!arch)
    throw Error("E_BACKEND_UNAVAILABLE",
                "Cannot create Remill amd64 architecture", 1);
  arch->PrepareModule(module);
  arch->InitFromSemanticsModule(module.get());
  const auto runtime_path = path.parent_path() / "runtime.bc";
  if (!prepared) {
    auto runtime_module = parseIRFile(runtime_path.string(), error, context);
    if (!runtime_module)
      throw Error("E_BACKEND_UNAVAILABLE",
                  "Cannot load runtime.bc: " + error.getMessage().str(), 1);
    runtime_module->setDataLayout(module->getDataLayout());
    runtime_module->setTargetTriple(module->getTargetTriple());
    if (Linker::linkModules(*module, std::move(runtime_module)))
      throw Error("E_LLVM_VERIFY", "Runtime module link failed", 2);
  }
  auto graph = recover(image, root, *arch, *module, options, process_step);
  Runtime runtime(*module);
  auto *function = arch->DefineLiftedFunction("zvril_lifted_v2", module.get());
  function->setCallingConv(CallingConv::C);
  function->setAttributes(AttributeList{});
  auto *state = function->getArg(remill::kStatePointerArgNum);
  auto *mem = function->getArg(remill::kMemoryPointerArgNum);
  auto *entry = &function->getEntryBlock();
  auto *done = BasicBlock::Create(context, "exit", function);
  auto *bad_return = BasicBlock::Create(context, "bad_return", function);
  std::map<std::uint64_t, BasicBlock *> blocks;
  for (const auto &[pc, _] : graph.instructions)
    blocks[pc] = BasicBlock::Create(context, "pc_" + hx(pc), function);
  IRBuilder<> b(entry);
  auto *trace_type = ArrayType::get(Type::getInt64Ty(context), 17);
  auto *trace_gpr = b.CreateAlloca(trace_type, nullptr, "trace.gpr");
  auto *fsbase =
      b.CreateCall(module->getFunction("zvril_runtime_fsbase"), {mem});
  auto *fsaddress = arch->RegisterByName("FSBASE")->AddressOf(state, b);
  b.CreateStore(b.CreateSelect(b.CreateICmpNE(fsbase, runtime.constant(0)),
                               fsbase, b.CreateLoad(b.getInt64Ty(), fsaddress)),
                fsaddress);
  auto *check_entry = BasicBlock::Create(context, "check_entry", function);
  b.CreateCondBr(b.CreateICmpEQ(runtime.read(b, mem, 3), runtime.constant(0)),
                 check_entry, done);
  b.SetInsertPoint(check_entry);
  auto *expected_entry = b.CreateAdd(
      runtime.constant(root.address),
      b.CreateCall(module->getFunction("zvril_runtime_bias"), {mem}));
  b.CreateCondBr(
      b.CreateICmpEQ(function->getArg(remill::kPCArgNum), expected_entry),
      blocks.at(root.address), bad_return);
  b.SetInsertPoint(done);
  b.CreateRet(mem);
  b.SetInsertPoint(bad_return);
  runtime.store(b, mem, 3, runtime.constant(4));
  b.CreateBr(done);
  Array pcmap;
  for (auto &[pc, inst] : graph.instructions) {
    auto *block = blocks.at(pc);
    b.SetInsertPoint(block);
    const auto repeated = repeat_base(inst->function);
    const bool repeat = !repeated.empty();
    const bool repeat_compare = repeat && (repeated.starts_with("CMPS") ||
                                           repeated.starts_with("SCAS"));
    BasicBlock *iteration = block;
    llvm::Value *saved_flags = nullptr, *saved_valid = nullptr;
    if (repeat_compare) {
      IRBuilder<> allocation(entry->getTerminator());
      saved_flags = allocation.CreateAlloca(ArrayType::get(b.getInt8Ty(), 7));
      saved_valid = allocation.CreateAlloca(b.getInt64Ty());
      for (unsigned i = 0; i < 7; i++)
        b.CreateStore(
            b.CreateLoad(
                b.getInt8Ty(),
                arch->RegisterByName(registers[17 + i])->AddressOf(state, b)),
            b.CreateConstGEP1_64(b.getInt8Ty(), saved_flags, i));
      b.CreateStore(
          b.CreateCall(module->getFunction("zvril_runtime_flags_valid"), {mem}),
          saved_valid);
    }
    if (repeat) {
      iteration =
          BasicBlock::Create(context, "repeat_iteration_" + hx(pc), function);
      b.CreateBr(iteration);
      b.SetInsertPoint(iteration);
    }
    auto *actual_pc = b.CreateAdd(
        runtime.constant(pc),
        b.CreateCall(module->getFunction("zvril_runtime_bias"), {mem}));
    remill::StoreProgramCounter(b.GetInsertBlock(), actual_pc);
    auto *valid_flags =
        b.CreateCall(module->getFunction("zvril_runtime_flags_valid"), {mem});
    auto *started =
        b.CreateCall(module->getFunction("zvril_rt_begin"),
                     {mem, state,
                      runtime.constant(module->getDataLayout().getTypeAllocSize(
                          arch->StateStructType())),
                      actual_pc, runtime.constant(0x8d5)});
    auto *execute = BasicBlock::Create(context, "exec_" + hx(pc), function);
    auto *exhausted =
        BasicBlock::Create(context, "step_limit_" + hx(pc), function);
    b.CreateCondBr(
        b.CreateICmpNE(started, ConstantInt::get(Type::getInt32Ty(context), 0)),
        execute, exhausted);
    b.SetInsertPoint(exhausted);
    b.CreateBr(done);
    b.SetInsertPoint(execute);
    if (graph.unresolved.contains(pc)) {
      b.CreateCall(module->getFunction("zvril_rt_fault"),
                   {mem, runtime.constant(9), actual_pc, runtime.constant(0)});
      b.CreateCall(module->getFunction("zvril_rt_end"),
                   {mem, state,
                    runtime.constant(module->getDataLayout().getTypeAllocSize(
                        arch->StateStructType()))});
      b.CreateBr(done);
      pcmap.push_back(Object{{"pc", hx(pc)},
                             {"block", block->getName().str()},
                             {"blocked", graph.unresolved.at(pc)}});
      continue;
    }
    auto *record = BasicBlock::Create(context, "trace", function);
    auto *semantics = BasicBlock::Create(context, "semantics", function);
    b.CreateCondBr(
        b.CreateICmpNE(
            b.CreateCall(module->getFunction("zvril_rt_tracing"), {mem}),
            b.getInt32(0)),
        record, semantics);
    b.SetInsertPoint(record);
    for (unsigned i = 0; i < 17; i++)
      b.CreateStore(
          b.CreateLoad(b.getInt64Ty(),
                       arch->RegisterByName(registers[i])->AddressOf(state, b)),
          b.CreateConstGEP2_32(trace_type, trace_gpr, 0, i));
    llvm::Value *flags = runtime.constant(0);
    const unsigned bits[] = {4, 0, 10, 11, 2, 7, 6};
    for (unsigned i = 0; i < 7; i++) {
      auto *reg = arch->RegisterByName(registers[17 + i]);
      flags = b.CreateOr(
          flags,
          b.CreateShl(b.CreateZExt(
                          b.CreateLoad(b.getInt8Ty(), reg->AddressOf(state, b)),
                          b.getInt64Ty()),
                      runtime.constant(bits[i])));
    }
    b.CreateCall(module->getFunction("zvril_rt_record"),
                 {mem, trace_gpr, flags});
    b.CreateBr(semantics);
    b.SetInsertPoint(semantics);
    execute = semantics;
    std::unique_ptr<Inst> element;
    Inst *semantic_inst = inst.get();
    llvm::Value *has_count = nullptr;
    BasicBlock *element_join = nullptr;
    if (repeat) {
      element = std::make_unique<Inst>();
      auto bytes = inst->bytes;
      bytes.erase(std::remove_if(
                      bytes.begin(), bytes.end(),
                      [](unsigned char v) { return v == 0xf2 || v == 0xf3; }),
                  bytes.end());
      if (!arch->DecodeInstruction(pc, bytes, *element,
                                   arch->CreateInitialContext()) ||
          element->function != repeated || !string_operation(repeated))
        fail("E_UNSUPPORTED_INSTRUCTION", pc,
             "Cannot decode a standalone REP element");
      // Keep the original length for Remill's NEXT_PC update.
      element->bytes = inst->bytes;
      element->next_pc = inst->next_pc;
      semantic_inst = element.get();
      auto *count_address = arch->RegisterByName("RCX")->AddressOf(state, b);
      has_count = b.CreateICmpNE(b.CreateLoad(b.getInt64Ty(), count_address),
                                 runtime.constant(0));
    }
    auto *after_flags =
        output_flags(*semantic_inst, b, valid_flags, state, runtime);
    if (repeat)
      after_flags = b.CreateSelect(has_count, after_flags, valid_flags);
    if (repeat) {
      auto *element_body =
          BasicBlock::Create(context, "repeat_element", function);
      element_join = BasicBlock::Create(context, "repeat_commit", function);
      b.CreateCondBr(has_count, element_body, element_join);
      b.SetInsertPoint(element_body);
      execute = element_body;
    }
    if (auto mask = required_flags(semantic_inst->function))
      b.CreateCall(module->getFunction("zvril_rt_consume_flags"),
                   {mem, runtime.constant(mask)});
    remill::StoreNextProgramCounter(execute, actual_pc);
    const bool fxsave = process_step &&
                        semantic_inst->function.starts_with("FXSAVE");
    const bool fxrstor = process_step &&
                         semantic_inst->function.starts_with("FXRSTOR");
    if (fxsave || fxrstor) {
      // Remill has no semantics for FXSAVE/FXRSTOR. The pinned x86 State keeps
      // the architectural 512-byte FXSAVE block in field 11, which is exactly
      // what a save/restore pair needs. glibc's lazy-binding trampoline uses
      // this pair around symbol resolution, so process execution copies the
      // block through checked guest memory instead of decoding another
      // instruction form. Both legacy and REX.W encodings are accepted because
      // the restored bytes originate from the same block.
      const remill::Operand *memory = nullptr;
      for (const auto &op : semantic_inst->operands)
        if (op.type == remill::Operand::kTypeAddress &&
            op.addr.IsMemoryAccess()) {
          memory = &op;
          break;
        }
      if (!memory)
        fail("E_UNSUPPORTED_INSTRUCTION", pc,
             "FXSAVE/FXRSTOR requires a memory operand");
      Value *address = runtime.constant(memory->addr.displacement);
      const auto add_register = [&](const std::string &name, Value *scale) {
        if (name.empty())
          return;
        if (name == "RIP" || name == "NEXT_PC" || name == "PC") {
          address = b.CreateAdd(
              address,
              b.CreateAdd(actual_pc,
                          runtime.constant(semantic_inst->next_pc - pc)));
          return;
        }
        auto *reg = arch->RegisterByName(name);
        if (!reg)
          fail("E_UNSUPPORTED_INSTRUCTION", pc,
               "FXSAVE/FXRSTOR uses an unknown base register: " + name);
        Value *value = b.CreateLoad(
            b.getInt64Ty(), reg->AddressOf(state, b));
        address = b.CreateAdd(address,
                              scale ? b.CreateMul(value, scale) : value);
      };
      if (!memory->addr.index_reg.name.empty())
        add_register(memory->addr.index_reg.name,
                     runtime.constant(memory->addr.scale));
      add_register(memory->addr.base_reg.name, nullptr);
      if (!memory->addr.segment_base_reg.name.empty())
        add_register(memory->addr.segment_base_reg.name, nullptr);
      if (memory->addr.address_size == 32)
        address = b.CreateZExt(b.CreateTrunc(address, b.getInt32Ty()),
                               b.getInt64Ty());
      auto *state_type =
          llvm::StructType::getTypeByName(context, "struct.X86State");
      if (!state_type)
        state_type = arch->StateStructType();
      const auto &layout = module->getDataLayout();
      if (state_type->getNumElements() != 14 ||
          layout.getTypeAllocSize(state_type->getElementType(11)) != 512)
        fail("E_BACKEND_UNAVAILABLE", pc,
             "Pinned x86 State lost its architectural FXSAVE block");
      auto *fpu = b.CreateStructGEP(state_type, state, 11);
      auto *st = b.CreateStructGEP(state_type, state, 7);
      auto *vec = b.CreateStructGEP(state_type, state, 1);
      auto *st_bytes = b.CreateBitCast(st, b.getPtrTy());
      auto *vec_bytes = b.CreateBitCast(vec, b.getPtrTy());
      const auto vec_stride = layout.getTypeAllocSize(
          cast<ArrayType>(state_type->getElementType(1))->getElementType());
      const auto st_bytes_size = layout.getTypeAllocSize(
          state_type->getElementType(7));
      // FXSAVE layout: control/MXCSR 0..31, ST0-ST7 32..159, XMM0-XMM15
      // 160..415, reserved 416..511. Remill stores XMM values in State.vec and
      // x87 stack values in State.st, so the FXSAVE shadow alone is not
      // sufficient: a save/restore pair must round-trip the real registers.
      const auto transfer = [&](bool save, Value *address, Value *source,
                                uint64_t size) {
        b.CreateCall(module->getFunction(save ? "zvril_runtime_write"
                                              : "zvril_runtime_read"),
                     {mem, address, source, runtime.constant(size)});
      };
      transfer(fxsave, address, b.CreateBitCast(fpu, b.getPtrTy()), 32);
      transfer(fxsave, b.CreateAdd(address, runtime.constant(32)), st_bytes,
               st_bytes_size);
      for (unsigned i = 0; i < 16; i++) {
        auto *element = b.CreateConstGEP1_64(
            b.getInt8Ty(), vec_bytes, std::uint64_t(i) * vec_stride);
        transfer(fxsave, b.CreateAdd(address, runtime.constant(160 + 16 * i)),
                 element, 16);
      }
    } else {
      const auto status = semantic_inst->GetLifter()->LiftIntoBlock(
          *semantic_inst, execute, state);
      if (status != remill::kLiftedInstruction)
        fail("E_UNSUPPORTED_INSTRUCTION", pc,
             "Remill failed to lift " + inst->function);
    }
    b.SetInsertPoint(execute);
    if (repeat) {
      auto *count_address = arch->RegisterByName("RCX")->AddressOf(state, b);
      b.CreateStore(b.CreateSub(b.CreateLoad(b.getInt64Ty(), count_address),
                                runtime.constant(1)),
                    count_address);
      b.CreateBr(element_join);
      b.SetInsertPoint(element_join);
      execute = element_join;
    }
    if (inst->function == "UD2")
      b.CreateCall(module->getFunction("zvril_rt_fault"),
                   {mem, runtime.constant(9), actual_pc, runtime.constant(0)});
    auto *transfer =
        BasicBlock::Create(context, "transfer_" + hx(pc), function);
    auto *completed =
        b.CreateCall(module->getFunction("zvril_rt_end"),
                     {mem, state,
                      runtime.constant(module->getDataLayout().getTypeAllocSize(
                          arch->StateStructType()))});
    auto *failure_target = done;
    if (repeat_compare) {
      failure_target =
          BasicBlock::Create(context, "repeat_fault_flags", function);
      IRBuilder<> restore(failure_target);
      auto *fault_code = runtime.read(restore, mem, 3);
      // The declared CPU policy selects initial versus completed comparison
      // FLAGS. Measured native hardware does not agree on this fault detail.
      auto *architectural = restore.CreateOr(
          restore.CreateICmpEQ(fault_code, runtime.constant(1)),
          restore.CreateICmpEQ(fault_code, runtime.constant(2)));
      architectural = restore.CreateOr(
          architectural, restore.CreateICmpEQ(fault_code, runtime.constant(6)));
      auto *policy = restore.CreateCall(
          module->getFunction("zvril_runtime_rep_fault_flags"), {mem});
      auto bit = inst->function.starts_with("REPE_") ? 1 : 2;
      architectural = restore.CreateAnd(
          architectural,
          restore.CreateICmpNE(restore.CreateAnd(policy, runtime.constant(bit)),
                               runtime.constant(0)));
      for (unsigned i = 0; i < 7; i++) {
        auto *address =
            arch->RegisterByName(registers[17 + i])->AddressOf(state, restore);
        restore.CreateStore(
            restore.CreateSelect(
                architectural,
                restore.CreateLoad(restore.getInt8Ty(),
                                   restore.CreateConstGEP1_64(
                                       restore.getInt8Ty(), saved_flags, i)),
                restore.CreateLoad(restore.getInt8Ty(), address)),
            address);
      }
      restore.CreateCall(
          module->getFunction("zvril_runtime_set_flags_valid"),
          {mem, restore.CreateSelect(
                    architectural,
                    restore.CreateLoad(restore.getInt64Ty(), saved_valid),
                    valid_flags)});
      restore.CreateBr(done);
    }
    b.CreateCondBr(b.CreateICmpNE(completed, ConstantInt::get(
                                                 Type::getInt32Ty(context), 0)),
                   transfer, failure_target);
    b.SetInsertPoint(transfer);
    b.CreateCall(module->getFunction("zvril_runtime_set_flags_valid"),
                 {mem, after_flags});
    if (process_step) {
      if (repeat) {
        auto *count = b.CreateLoad(
            b.getInt64Ty(), arch->RegisterByName("RCX")->AddressOf(state, b));
        auto *again = b.CreateICmpNE(count, runtime.constant(0));
        if (repeat_compare) {
          auto *zf = b.CreateICmpNE(
              b.CreateLoad(b.getInt8Ty(),
                           arch->RegisterByName("ZF")->AddressOf(state, b)),
              b.getInt8(0));
          again = b.CreateAnd(again, inst->function.starts_with("REPE_")
                                         ? zf
                                         : b.CreateNot(zf));
        }
        auto *finish = BasicBlock::Create(context, "repeat_done", function);
        b.CreateCondBr(again, iteration, finish);
        b.SetInsertPoint(finish);
      }
      Value *next = runtime.constant(inst->next_pc);
      if (inst->category == Inst::kCategoryConditionalBranch)
        next = b.CreateSelect(remill::LoadBranchTaken(transfer),
                              runtime.constant(inst->branch_taken_pc),
                              runtime.constant(inst->branch_not_taken_pc));
      else if (inst->category == Inst::kCategoryDirectJump ||
               inst->category == Inst::kCategoryDirectFunctionCall)
        next = runtime.constant(inst->branch_taken_pc);
      else if (inst->category == Inst::kCategoryIndirectJump ||
               inst->category == Inst::kCategoryIndirectFunctionCall ||
               inst->category == Inst::kCategoryFunctionReturn)
        next = remill::LoadNextProgramCounter(transfer,
                                              *arch->GetInstrinsicTable());
      remill::StoreProgramCounter(b.GetInsertBlock(), next);
      b.CreateBr(done);
    } else if (graph.external_calls.contains(pc)) {
      const auto &symbol = graph.external_calls.at(pc);
      if (symbol != "__zvril_tlsdesc")
        b.CreateCall(module->getFunction("zvril_runtime_set_flags_valid"),
                     {mem, runtime.constant(0x400)});
      const auto load_reg = [&](const char *name) {
        return b.CreateLoad(Type::getInt64Ty(context),
                            arch->RegisterByName(name)->AddressOf(state, b));
      };
      Value *result =
          b.CreateCall(module->getFunction("zvril_runtime_bridge"),
                       {mem, b.CreateGlobalString(symbol),
                        load_reg(symbol == "__zvril_tlsdesc" ? "RAX" : "RDI"),
                        load_reg("RSI"), load_reg("RDX")});
      if (symbol == "strcmp" || symbol == "strncmp" || symbol == "memcmp")
        result = b.CreateZExt(b.CreateTrunc(result, Type::getInt32Ty(context)),
                              Type::getInt64Ty(context));
      b.CreateStore(result, arch->RegisterByName("RAX")->AddressOf(state, b));
      auto *sp = load_reg("RSP");
      auto *target = b.CreateCall(
          module->getFunction("__remill_read_memory_64"), {mem, sp});
      b.CreateStore(b.CreateAdd(sp, runtime.constant(8)),
                    arch->RegisterByName("RSP")->AddressOf(state, b));
      remill::StoreProgramCounter(transfer, target);
      remill::StoreNextProgramCounter(transfer, target);
      auto *dispatch_block =
          BasicBlock::Create(context, "external_return", function);
      b.CreateCondBr(
          b.CreateICmpEQ(runtime.read(b, mem, 3), runtime.constant(0)),
          dispatch_block, done);
      b.SetInsertPoint(dispatch_block);
      auto *internal =
          BasicBlock::Create(context, "external_return_dispatch", function);
      b.CreateCondBr(b.CreateICmpEQ(target, runtime.read(b, mem, 8)), done,
                     internal);
      b.SetInsertPoint(internal);
      auto *normalized = b.CreateSub(
          target,
          b.CreateCall(module->getFunction("zvril_runtime_bias"), {mem}));
      auto *dispatch =
          b.CreateSwitch(normalized, bad_return, graph.return_sites.size());
      for (auto site : graph.return_sites)
        dispatch->addCase(cast<ConstantInt>(runtime.constant(site)),
                          blocks.at(site));
    } else
      switch (inst->category) {
      case Inst::kCategoryNormal:
      case Inst::kCategoryNoOp:
        if (repeat) {
          auto *again = b.CreateICmpNE(
              b.CreateLoad(b.getInt64Ty(),
                           arch->RegisterByName("RCX")->AddressOf(state, b)),
              runtime.constant(0));
          if (repeat_compare) {
            auto *zf = b.CreateICmpNE(
                b.CreateLoad(b.getInt8Ty(),
                             arch->RegisterByName("ZF")->AddressOf(state, b)),
                b.getInt8(0));
            again = b.CreateAnd(again, inst->function.starts_with("REPE_")
                                           ? zf
                                           : b.CreateNot(zf));
          }
          b.CreateCondBr(again, iteration, blocks.at(inst->next_pc));
        } else
          b.CreateBr(blocks.at(inst->next_pc));
        break;
      case Inst::kCategoryConditionalBranch:
        b.CreateCondBr(remill::LoadBranchTaken(transfer),
                       blocks.at(inst->branch_taken_pc),
                       blocks.at(inst->branch_not_taken_pc));
        break;
      case Inst::kCategoryDirectJump:
      case Inst::kCategoryDirectFunctionCall:
        b.CreateBr(blocks.at(graph.resolved_calls.contains(pc)
                                 ? graph.resolved_calls.at(pc)
                                 : inst->branch_taken_pc));
        break;
      case Inst::kCategoryIndirectFunctionCall:
      case Inst::kCategoryIndirectJump:
        if (graph.indirect_targets.contains(pc)) {
          auto *target = remill::LoadNextProgramCounter(
              transfer, *arch->GetInstrinsicTable());
          auto *normalized = b.CreateSub(
              target,
              b.CreateCall(module->getFunction("zvril_runtime_bias"), {mem}));
          auto *dispatch = b.CreateSwitch(normalized, bad_return,
                                          graph.indirect_targets.at(pc).size());
          for (auto to : graph.indirect_targets.at(pc))
            dispatch->addCase(cast<ConstantInt>(runtime.constant(to)),
                              blocks.at(to));
        } else
          b.CreateBr(blocks.at(graph.resolved_calls.at(pc)));
        break;
      case Inst::kCategoryFunctionReturn: {
        auto *return_pc = remill::LoadNextProgramCounter(
            transfer, *arch->GetInstrinsicTable());
        auto *internal =
            BasicBlock::Create(context, "return_dispatch", function);
        b.CreateCondBr(b.CreateICmpEQ(return_pc, runtime.read(b, mem, 8)), done,
                       internal);
        b.SetInsertPoint(internal);
        auto *normalized = b.CreateSub(
            return_pc,
            b.CreateCall(module->getFunction("zvril_runtime_bias"), {mem}));
        auto *dispatch =
            b.CreateSwitch(normalized, bad_return, graph.return_sites.size());
        for (auto target : graph.return_sites)
          dispatch->addCase(cast<ConstantInt>(runtime.constant(target)),
                            blocks.at(target));
        break;
      }
      case Inst::kCategoryError:
        b.CreateBr(done);
        break;
      default:
        fail("E_INTERNAL", pc,
             "Unexpected instruction category after preflight");
      }
    pcmap.push_back(Object{{"pc", hx(pc)},
                           {"block", block->getName().str()},
                           {"encoding",
                            [&] {
                              std::ostringstream s;
                              for (unsigned char v : inst->bytes)
                                s << std::hex << std::setw(2)
                                  << std::setfill('0') << unsigned(v);
                              return s.str();
                            }()},
                           {"semantics", inst->function}});
  }
  std::set<std::string> exports{"zvril_lifted_v2"};
  if (!process_step) {
    // Preserve the ABI-v1 interface by giving the machine-state core a v2
    // context.
    auto *legacy = arch->DeclareLiftedFunction("zvril_lifted", module.get());
    legacy->setCallingConv(CallingConv::C);
    legacy->setAttributes(AttributeList{});
    b.SetInsertPoint(BasicBlock::Create(context, "entry", legacy));
    auto *converted = b.CreateCall(module->getFunction("zvril_rt_legacy_begin"),
                                   {legacy->getArg(2)});
    auto *run = BasicBlock::Create(context, "run", legacy);
    auto *cleanup = BasicBlock::Create(context, "cleanup", legacy);
    b.CreateCondBr(b.CreateICmpNE(converted, ConstantPointerNull::get(
                                                 PointerType::get(context, 0))),
                   run, cleanup);
    b.SetInsertPoint(run);
    b.CreateCall(function, {legacy->getArg(0), legacy->getArg(1), converted});
    b.CreateBr(cleanup);
    b.SetInsertPoint(cleanup);
    b.CreateCall(module->getFunction("zvril_rt_legacy_end"),
                 {converted, legacy->getArg(2)});
    b.CreateRet(legacy->getArg(2));
    exports.insert("zvril_lifted");
  }
  for (auto &f : *module)
    if (!process_step && f.getName().starts_with("zvril_runtime_"))
      exports.insert(f.getName().str());
  // Intrinsic lowering below introduces calls to this helper. Keep it alive
  // across the preliminary DCE, then restore its internal linkage.
  exports.insert("zvril_rt_fault");
  if (!process_step)
    emit_image(*module, image, exports);
  if (!process_step)
    state_api(*module, *arch, exports);
  auto wrapper = typed_wrapper(*module, *arch, options.abi_contract,
                               root.address, exports);
  std::set<std::string> process_imports;
#define ZVRIL_IMPORT_NAME(name) process_imports.insert(#name);
  ZVRIL_PROCESS_RUNTIME(ZVRIL_IMPORT_NAME)
#undef ZVRIL_IMPORT_NAME
  std::map<std::string, FunctionType *> process_types;
  if (process_step)
    for (const auto &name : process_imports)
      if (auto *f = module->getFunction(name)) {
        process_types[name] = f->getFunctionType();
        f->deleteBody();
        f->setLinkage(GlobalValue::ExternalLinkage);
        f->setAttributes(AttributeList{});
      }
  for (const char *name : {"llvm.used", "llvm.compiler.used"})
    if (auto *global = module->getGlobalVariable(name))
      global->eraseFromParent();
  for (auto &f : *module)
    if (!f.isDeclaration() && !exports.contains(f.getName().str()))
      f.setLinkage(GlobalValue::InternalLinkage);
  for (auto &global : module->globals())
    if (global.hasInitializer())
      global.setLinkage(GlobalValue::InternalLinkage);
  dce(*module);
  guard_division(*module);
  if (process_step)
    for (const auto &[name, type] : process_types)
      if (!module->getFunction(name))
        llvm::Function::Create(type, GlobalValue::ExternalLinkage, name,
                               module.get());
  runtime.lower_intrinsics();
  exports.erase("zvril_rt_fault");
  // Runtime definitions are internal; the public machine-state API is the only
  // ABI.
  for (auto &f : *module)
    if (!f.isDeclaration() && !exports.contains(f.getName().str()))
      f.setLinkage(GlobalValue::InternalLinkage);
  dce(*module);
  for (const auto &f : *module)
    if (f.isDeclaration() && !f.use_empty() && !f.isIntrinsic() &&
        !std::set<std::string>{"calloc", "malloc", "realloc", "free", "memcpy",
                               "memmove", "memset", "strcmp"}
             .contains(f.getName().str()) &&
        !(process_step && (process_imports.contains(f.getName().str()) ||
                           math_bridge(f.getName()))))
      fail("E_EXTERNAL_UNMODELED", root.address,
           "Unmodeled semantics/runtime function: " + f.getName().str());
  for (const auto &global : module->globals())
    if (global.isDeclaration() && !global.use_empty())
      fail("E_EXTERNAL_UNMODELED", root.address,
           "Unmodeled semantics/runtime global: " + global.getName().str());
  std::string verifier;
  raw_string_ostream diagnostics(verifier);
  if (verifyModule(*module, &diagnostics))
    throw Error("E_LLVM_VERIFY", diagnostics.str(), 2);
  Array functions;
  for (const auto &[pc, f] : graph.functions) {
    std::uint64_t count = 0;
    for (const auto &[ip, _] : graph.instructions)
      if (ip >= pc && ip - pc < f.size)
        ++count;
    Array unresolved_edges;
    for (const auto &[ip, reason] : graph.unresolved)
      if (ip >= pc && ip - pc < f.size)
        unresolved_edges.push_back(Object{{"pc", hx(ip)}, {"message", reason}});
    functions.push_back(
        Object{{"name", llvm::json::fixUTF8(f.name)},
               {"address", hx(pc)},
               {"size", hx(f.size)},
               {"discovery_evidence", Array{f.source}},
               {"boundary_known", true},
               {"status", graph.unresolved.empty() ? "LIFTED" : "PARTIAL"},
               {"instruction_count", count},
               {"unsupported_instructions", Array{}},
               {"unresolved_edges", std::move(unresolved_edges)},
               {"llvm_verified", true},
               {"tested_cases", 0}});
  }
  Array layout;
  arch->ForEachRegister([&](const remill::Register *reg) {
    layout.push_back(Object{
        {"name", reg->name}, {"offset", reg->offset}, {"bytes", reg->size}});
  });
  // The pinned x86 State stores the architectural FXSAVE block in field 11;
  // MXCSR is byte 24 of the architectural FXSAVE64 format. Validate the LLVM
  // shape instead of assuming a host C++ structure has the bitcode's layout.
  auto *x86_state = StructType::getTypeByName(context, "struct.X86State");
  if (!x86_state || x86_state->getNumElements() != 14 ||
      module->getDataLayout().getTypeAllocSize(x86_state->getElementType(11)) !=
          512)
    throw Error("E_BACKEND_UNAVAILABLE", "Unexpected pinned x86 FXSAVE layout",
                1);
  const auto mxcsr_offset =
      module->getDataLayout().getStructLayout(x86_state)->getElementOffset(11) +
      24;
  layout.push_back(
      Object{{"name", "MXCSR"}, {"offset", mxcsr_offset}, {"bytes", 4}});
  Object result{{"backend", "remill"},
                {"remill_revision", ZVRIL_REMILL_REVISION},
                {"semantics_sha256", semantics_sha},
                {"runtime_sha256", sha_file(runtime_path)},
                {"isa", options.architecture},
                {"entry", hx(root.address)},
                {"functions", std::move(functions)},
                {"instruction_count", graph.instructions.size()},
                {"runtime_abi", "zvril-memory-v2 (v1 compatible)"},
                {"undefined_values",
                 "Remill undefined values are concretized to zero; undefined "
                 "flags are not native equivalence evidence"},
                {"execution_contract",
                 "Single-threaded machine state; checked paged guest memory, "
                 "ELF image initializer, modeled libc bridges and step budget; "
                 "unsupported process behavior is rejected"}};
  result["status"] = graph.unresolved.empty() ? "LIFTED" : "PARTIAL";
  Array unresolved;
  for (const auto &[pc, message] : graph.unresolved)
    unresolved.push_back(Object{{"pc", hx(pc)}, {"message", message}});
  result["unresolved"] = std::move(unresolved);
  result["typed_wrapper"] = std::move(wrapper);
  result["indirect_resolution"] = std::move(graph.indirect_evidence);
  Array bindings;
  for (const auto &[pc, symbol] : graph.external_calls)
    bindings.push_back(
        Object{{"pc", hx(pc)},
               {"symbol", symbol},
               {"requested_symbol", graph.external_requests.at(pc)},
               {"kind", "guest_model"}});
  result["external_bindings"] = std::move(bindings);
  result["model_limits"] = Array{
      "Single-threaded, one TLS module; no loader constructors, signals or C++ "
      "exceptions",
      "libc string/memory/allocation bridges obey their declared C API model; "
      "comparison magnitudes may differ from a host libc implementation",
      "__ctype_b_loc uses the glibc C/POSIX locale table ABI only"};
  module->getOrInsertNamedMetadata("zvril.provenance")
      ->addOperand(MDNode::get(
          context,
          {MDString::get(context, "Remill " ZVRIL_REMILL_REVISION),
           MDString::get(context,
                         "Instruction semantics: Trail of Bits and Remill "
                         "contributors; Apache-2.0; see LICENSE.remill"),
           MDString::get(
               context,
               "Zvril CFG, runtime and state API are additional code")}));
  if (compiled) {
    result["pcmap"] = Object{{"instructions", std::move(pcmap)}};
    result["state_layout"] = Object{{"registers", std::move(layout)}};
    result["execution_contract"] =
        "One instruction under a dynamic process dispatcher; recheck "
        "executable bytes on every entry";
    result["model_limits"] =
        Array{"Dynamic execution is not static whole-program recovery or "
              "exhaustive path validation"};
    *compiled = std::move(module);
    return result;
  }
  // Stage artifacts in an owned temporary directory; CLI publishes this
  // directory.
  std::error_code ec;
  std::filesystem::create_directories(options.output, ec);
  if (ec)
    throw Error("E_OUTPUT", "Cannot create artifact directory", 2);
  {
    raw_fd_ostream output((options.output / "module.ll").string(), ec);
    if (ec)
      throw Error("E_OUTPUT", "Cannot open module.ll", 2);
    module->print(output, nullptr);
    output.flush();
    if (output.has_error())
      throw Error("E_OUTPUT", "Cannot finish module.ll", 2);
  }
  {
    raw_fd_ostream output((options.output / "module.bc").string(), ec);
    if (ec)
      throw Error("E_OUTPUT", "Cannot open module.bc", 2);
    WriteBitcodeToFile(*module, output);
    output.flush();
    if (output.has_error())
      throw Error("E_OUTPUT", "Cannot finish module.bc", 2);
  }
  json_file(
      options.output / "pcmap.json",
      Object{{"schema_version", "0.1"}, {"instructions", std::move(pcmap)}});
  json_file(options.output / "functions.json",
            Object{{"schema_version", "0.1"},
                   {"functions", Array(*result.getArray("functions"))}});
  {
    raw_fd_ostream dot((options.output / "cfg.dot").string(), ec);
    if (ec)
      throw Error("E_OUTPUT", "Cannot open cfg.dot", 2);
    dot << "digraph zvril {\n";
    for (const auto &[pc, instruction] : graph.instructions)
      dot << "  \"" << hx(pc) << "\" [label=\"" << hx(pc) << "\\n"
          << instruction->function << "\"];\n";
    for (const auto &edge : graph.edges)
      if (auto *e = edge.getAsObject()) {
        auto from = e->getString("from").value_or("");
        auto to =
            e->getString("to").value_or(e->getString("external").value_or(""));
        dot << "  \"" << from << "\" -> \"" << to << "\" [label=\""
            << e->getString("kind").value_or("") << "\"];\n";
      }
    dot << "}\n";
    dot.flush();
    if (dot.has_error())
      throw Error("E_OUTPUT", "Cannot finish cfg.dot", 2);
  }
  json_file(
      options.output / "cfg.json",
      Object{{"schema_version", "0.1"}, {"edges", std::move(graph.edges)}});
  json_file(
      options.output / "state_layout.json",
      Object{{"remill_revision", ZVRIL_REMILL_REVISION},
             {"state_bytes", module->getDataLayout()
                                 .getTypeAllocSize(arch->StateStructType())
                                 .getFixedValue()},
             {"registers", std::move(layout)}});
  std::ofstream license(options.output / "LICENSE.remill", std::ios::binary);
  license << kRemillLicense;
  license.close();
  if (!license)
    throw Error("E_OUTPUT", "Cannot write Remill license", 2);
  return result;
#endif
}
Object lift(const Image &image, const LiftOptions &options) {
  return lift_impl(image, options);
}
#ifdef ZVRIL_HAS_REMILL
struct StepCompiler::Impl {
  LLVMContext context;
  std::unique_ptr<Module> prepared;
  remill::Arch::ArchPtr decoder;
  std::map<std::string, std::unique_ptr<Module>> slices;
  std::string architecture;
  explicit Impl(const std::string &isa) : architecture(isa) {
    SMDiagnostic error;
    auto path = default_semantics_path(isa);
    prepared = parseIRFile(path.string(), error, context);
    if (!prepared)
      throw Error("E_BACKEND_UNAVAILABLE", error.getMessage().str(), 1);
    decoder = remill::Arch::Get(context, "linux", isa);
    decoder->PrepareModule(prepared);
    decoder->InitFromSemanticsModule(prepared.get());
    auto runtime = parseIRFile((path.parent_path() / "runtime.bc").string(),
                               error, context);
    if (!runtime)
      throw Error("E_BACKEND_UNAVAILABLE", "Cannot load runtime.bc", 1);
    runtime->setDataLayout(prepared->getDataLayout());
    runtime->setTargetTriple(prepared->getTargetTriple());
    if (Linker::linkModules(*prepared, std::move(runtime)))
      throw Error("E_LLVM_VERIFY", "Process runtime link failed", 2);
  }
  Module *slice(std::uint64_t pc, std::span<const std::uint8_t> bytes) {
    remill::Instruction instruction;
    std::string_view view(reinterpret_cast<const char *>(bytes.data()),
                          bytes.size());
    bool decoded = false;
    for (std::size_t width = 1; width <= bytes.size(); width++)
      if (decoder->DecodeInstruction(pc, view.substr(0, width), instruction,
                                     decoder->CreateInitialContext())) {
        decoded = true;
        break;
      }
    if (!decoded)
      return prepared.get();
    const auto name = instruction.function;
    if (auto existing = slices.find(name); existing != slices.end())
      return existing->second.get();
    auto reduced = CloneModule(*prepared);
    std::set<std::string> roots{"ISEL_" + name,
                                "ISEL_INVALID_INSTRUCTION",
                                "ISEL_UNSUPPORTED_INSTRUCTION",
                                "__remill_basic_block",
                                "__remill_state",
                                "__remill_register_window"};
    auto base = repeat_base(name);
    if (!base.empty())
      roots.insert("ISEL_" + base);
    for (const char *key : {"llvm.used", "llvm.compiler.used"})
      if (auto *g = reduced->getGlobalVariable(key))
        g->eraseFromParent();
    for (auto &f : *reduced)
      if (!f.isDeclaration() && !roots.contains(f.getName().str()))
        f.setLinkage(GlobalValue::InternalLinkage);
    for (auto &g : reduced->globals())
      if (g.hasInitializer() && !roots.contains(g.getName().str()))
        g.setLinkage(GlobalValue::InternalLinkage);
    dce(*reduced);
    // Arch/IntrinsicTable needs all Remill intrinsic declarations, and the IR
    // builder needs the C runtime ABI before lowering memory intrinsics.
    for (const auto &f : *prepared)
      if ((f.getName().starts_with("__remill_") ||
           f.getName().starts_with("zvril_")) &&
          !reduced->getFunction(f.getName())) {
        auto *declaration = llvm::Function::Create(f.getFunctionType(),
                                                   GlobalValue::ExternalLinkage,
                                                   f.getName(), reduced.get());
        declaration->setCallingConv(f.getCallingConv());
      }
    auto *result = reduced.get();
    slices.emplace(name, std::move(reduced));
    return result;
  }
};
StepCompiler::StepCompiler(const std::string &isa)
    : impl(std::make_unique<Impl>(isa)) {}
StepCompiler::~StepCompiler() = default;
LLVMContext &StepCompiler::context() { return impl->context; }
StepModule StepCompiler::instruction(std::uint64_t pc,
                                     std::span<const std::uint8_t> bytes) {
  Image snapshot;
  snapshot.type = ET_EXEC;
  snapshot.bytes.assign(bytes.begin(), bytes.end());
  snapshot.segments.push_back(
      Segment{0, pc, bytes.size(), bytes.size(), 1, PF_R | PF_X});
  LiftOptions options;
  options.address = pc;
  options.size = bytes.size();
  options.architecture = impl->architecture;
  StepModule result;
  result.evidence = lift_impl(snapshot, options, true, &impl->context,
                              impl->slice(pc, bytes), &result.module);
  return result;
}
StepModule StepCompiler::image(const Image &image) {
  auto module = CloneModule(*impl->prepared);
  auto arch = remill::Arch::Get(impl->context, "linux", impl->architecture);
  arch->PrepareModule(module);
  arch->InitFromSemanticsModule(module.get());
  std::set<std::string> exports;
  state_api(*module, *arch, exports);
  // Linux maps PT_LOAD at page granularity. Process mprotect/munmap and code
  // fetch must also see the padding of these pages, unlike function-only maps.
  Image mapped = image;
  mapped.segments.clear();
  struct LoadPage {
    std::array<std::uint8_t, 4096> bytes{};
    unsigned flags = 0;
  };
  std::map<std::uint64_t, LoadPage> pages;
  for (const auto &segment : image.segments) {
    if (!segment.memory_size)
      continue;
    if (segment.memory_size > 256 * 1024 * 1024 ||
        segment.address > UINT64_MAX - segment.memory_size - 4095)
      throw Error("E_PROCESS_RESOURCE",
                  "Process PT_LOAD page extent exceeds limits", 1);
    const auto begin = segment.address & ~std::uint64_t(4095);
    const auto end =
        (segment.address + segment.memory_size + 4095) & ~std::uint64_t(4095);
    for (auto address = begin; address < end; address += 4096) {
      if (pages.size() >= 65536 && !pages.contains(address))
        throw Error("E_PROCESS_RESOURCE", "Too many process image pages", 1);
      auto &page = pages[address];
      page.flags = segment.flags;
      // Include file bytes before/after the nominal extent on file-backed
      // pages, then zero the segment's BSS tail as the kernel loader does.
      const auto delta = segment.address - begin;
      if (segment.offset < delta)
        throw Error("E_PROCESS_IMAGE", "Invalid page-aligned file offset", 1);
      const auto file_base = segment.offset - delta;
      const auto file_end = segment.address + segment.file_size;
      for (unsigned i = 0; i < 4096; i++) {
        const auto at = address + i;
        const auto offset = file_base + (at - begin);
        if (at >= file_end && segment.memory_size > segment.file_size)
          page.bytes[i] = 0;
        else if (address < file_end && offset < image.bytes.size())
          page.bytes[i] = image.bytes[offset];
      }
    }
  }
  for (const auto &[address, page] : pages) {
    auto offset = mapped.bytes.size();
    mapped.bytes.insert(mapped.bytes.end(), page.bytes.begin(),
                        page.bytes.end());
    mapped.segments.push_back(
        Segment{offset, address, 4096, 4096, 4096, page.flags});
  }
  // This is kernel-style entry into the original ELF startup code. Its static
  // PIE CRT performs relocations, TLS setup and RELRO protection itself. The
  // selected-function initializer does those tasks on behalf of a missing CRT;
  // doing them here would relocate twice and protect data before startup uses
  // it.
  mapped.metadata.clear();
  mapped.relocations.clear();
  mapped.unsupported_loader_features.clear();
  mapped.dynamic_complete = true;
  emit_image(*module, mapped, exports);
  for (auto &f : *module)
    if (!f.isDeclaration() && !exports.contains(f.getName().str()))
      f.setLinkage(GlobalValue::InternalLinkage);
  for (auto &g : module->globals())
    if (g.hasInitializer())
      g.setLinkage(GlobalValue::InternalLinkage);
  for (const char *n : {"llvm.used", "llvm.compiler.used"})
    if (auto *g = module->getGlobalVariable(n))
      g->eraseFromParent();
  dce(*module);
  std::string message;
  raw_string_ostream out(message);
  if (verifyModule(*module, &out))
    throw Error("E_LLVM_VERIFY", out.str(), 2);
  Array registers;
  arch->ForEachRegister([&](const remill::Register *r) {
    registers.push_back(
        Object{{"name", r->name}, {"offset", r->offset}, {"bytes", r->size}});
  });
  auto *state_type =
      StructType::getTypeByName(impl->context, "struct.X86State");
  auto mxcsr = module->getDataLayout()
                   .getStructLayout(state_type)
                   ->getElementOffset(11) +
               24;
  registers.push_back(
      Object{{"name", "MXCSR"}, {"offset", mxcsr}, {"bytes", 4}});
  return {std::move(module), Object{{"kind", "process_image"},
                                    {"registers", std::move(registers)}}};
}
#endif
} // namespace zvril
