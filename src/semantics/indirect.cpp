#include "zvril/analysis/indirect.h"
#include <algorithm>
#include <cstring>
#include <elf.h>
#include <optional>
#include <sstream>

namespace zvril {
namespace {
using Inst = remill::Instruction;
using Op = remill::Operand;
struct Known {
  std::uint64_t value = 0, mask = 0;
  int bias = 0;
};
std::uint64_t mask(unsigned bits) {
  return bits >= 64 ? UINT64_MAX : (UINT64_C(1) << bits) - 1;
}
unsigned width(const Inst &i) {
  for (unsigned n : {64u, 32u, 16u, 8u})
    if (llvm::StringRef(i.function).ends_with("_" + std::to_string(n)))
      return n;
  return 64;
}
std::string hex(std::uint64_t n) {
  std::ostringstream s;
  s << "0x" << std::hex << n;
  return s.str();
}
} // namespace
std::optional<IndirectTargets> resolve_bounded_indirect(
    const Image &image, const remill::Arch &arch,
    const std::map<std::uint64_t, std::unique_ptr<Inst>> &decoded,
    const Inst &terminal, std::uint64_t owner_start) {
  // Prove a bounded register domain through an adjacent unsigned CMP/JA guard.
  // Every later instruction must have one predecessor; recovery rechecks this
  // after all edges (including table targets) have been discovered.
  std::vector<const Inst *> chain;
  const Inst *guard = nullptr;
  const Inst *compare = nullptr;
  auto at = decoded.lower_bound(terminal.pc);
  std::uint64_t next = terminal.pc;
  for (unsigned count = 0; count < 24 && at != decoded.begin(); count++) {
    --at;
    const auto *i = at->second.get();
    if (i->pc < owner_start || i->next_pc != next)
      return std::nullopt;
    if (i->category == Inst::kCategoryConditionalBranch) {
      guard = i;
      break;
    }
    if (i->category != Inst::kCategoryNormal &&
        i->category != Inst::kCategoryNoOp)
      return std::nullopt;
    chain.push_back(i);
    next = i->pc;
  }
  if (!guard || guard->branch_not_taken_pc != next ||
      !(guard->function.starts_with("JNBE_") ||
        guard->function.starts_with("JA_")))
    return std::nullopt;
  if (at == decoded.begin())
    return std::nullopt;
  --at;
  compare = at->second.get();
  if (compare->next_pc != guard->pc || !compare->function.starts_with("CMP_"))
    return std::nullopt;
  const Op *index = nullptr;
  std::optional<std::uint64_t> bound;
  for (const auto &o : compare->operands) {
    if (o.action == Op::kActionRead && o.type == Op::kTypeRegister && !index)
      index = &o;
    if (o.type == Op::kTypeImmediate)
      bound = o.imm.val;
  }
  if (!index || !bound || *bound > 4095 || index->size < 32)
    return std::nullopt;
  const auto *index_reg = arch.RegisterByName(index->reg.name);
  if (!index_reg)
    return std::nullopt;
  std::reverse(chain.begin(), chain.end());
  std::string target_register;
  const Op *target_address = nullptr;
  for (const auto &o : terminal.operands)
    if (o.type == Op::kTypeAddress && o.action == Op::kActionRead &&
        o.addr.IsMemoryAccess() && o.size == 64)
      target_address = &o;
  for (const auto &o : terminal.operands)
    if (o.type == Op::kTypeRegister && o.action == Op::kActionRead &&
        o.size == 64) {
      target_register = o.reg.name;
      break;
    }
  if (target_register.empty() && !target_address)
    return std::nullopt;
  IndirectTargets result;
  result.predecessors.emplace_back(guard->pc, compare->pc);
  auto previous = guard->pc;
  for (auto *i : chain) {
    result.predecessors.emplace_back(i->pc, previous);
    previous = i->pc;
  }
  result.predecessors.emplace_back(terminal.pc, previous);
  std::set<std::uint64_t> read_addresses;
  std::map<std::uint64_t, llvm::json::Object> relocated;
  const auto table_read = [&](Known address, unsigned bytes) -> std::optional<Known> {
    if (address.bias != (image.type == ET_DYN ? 1 : 0) ||
        (bytes != 1 && bytes != 2 && bytes != 4 && bytes != 8) ||
        address.value > UINT64_MAX - bytes)
      return std::nullopt;
    const Segment *segment = nullptr;
    for (const auto &s : image.segments)
      if ((s.flags & PF_R) && address.value >= s.address &&
          address.value - s.address <= s.file_size &&
          bytes <= s.file_size - (address.value - s.address)) {
        bool immutable = !(s.flags & PF_W);
        for (const auto &r : image.metadata)
          if (r.type == PT_GNU_RELRO && address.value >= r.address &&
              address.value - r.address <= r.memory_size &&
              bytes <= r.memory_size - (address.value - r.address))
            immutable = true;
        if (immutable) segment = &s;
      }
    if (!segment) return std::nullopt;
    std::uint64_t value = 0;
    std::memcpy(&value, image.bytes.data() + segment->offset + address.value - segment->address, bytes);
    Known result{value, UINT64_MAX, 0};
    bool applied = false;
    for (const auto &r : image.relocations) {
      if (!r.active_dynamic || !r.type) continue;
      const unsigned extent = r.type == R_X86_64_TLSDESC ? 16 : 8;
      if (r.offset >= address.value + bytes ||
          (address.value >= r.offset && address.value - r.offset >= extent)) continue;
      if (r.offset != address.value || bytes != 8 || applied) return std::nullopt;
      if (r.type == R_X86_64_RELATIVE) {
        result.value = r.explicit_addend ? std::uint64_t(r.addend) : value;
        result.bias = image.type == ET_DYN ? 1 : 0;
      } else if (r.type == R_X86_64_64 && r.explicit_addend &&
                 r.symbol_section != SHN_UNDEF && r.symbol_type != STT_GNU_IFUNC) {
        result.value = r.symbol_value + std::uint64_t(r.addend);
        result.bias = r.symbol_section != SHN_ABS && image.type == ET_DYN ? 1 : 0;
      } else return std::nullopt;
      applied = true;
      relocated[address.value] = llvm::json::Object{{"address", hex(address.value)},
          {"relocation_type", r.type}, {"value", hex(result.value)}, {"bias_coefficient", result.bias}};
    }
    read_addresses.insert(address.value);
    return result;
  };
  for (std::uint64_t trial = 0; trial <= *bound; trial++) {
    std::map<std::string, Known> values;
    values[index_reg->EnclosingRegister()->name] = {trial, mask(index->size),
                                                    0};
    const auto reg = [&](const std::string &name, const Inst &i) -> Known {
      if (name.empty())
        return {0, UINT64_MAX, 0};
      if (name == "PC" || name == "RIP" || name == "NEXT_PC")
        return {i.next_pc, UINT64_MAX, image.type == ET_DYN ? 1 : 0};
      const auto *r = arch.RegisterByName(name);
      if (!r)
        return {};
      const auto *root = r->EnclosingRegister();
      auto v = values[root->name];
      auto shift = unsigned((r->offset - root->offset) * 8),
           bits = unsigned(r->size * 8);
      if (shift >= 64 || bits > 64)
        return {};
      auto required = mask(bits);
      if (((v.mask >> shift) & required) != required ||
          (v.bias && (shift || bits < 64)))
        return {};
      return {(v.value >> shift) & required, UINT64_MAX, v.bias};
    };
    bool loaded = false;
    for (auto *i : chain) {
      std::vector<Known> reads;
      const Op *dst = nullptr;
      Known computed;
      bool has_computed = false;
      const auto n = llvm::StringRef(i->function);
      auto bits = width(*i);
      for (const auto &o : i->operands) {
        if (o.type == Op::kTypeRegister && o.action == Op::kActionWrite) {
          if (dst)
            return std::nullopt;
          dst = &o;
        } else if (o.action == Op::kActionRead && o.type == Op::kTypeRegister)
          reads.push_back(reg(o.reg.name, *i));
        else if (o.type == Op::kTypeImmediate)
          reads.push_back({o.imm.val, UINT64_MAX, 0});
        else if (o.type == Op::kTypeAddress) {
          if (o.action == Op::kActionWrite || i->segment_override)
            return std::nullopt;
          auto base = reg(o.addr.base_reg.name, *i),
               idx = reg(o.addr.index_reg.name, *i);
          if (base.mask != UINT64_MAX || idx.mask != UINT64_MAX)
            return std::nullopt;
          Known address{base.value + idx.value * o.addr.scale +
                            o.addr.displacement,
                        UINT64_MAX, base.bias + idx.bias * int(o.addr.scale)};
          if (n.starts_with("LEA_")) {
            computed = address;
            has_computed = true;
            continue;
          }
          if (!o.addr.IsMemoryAccess()) return std::nullopt;
          auto value = table_read(address, unsigned(o.size / 8));
          if (!value) return std::nullopt;
          if (n.starts_with("MOVSXD")) {
            if (value->bias) return std::nullopt;
            value->value = static_cast<std::int64_t>(static_cast<std::int32_t>(value->value));
          }
          reads.push_back(*value);
          loaded = true;
        }
      }
      if (i->category == Inst::kCategoryNoOp)
        continue;
      if (n.starts_with("MOV_") || n.starts_with("MOVSXD") ||
          n.starts_with("MOVZX")) {
        if (reads.size() != 1)
          return std::nullopt;
        computed = reads[0];
        has_computed = true;
      } else if (n.starts_with("ADD_") || n.starts_with("SUB_") ||
                 n.starts_with("AND_") || n.starts_with("OR_") ||
                 n.starts_with("XOR_")) {
        if (reads.size() != 2)
          return std::nullopt;
        if (reads[0].mask == UINT64_MAX && reads[1].mask == UINT64_MAX) {
          auto a = reads[0], b = reads[1];
          computed.mask = UINT64_MAX;
          if (n.starts_with("ADD_")) {
            computed.value = a.value + b.value;
            computed.bias = a.bias + b.bias;
          } else if (n.starts_with("SUB_")) {
            computed.value = a.value - b.value;
            computed.bias = a.bias - b.bias;
          } else {
            if (a.bias || b.bias)
              return std::nullopt;
            computed.value = n.starts_with("AND_")  ? (a.value & b.value)
                             : n.starts_with("OR_") ? (a.value | b.value)
                                                    : (a.value ^ b.value);
          }
        }
        has_computed = true;
      } else if (!n.starts_with("LEA_"))
        return std::nullopt;
      if (!dst || !has_computed)
        return std::nullopt;
      const auto *r = arch.RegisterByName(dst->reg.name);
      if (!r || r->EnclosingRegister()->size != 8)
        return std::nullopt;
      if (bits < 64 && computed.bias)
        return std::nullopt;
      if (computed.mask == UINT64_MAX)
        computed.value &= mask(bits);
      values[r->EnclosingRegister()->name] = computed;
    }
    Known target;
    if (target_address) {
      const auto &o = *target_address;
      if (terminal.segment_override) return std::nullopt;
      auto base = reg(o.addr.base_reg.name, terminal), index = reg(o.addr.index_reg.name, terminal);
      if (base.mask != UINT64_MAX || index.mask != UINT64_MAX) return std::nullopt;
      Known address{base.value + index.value * o.addr.scale + o.addr.displacement,
                    UINT64_MAX, base.bias + index.bias * int(o.addr.scale)};
      auto value = table_read(address, 8);
      if (!value) return std::nullopt;
      target = *value;
      loaded = true;
    } else target = reg(target_register, terminal);
    if (!loaded || target.mask != UINT64_MAX ||
        target.bias != (image.type == ET_DYN ? 1 : 0))
      return std::nullopt;
    result.targets.insert(target.value);
  }
  llvm::json::Array addresses, targets;
  for (auto address : read_addresses)
    addresses.push_back(hex(address));
  for (auto target : result.targets)
    targets.push_back(hex(target));
  llvm::json::Array relocation_evidence;
  for (auto &item : relocated) relocation_evidence.push_back(std::move(item.second));
  result.evidence = llvm::json::Object{
      {"relocation_backed_reads", std::move(relocation_evidence)},
      {"transfer_operand", target_address ? "memory" : "register"},
      {"guard_pc", hex(guard->pc)},
      {"compare_pc", hex(compare->pc)},
      {"index_register", index->reg.name},
      {"index_max", *bound},
      {"read_only_table_addresses", std::move(addresses)},
      {"targets", std::move(targets)},
      {"proof", "unsigned bound, finite value propagation, immutable/RELRO table, modeled relocations and "
                "unique-predecessor chain"}};
  return result;
}
} // namespace zvril
