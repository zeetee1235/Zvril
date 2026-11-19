#include "zvril/abi.h"
#include <algorithm>
#include <set>
#include <llvm/IR/IRBuilder.h>

namespace zvril {
namespace {
using llvm::json::Object;
using llvm::json::Value;
std::uint64_t align(std::uint64_t n, std::uint64_t a) {
  return (n + a - 1) & ~(a - 1);
}
AbiType type(const Value &value, bool returned, unsigned depth = 0) {
  if (depth > 8) throw Error("E_ABI_UNKNOWN", "Aggregate nesting exceeds eight levels");
  AbiType t;
  if (auto name = value.getAsString()) {
    t.name = name->str();
    if (t.name == "void" && returned)
      return t;
    if (t.name == "u64" || t.name == "i64" || t.name == "ptr" ||
        t.name == "f64")
      t.size = t.alignment = 8;
    else if (t.name == "u32" || t.name == "i32" || t.name == "f32")
      t.size = t.alignment = 4;
    else if (t.name == "u16" || t.name == "i16")
      t.size = t.alignment = 2;
    else if (t.name == "u8" || t.name == "i8")
      t.size = t.alignment = 1;
    else
      throw Error("E_ABI_UNKNOWN", "Unknown ABI scalar type");
    t.classes = {t.floating() ? AbiClass::Sse : AbiClass::Integer};
    t.defined.assign(t.size, 1);
    return t;
  }
  auto *object = value.getAsObject();
  auto *layout = object ? object->getObject("aggregate") : nullptr;
  if (!layout)
    throw Error("E_ABI_UNKNOWN",
                "Aggregate type needs an explicit aggregate layout");
  if (object->size() != 1)
    throw Error("E_ABI_UNKNOWN", "Unknown aggregate type field");
  for (const auto &field : *layout)
    if (!std::set<llvm::StringRef>{"size", "alignment", "classes", "fields", "defined_bytes", "pointer_offsets"}.contains(field.first))
      throw Error("E_ABI_UNKNOWN", "Unknown aggregate layout field: " + field.first.str());
  auto size = layout->getInteger("size"),
       alignment = layout->getInteger("alignment");
  auto *classes = layout->getArray("classes");
  auto *fields = layout->getArray("fields");
  if ((layout->get("fields") && !fields) ||
      (layout->get("classes") && !classes) ||
      (layout->get("defined_bytes") && !layout->getString("defined_bytes")) ||
      (layout->get("pointer_offsets") && !layout->getArray("pointer_offsets")))
    throw Error("E_ABI_UNKNOWN", "Invalid aggregate layout field type");
  if (!size || !alignment || *size <= 0 || *size > 4096 || *alignment <= 0 ||
      *alignment > 16 || (*alignment & (*alignment - 1)) ||
      (*size % *alignment) || (!classes && !fields))
    throw Error("E_ABI_UNKNOWN", "Invalid aggregate size/alignment/classes");
  t.aggregate = true;
  t.name = "aggregate";
  t.size = *size;
  t.alignment = *alignment;
  if (classes) for (const auto &c : *classes) {
    auto s = c.getAsString();
    if (!s)
      throw Error("E_ABI_UNKNOWN",
                  "Aggregate class must be INTEGER, SSE or MEMORY");
    if (*s == "INTEGER")
      t.classes.push_back(AbiClass::Integer);
    else if (*s == "SSE")
      t.classes.push_back(AbiClass::Sse);
    else if (*s == "MEMORY")
      t.classes.push_back(AbiClass::Memory);
    else if (*s == "NO_CLASS")
      t.classes.push_back(AbiClass::None);
    else
      throw Error("E_ABI_UNKNOWN", "Unsupported aggregate eightbyte class");
  }
  if (fields) {
    if (fields->empty() || fields->size() > 256)
      throw Error("E_ABI_UNKNOWN", "Aggregate fields must contain 1..256 entries");
    std::vector<AbiClass> inferred((t.size + 7) / 8, AbiClass::None);
    t.defined.assign(t.size, 0);
    std::vector<bool> occupied(t.size, false);
    bool memory = t.size > 16;
    const auto merge = [](AbiClass a, AbiClass b) {
      if (a == b || b == AbiClass::None) return a;
      if (a == AbiClass::None) return b;
      if (a == AbiClass::Integer || b == AbiClass::Integer) return AbiClass::Integer;
      return AbiClass::Sse;
    };
    for (const auto &v : *fields) {
      auto *field = v.getAsObject();
      if (!field || !field->getInteger("offset") || !field->get("type"))
        throw Error("E_ABI_UNKNOWN", "Aggregate field needs offset and type");
      for (const auto &property : *field)
        if (!std::set<llvm::StringRef>{"name", "offset", "type"}.contains(property.first))
          throw Error("E_ABI_UNKNOWN", "Unknown aggregate field property");
      auto offset = *field->getInteger("offset");
      auto child = type(*field->get("type"), false, depth + 1);
      if (offset < 0 || std::uint64_t(offset) > t.size || child.size > t.size - offset)
        throw Error("E_ABI_UNKNOWN", "Aggregate field exceeds its declared layout");
      memory |= child.memory() || std::uint64_t(offset) % child.alignment;
      for (unsigned j = 0; j < child.size; j++) {
        if (occupied[offset + j])
          throw Error("E_ABI_UNKNOWN", "Overlapping struct fields; declare union classification explicitly");
        occupied[offset + j] = true;
        t.defined[offset + j] = child.defined[j];
        if (!child.memory() && child.defined[j])
          inferred[(offset + j) / 8] = merge(inferred[(offset + j) / 8], child.classes[j / 8]);
      }
      if (child.name == "ptr") t.pointer_offsets.push_back(offset);
      else for (auto p : child.pointer_offsets) t.pointer_offsets.push_back(offset + p);
    }
    if (memory) inferred = {AbiClass::Memory};
    if (classes && inferred != t.classes)
      throw Error("E_ABI_UNKNOWN", "Declared classes disagree with field classification");
    t.classes = std::move(inferred);
  }
  if (t.classes.empty() || (t.memory() && t.classes.size() != 1) ||
      (!t.memory() && (t.size > 16 || t.classes.size() != (t.size + 7) / 8 ||
                       std::find(t.classes.begin(), t.classes.end(),
                                 AbiClass::Memory) != t.classes.end())))
    throw Error("E_ABI_UNKNOWN", "Aggregate classes do not describe its size");
  for (std::size_t i = 0; i < t.classes.size() && !t.memory(); i++)
    if (t.classes[i] == AbiClass::Sse &&
        std::min<std::uint64_t>(8, t.size - i * 8) != 4 &&
        std::min<std::uint64_t>(8, t.size - i * 8) != 8)
      throw Error("E_ABI_UNKNOWN",
                  "SSE eightbytes need four or eight payload bytes");
  if (!fields) t.defined.assign(t.size, 1);
  if (auto mask = layout->getString("defined_bytes")) {
    if (mask->size() != t.size)
      throw Error("E_ABI_UNKNOWN",
                  "defined_bytes must have one 0/1 character per byte");
    for (unsigned i = 0; i < t.size; i++) {
      if ((*mask)[i] != '0' && (*mask)[i] != '1')
        throw Error("E_ABI_UNKNOWN", "Invalid defined-byte mask");
      t.defined[i] = (*mask)[i] == '1';
    }
  }
  if (auto *pointers = layout->getArray("pointer_offsets")) {
    t.pointer_offsets.clear();
    for (const auto &p : *pointers) {
      auto n = p.getAsInteger();
      if (!n || *n < 0 || std::uint64_t(*n) > t.size || t.size - *n < 8)
        throw Error("E_ABI_UNKNOWN", "Invalid aggregate pointer slot");
      t.pointer_offsets.push_back(*n);
    }
  }
  bool has_data = false;
  for (unsigned j = 0; j < t.classes.size() && !t.memory(); j++) {
    has_data |= t.classes[j] != AbiClass::None;
    if (t.classes[j] == AbiClass::None)
      for (unsigned i = j * 8; i < std::min<std::uint64_t>(t.size, j * 8 + 8); i++)
        if (t.defined[i]) throw Error("E_ABI_UNKNOWN", "NO_CLASS eightbyte has defined payload");
  }
  if (!t.memory() && !has_data) throw Error("E_ABI_UNKNOWN", "Empty aggregate register classification");
  auto pointers = t.pointer_offsets;
  std::sort(pointers.begin(), pointers.end());
  for (unsigned i = 1; i < pointers.size(); i++)
    if (pointers[i] - pointers[i - 1] < 8)
      throw Error("E_ABI_UNKNOWN", "Overlapping aggregate pointer slots");
  return t;
}
llvm::Type *scalar(llvm::LLVMContext &c, const AbiType &t) {
  if (t.name == "void")
    return llvm::Type::getVoidTy(c);
  if (t.name == "ptr")
    return llvm::PointerType::get(c, 0);
  if (t.name == "f64")
    return llvm::Type::getDoubleTy(c);
  if (t.name == "f32")
    return llvm::Type::getFloatTy(c);
  return llvm::Type::getIntNTy(c, t.size * 8);
}
llvm::Type *piece(llvm::LLVMContext &c, const AbiType &t, unsigned j) {
  if (t.classes[j] == AbiClass::Integer)
    return llvm::Type::getInt64Ty(c);
  return t.size - j * 8 >= 8 ? llvm::Type::getDoubleTy(c)
                             : llvm::Type::getFloatTy(c);
}
} // namespace
AbiSignature parse_abi(const Object &object) {
  AbiSignature s;
  for (const auto &field : object)
    if (!std::set<llvm::StringRef>{"return", "arguments", "globals", "return_comparison", "variadic", "fixed_arguments"}.contains(field.first))
      throw Error("E_ABI_UNKNOWN", "Unknown ABI signature field: " + field.first.str());
  auto *result = object.get("return");
  auto *arguments = object.getArray("arguments");
  if (!result || !arguments || arguments->size() > 32)
    throw Error("E_ABI_UNKNOWN",
                "Explicit ABI return and at most 32 arguments required");
  s.result = type(*result, true);
  s.aggregate = s.result.aggregate;
  for (const auto &value : *arguments) {
    s.arguments.push_back(type(value, false));
    s.aggregate |= s.arguments.back().aggregate;
  }
  if (object.get("variadic") && !object.getBoolean("variadic"))
    throw Error("E_ABI_UNKNOWN", "variadic must be boolean");
  s.variadic = object.getBoolean("variadic").value_or(false);
  s.fixed = s.arguments.size();
  if (s.variadic) {
    auto fixed = object.getInteger("fixed_arguments");
    if (!fixed || *fixed < 0 || std::uint64_t(*fixed) > s.arguments.size())
      throw Error("E_ABI_UNKNOWN", "Invalid fixed_arguments");
    s.fixed = *fixed;
    for (unsigned i = s.fixed; i < s.arguments.size(); i++)
      if (s.arguments[i].name == "f32" || s.arguments[i].narrow_integer())
        throw Error("E_ABI_UNKNOWN", "Promote variadic f32 to f64 and narrow integers to i32/u32");
  } else if (object.get("fixed_arguments"))
    throw Error("E_ABI_UNKNOWN", "fixed_arguments requires variadic=true");
  s.gpr_used = s.result.memory() ? 1 : 0;
  for (const auto &t : s.arguments) {
    AbiLocation location;
    unsigned gp = 0, fp = 0;
    for (auto c : t.classes) {
      gp += c == AbiClass::Integer;
      fp += c == AbiClass::Sse;
    }
    if (t.memory() || gp + s.gpr_used > 6 || fp + s.sse_used > 8) {
      location.stack = true;
      location.offset =
          align(s.stack_bytes, std::max<std::uint64_t>(8, t.alignment));
      s.stack_bytes = location.offset + align(t.size, 8);
    } else
      for (auto c : t.classes)
        location.registers.push_back(c == AbiClass::None ? unsigned(-1) :
                                     c == AbiClass::Integer ? s.gpr_used++ : s.sse_used++);
    s.locations.push_back(std::move(location));
  }
  if (s.stack_bytes > 32768)
    throw Error("E_RESOURCE_LIMIT", "ABI stack arguments exceed 32 KiB", 1);
  return s;
}
void emit_native_packet_adapter(llvm::Module &m, const AbiSignature &s) {
  using namespace llvm;
  auto &c = m.getContext();
  auto *ptr = PointerType::get(c, 0);
  auto *i64 = Type::getInt64Ty(c);
  auto *i8 = Type::getInt8Ty(c);
  auto *f =
      llvm::Function::Create(FunctionType::get(i64, {ptr, ptr}, false),
                       GlobalValue::ExternalLinkage, "zvril_native_adapter", m);
  IRBuilder<> b(BasicBlock::Create(c, "entry", f));
  std::vector<Type *> types;
  std::vector<llvm::Value *> args;
  std::vector<std::pair<unsigned, bool>> extensions;
  struct Byval {
    unsigned index;
    ArrayType *type;
    std::uint64_t alignment;
  };
  std::vector<Byval> byvals;
  if (s.result.memory()) {
    types.push_back(ptr);
    args.push_back(f->getArg(1));
  }
  unsigned fixed_types = s.result.memory() ? 1 : 0;
  for (unsigned i = 0; i < s.arguments.size(); i++) {
    const auto &t = s.arguments[i];
    auto *raw = b.CreateLoad(i64, b.CreateConstGEP1_64(i64, f->getArg(0), i));
    if (!t.aggregate) {
      if (t.narrow_integer()) extensions.emplace_back(args.size(), t.signed_integer());
      auto *ty = scalar(c, t);
      llvm::Value *value = raw;
      if (ty->isPointerTy())
        value = b.CreateIntToPtr(raw, ptr);
      else if (ty->isFloatTy())
        value = b.CreateBitCast(b.CreateTrunc(raw, b.getInt32Ty()), ty);
      else if (ty->isDoubleTy())
        value = b.CreateBitCast(raw, ty);
      else
        value = b.CreateZExtOrTrunc(raw, ty);
      types.push_back(ty);
      args.push_back(value);
    } else {
      auto *data = b.CreateIntToPtr(raw, ptr);
      if (s.locations[i].stack) {
        auto *ty = ArrayType::get(i8, t.size);
        byvals.push_back({unsigned(args.size()), ty, t.alignment});
        types.push_back(ptr);
        args.push_back(data);
      } else
        for (unsigned j = 0; j < t.classes.size(); j++) {
          if (t.classes[j] == AbiClass::None) continue;
          auto *ty = piece(c, t, j);
          auto *slot = b.CreateAlloca(i64);
          b.CreateStore(b.getInt64(0), slot);
          b.CreateMemCpy(slot, MaybeAlign(1),
                         b.CreateConstGEP1_64(i8, data, j * 8), MaybeAlign(1),
                         std::min<std::uint64_t>(8, t.size - j * 8));
          args.push_back(b.CreateLoad(ty, slot));
          types.push_back(ty);
        }
    }
    if (i + 1 == s.fixed)
      fixed_types = types.size();
  }
  Type *result = nullptr;
  if (!s.result.aggregate)
    result = scalar(c, s.result);
  else if (s.result.memory())
    result = Type::getVoidTy(c);
  else {
    std::vector<Type *> pieces;
    for (unsigned j = 0; j < s.result.classes.size(); j++)
      if (s.result.classes[j] != AbiClass::None) pieces.push_back(piece(c, s.result, j));
    result = pieces.size() == 1 ? pieces[0] : StructType::get(c, pieces);
  }
  auto *target = b.CreateIntToPtr(
      b.CreateLoad(i64,
                   b.CreateConstGEP1_64(i64, f->getArg(0), s.arguments.size())),
      ptr);
  auto fixed = types;
  if (s.variadic)
    fixed.resize(fixed_types);
  auto *returned =
      b.CreateCall(FunctionType::get(result, fixed, s.variadic), target, args);
  for (const auto &[index, sign] : extensions)
    returned->addParamAttr(index, sign ? Attribute::SExt : Attribute::ZExt);
  if (s.result.narrow_integer())
    returned->addRetAttr(s.result.signed_integer() ? Attribute::SExt : Attribute::ZExt);
  for (const auto &a : byvals) {
    returned->addParamAttr(a.index, Attribute::getWithByValType(c, a.type));
    returned->addParamAttr(a.index,
                           Attribute::getWithAlignment(c, Align(a.alignment)));
  }
  if (s.result.memory()) {
    returned->addParamAttr(0, Attribute::getWithStructRetType(
                                  c, ArrayType::get(i8, s.result.size)));
    returned->addParamAttr(
        0, Attribute::getWithAlignment(c, Align(s.result.alignment)));
  }
  if (s.result.aggregate) {
    unsigned result_pieces = 0;
    for (auto c : s.result.classes) result_pieces += c != AbiClass::None;
    unsigned returned_index = 0;
    if (!s.result.memory())
      for (unsigned j = 0; j < s.result.classes.size(); j++) {
        if (s.result.classes[j] == AbiClass::None) continue;
        llvm::Value *v = result_pieces == 1
                             ? static_cast<llvm::Value *>(returned)
                             : b.CreateExtractValue(returned, returned_index++);
        auto *slot = b.CreateAlloca(v->getType());
        b.CreateStore(v, slot);
        b.CreateMemCpy(b.CreateConstGEP1_64(i8, f->getArg(1), j * 8),
                       MaybeAlign(1), slot, MaybeAlign(1),
                       std::min<std::uint64_t>(8, s.result.size - j * 8));
      }
    b.CreateRet(b.getInt64(0));
  } else if (s.result.name == "void")
    b.CreateRet(b.getInt64(0));
  else if (s.result.name == "ptr")
    b.CreateRet(b.CreatePtrToInt(returned, i64));
  else if (s.result.floating())
    b.CreateRet(b.CreateZExtOrTrunc(
        b.CreateBitCast(returned, Type::getIntNTy(c, s.result.size * 8)), i64));
  else
    b.CreateRet(b.CreateZExtOrTrunc(returned, i64));
}
} // namespace zvril
