#pragma once
#include "zvril/elf/image.h"
#include <llvm/IR/Module.h>
#include <llvm/Support/JSON.h>
namespace zvril {
enum class AbiClass { Integer, Sse, Memory, None };
struct AbiType {
  std::string name;
  std::uint64_t size = 0, alignment = 1;
  std::vector<AbiClass> classes;
  std::vector<std::uint8_t> defined;
  std::vector<std::uint64_t> pointer_offsets;
  bool aggregate = false;
  bool narrow_integer() const { return !aggregate && size && size < 4; }
  bool signed_integer() const { return name.starts_with('i'); }
  bool floating() const { return name == "f32" || name == "f64"; }
  bool memory() const {
    return !classes.empty() && classes[0] == AbiClass::Memory;
  }
};
struct AbiLocation {
  bool stack = false;
  std::uint64_t offset = 0;
  std::vector<unsigned> registers;
};
struct AbiSignature {
  AbiType result;
  std::vector<AbiType> arguments;
  bool variadic = false, aggregate = false;
  unsigned fixed = 0, gpr_used = 0, sse_used = 0;
  std::uint64_t stack_bytes = 0;
  std::vector<AbiLocation> locations;
};
AbiSignature parse_abi(const llvm::json::Object &signature);
void emit_native_packet_adapter(llvm::Module &, const AbiSignature &);
} // namespace zvril
