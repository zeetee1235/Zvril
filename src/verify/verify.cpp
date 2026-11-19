#include "zvril/verify.h"
#include "zvril/abi.h"
#include "zvril/native_trace.h"
#include "zvril/runtime.h"
#include <algorithm>
#include <array>
#include <charconv>
#include <chrono>
#include <cmath>
#include <cstring>
#include <dlfcn.h>
#include <fcntl.h>
#include <fstream>
#include <link.h>
#include <llvm/ExecutionEngine/ExecutionEngine.h>
#include <llvm/ExecutionEngine/MCJIT.h>
#include <llvm/ExecutionEngine/SectionMemoryManager.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/InlineAsm.h>
#include <llvm/IRReader/IRReader.h>
#include <llvm/Support/DynamicLibrary.h>
#include <llvm/Support/FormatVariadic.h>
#include <llvm/Support/JSON.h>
#include <llvm/Support/SHA256.h>
#include <llvm/Support/SourceMgr.h>
#include <llvm/Support/TargetSelect.h>
#include <map>
#include <poll.h>
#include <set>
#include <signal.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/ucontext.h>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>

namespace zvril {
namespace {
using llvm::json::Array;
using llvm::json::Object;
using llvm::json::Value;
std::string text_file(const std::filesystem::path &p) {
  std::error_code e;
  auto size = std::filesystem::file_size(p, e);
  if (e || size > 16 * 1024 * 1024)
    throw Error("E_CASES",
                "Cases/artifact file exceeds 16 MiB or cannot be read");
  std::ifstream f(p, std::ios::binary);
  if (!f)
    throw Error("E_CASES", "Cannot open cases/artifact");
  return {std::istreambuf_iterator<char>(f), {}};
}
Value json(const std::string &s) {
  auto v = llvm::json::parse(s);
  if (!v)
    throw Error("E_CASES", llvm::toString(v.takeError()));
  return std::move(*v);
}
std::string digest(const std::string &s) {
  auto d = llvm::SHA256::hash(
      {reinterpret_cast<const std::uint8_t *>(s.data()), s.size()});
  std::string out;
  constexpr char chars[] = "0123456789abcdef";
  for (auto v : d) {
    out += chars[v >> 4];
    out += chars[v & 15];
  }
  return out;
}
std::uint64_t integer(const Value &v) {
  if (auto n = v.getAsUINT64())
    return *n;
  if (auto n = v.getAsInteger())
    return static_cast<std::uint64_t>(*n);
  if (auto s = v.getAsString()) {
    std::uint64_t n = 0;
    auto t = *s;
    int base = 10;
    if (t.starts_with("0x")) {
      t = t.drop_front(2);
      base = 16;
    }
    auto r = std::from_chars(t.data(), t.data() + t.size(), n, base);
    if (!t.empty() && r.ec == std::errc() && r.ptr == t.end())
      return n;
  }
  throw Error("E_CASES", "Expected an integer or hexadecimal string");
}
std::string hex(std::uint64_t n) { return llvm::formatv("{0:x}", n).str(); }
std::string encode(const std::vector<std::uint8_t> &data) {
  std::string out;
  constexpr char c[] = "0123456789abcdef";
  for (auto v : data) {
    out += c[v >> 4];
    out += c[v & 15];
  }
  return out;
}
std::vector<std::uint8_t> decode(llvm::StringRef s) {
  if (s.size() % 2 || s.size() > 128 * 1024)
    throw Error("E_CASES", "Invalid buffer hex length");
  std::vector<std::uint8_t> result;
  const auto digit = [](char c) {
    if (c >= '0' && c <= '9')
      return c - '0';
    if (c >= 'a' && c <= 'f')
      return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
      return c - 'A' + 10;
    throw Error("E_CASES", "Invalid hex digit");
  };
  for (std::size_t i = 0; i < s.size(); i += 2)
    result.push_back((digit(s[i]) << 4) | digit(s[i + 1]));
  return result;
}
struct Buffer {
  struct PointerSlot {
    std::uint64_t offset;
    std::string target;
    std::uint64_t target_offset;
  };
  std::vector<PointerSlot> pointers;
  std::string name;
  std::vector<std::uint8_t> bytes;
  unsigned permissions = 3;
  std::uint64_t guest = 0;
};
struct Case {
  unsigned rep_fault_restore_mask = 3;
  bool trace = false;
  bool native_trace = false, has_initial = false;
  std::array<std::uint64_t, 17> initial{};
  std::uint64_t initial_flags = 0, image_bias = 0, return_pc = 0;
  std::vector<std::uint8_t> initial_xmm;
  std::uint32_t initial_mxcsr = 0;
  struct Snapshot {
    std::uint64_t address;
    std::vector<std::uint8_t> bytes;
    bool image;
  };
  std::vector<Snapshot> snapshots;
  std::vector<Value> arguments;
  std::vector<Buffer> buffers;
  std::string id;
};
struct Contract {
  AbiSignature abi;
  bool variadic = false;
  unsigned fixed_arguments = 0;
  std::string comparison = "bits";
  std::string result;
  std::vector<std::string> arguments, globals;
};
bool supported(const std::string &t, bool result) {
  return t == "u64" || t == "i64" || t == "u32" || t == "i32" || t == "f64" ||
         t == "f32" || t == "ptr" || t == "u8" || t == "i8" || t == "u16" ||
         t == "i16" || (result && t == "void");
}
Contract contract(const Object &o) {
  Contract c;
  auto *signature = o.getObject("signature");
  if (!signature)
    throw Error("E_ABI_UNKNOWN", "An explicit signature is required");
  for (const auto &pair : *signature)
    if (!std::set<llvm::StringRef>{"return", "arguments", "globals",
                                   "return_comparison", "variadic",
                                   "fixed_arguments"}
             .contains(pair.first))
      throw Error("E_ABI_UNKNOWN",
                  "Unknown signature field: " + pair.first.str());
  if (!signature->get("return"))
    throw Error("E_ABI_UNKNOWN", "Explicit return type is required");
  c.abi = parse_abi(*signature);
  c.result = c.abi.result.name;
  c.comparison =
      signature->getString("return_comparison").value_or("bits").str();
  if (c.comparison != "bits" && (c.comparison != "sign" || c.result != "i32"))
    throw Error(
        "E_ABI_UNKNOWN",
        "Return comparison must be bits, or sign for an explicit i32 contract");
  auto *arguments = signature->getArray("arguments");
  if ((!supported(c.result, true) && c.result != "aggregate") || !arguments ||
      arguments->size() > 32)
    throw Error("E_ABI_UNKNOWN", "Unsupported explicit signature");
  for (const auto &type : c.abi.arguments)
    c.arguments.push_back(type.name);
  if (signature->get("variadic") && !signature->getBoolean("variadic"))
    throw Error("E_ABI_UNKNOWN", "variadic must be boolean");
  c.variadic = signature->getBoolean("variadic").value_or(false);
  c.fixed_arguments = c.arguments.size();
  if (c.variadic) {
    auto fixed = signature->getInteger("fixed_arguments");
    if (!fixed || *fixed < 0 || std::uint64_t(*fixed) > c.arguments.size())
      throw Error("E_ABI_UNKNOWN",
                  "Variadic signature needs a valid fixed_arguments count");
    c.fixed_arguments = *fixed;
    for (unsigned i = c.fixed_arguments; i < c.arguments.size(); i++)
      if (c.arguments[i] == "f32")
        throw Error(
            "E_ABI_UNKNOWN",
            "Variadic float arguments require default promotion to f64");
  } else if (signature->get("fixed_arguments"))
    throw Error("E_ABI_UNKNOWN", "fixed_arguments requires variadic=true");
  if (auto *names = signature->getArray("globals")) {
    if (names->size() > 32)
      throw Error("E_ABI_UNKNOWN", "Too many global observations");
    for (const auto &name : *names) {
      auto n = name.getAsString();
      if (!n)
        throw Error("E_ABI_UNKNOWN", "Global name must be a string");
      c.globals.push_back(n->str());
    }
  }
  return c;
}
Case parse_case(const Object &o, std::size_t index, const Contract &signature) {
  Case c;
  c.id = o.getString("id").value_or("").str();
  if (c.id.empty())
    c.id = std::to_string(index);
  auto *args = o.getArray("arguments");
  if (!args || args->size() != signature.arguments.size())
    throw Error("E_CASES", "Argument count differs from contract");
  for (const auto &a : *args)
    c.arguments.push_back(a);
  if (auto *buffers = o.getObject("buffers")) {
    std::uint64_t total = 0;
    for (const auto &pair : *buffers) {
      auto *value = pair.second.getAsObject();
      if (!value)
        throw Error("E_CASES", "Buffer must be an object");
      Buffer b;
      b.name = pair.first.str();
      b.bytes = decode(value->getString("hex").value_or(""));
      auto n = value->getInteger("size").value_or(b.bytes.size());
      if (n < 0 || n > 65536 || std::uint64_t(n) < b.bytes.size())
        throw Error("E_CASES", "Invalid buffer size");
      b.bytes.resize(n);
      if (auto *slots = value->getObject("pointers"))
        for (const auto &pair : *slots) {
          auto offset = integer(Value(pair.first.str()));
          auto *ref = pair.second.getAsObject();
          if (!ref || !ref->getString("buffer") || offset > b.bytes.size() ||
              b.bytes.size() - offset < 8)
            throw Error("E_CASES", "Invalid pointer slot");
          b.pointers.push_back(
              {offset, ref->getString("buffer")->str(),
               ref->get("offset") ? integer(*ref->get("offset")) : 0});
        }
      total += n;
      if (total > 256 * 1024 || c.buffers.size() >= 16)
        throw Error("E_CASES", "Case memory budget exceeded");
      auto p = value->getString("permissions").value_or("rw");
      if (p != "r" && p != "rw")
        throw Error("E_CASES", "Buffer permissions must be r or rw");
      b.permissions = p == "r" ? 1 : 3;
      c.buffers.push_back(std::move(b));
    }
  }
  std::sort(c.buffers.begin(), c.buffers.end(),
            [](const auto &a, const auto &b) { return a.name < b.name; });
  for (std::size_t i = 0; i < c.buffers.size(); i++)
    c.buffers[i].guest = UINT64_C(0x50000000) + i * UINT64_C(0x100000);
  return c;
}
std::uint64_t scalar(const Value &a, const std::string &type) {
  if (type == "f64" || type == "f32") {
    auto n = a.getAsNumber();
    if (!n || !std::isfinite(*n))
      throw Error("E_CASES", "Floating argument must be finite");
    std::uint64_t bits = 0;
    if (type == "f64") {
      double d = *n;
      std::memcpy(&bits, &d, 8);
    } else {
      float f = *n;
      std::memcpy(&bits, &f, 4);
    }
    return bits;
  }
  auto n = integer(a);
  if (type == "i32" || type == "u32")
    n = std::uint32_t(n);
  if (type == "u8")
    n = std::uint8_t(n);
  if (type == "u16")
    n = std::uint16_t(n);
  if (type == "i8")
    n = std::uint32_t(std::int32_t(std::int8_t(n)));
  if (type == "i16")
    n = std::uint32_t(std::int32_t(std::int16_t(n)));
  return n;
}
using Entry = std::uint64_t (*)(std::uint64_t *, void *);
struct Engine {
  std::set<std::uint64_t> pcs;
  llvm::LLVMContext context;
  std::unique_ptr<llvm::ExecutionEngine> engine;
  Entry native = nullptr;
  std::map<std::string, std::pair<std::uint64_t, std::uint64_t>> registers;
  Engine(const std::filesystem::path &bitcode, const Contract &signature,
         bool native_trace = false) {
    auto pcmap = json(text_file(bitcode.parent_path() / "pcmap.json"));
    for (const auto &row : *pcmap.getAsObject()->getArray("instructions"))
      pcs.insert(integer(*row.getAsObject()->get("pc")));
    auto layout = json(text_file(bitcode.parent_path() / "state_layout.json"));
    for (const auto &row : *layout.getAsObject()->getArray("registers")) {
      auto *object = row.getAsObject();
      registers.emplace(object->getString("name").value_or("").str(),
                        std::pair{integer(*object->get("offset")),
                                  integer(*object->get("bytes"))});
    }
    llvm::InitializeNativeTarget();
    llvm::InitializeNativeTargetAsmPrinter();
    llvm::InitializeNativeTargetAsmParser();
    llvm::sys::DynamicLibrary::LoadLibraryPermanently(nullptr);
    llvm::SMDiagnostic diagnostic;
    auto m = llvm::parseIRFile(bitcode.string(), diagnostic, context);
    if (!m)
      throw Error("E_LLVM_VERIFY", diagnostic.getMessage().str(), 2);
    using namespace llvm;
    auto *i64 = Type::getInt64Ty(context);
    auto *ptr = PointerType::get(context, 0);
    const auto type = [&](const std::string &t) -> Type * {
      if (t == "void")
        return Type::getVoidTy(context);
      if (t == "f64")
        return Type::getDoubleTy(context);
      if (t == "f32")
        return Type::getFloatTy(context);
      if (t == "ptr")
        return ptr;
      if (t == "i32" || t == "u32")
        return Type::getInt32Ty(context);
      if (t == "i16" || t == "u16")
        return Type::getInt16Ty(context);
      if (t == "i8" || t == "u8")
        return Type::getInt8Ty(context);
      return i64;
    };
    if (signature.abi.aggregate)
      emit_native_packet_adapter(*m, signature.abi);
    else {
      auto *adapter = llvm::Function::Create(
          FunctionType::get(i64, {ptr, ptr}, false),
          GlobalValue::ExternalLinkage, "zvril_native_adapter", *m);
      IRBuilder<> b(BasicBlock::Create(context, "entry", adapter));
      std::vector<Type *> types;
      std::vector<llvm::Value *> args;
      for (std::size_t i = 0; i < signature.arguments.size(); i++) {
        auto *t = type(signature.arguments[i]);
        types.push_back(t);
        auto *value = b.CreateLoad(i64, b.CreateGEP(i64, adapter->getArg(0),
                                                    ConstantInt::get(i64, i)));
        llvm::Value *v = value;
        if (t->isPointerTy())
          v = b.CreateIntToPtr(v, ptr);
        else if (t->isIntegerTy() && t->getIntegerBitWidth() < 64)
          v = b.CreateTrunc(v, t);
        else if (t->isFloatTy())
          v = b.CreateBitCast(b.CreateTrunc(v, Type::getInt32Ty(context)), t);
        else if (t->isDoubleTy())
          v = b.CreateBitCast(v, t);
        args.push_back(v);
      }
      auto *address = b.CreateLoad(
          i64, b.CreateGEP(i64, adapter->getArg(0),
                           ConstantInt::get(i64, signature.arguments.size())));
      auto *fn = b.CreateIntToPtr(address, ptr);
      if (native_trace)
        b.CreateCall(
            InlineAsm::get(FunctionType::get(Type::getVoidTy(context), false),
                           "int3", "", true));
      auto fixed_types = types;
      fixed_types.resize(signature.fixed_arguments);
      auto *returned =
          b.CreateCall(FunctionType::get(type(signature.result), fixed_types,
                                         signature.variadic),
                       fn, args);
      for (unsigned i = 0; i < signature.abi.arguments.size(); i++)
        if (signature.abi.arguments[i].narrow_integer())
          returned->addParamAttr(i, signature.abi.arguments[i].signed_integer()
                                        ? Attribute::SExt
                                        : Attribute::ZExt);
      if (signature.abi.result.narrow_integer())
        returned->addRetAttr(signature.abi.result.signed_integer()
                                 ? Attribute::SExt
                                 : Attribute::ZExt);
      llvm::Value *value = returned;
      if (signature.result == "void")
        value = ConstantInt::get(i64, 0);
      else if (signature.result == "ptr")
        value = b.CreatePtrToInt(value, i64);
      else if (signature.result == "f64")
        value = b.CreateBitCast(value, i64);
      else if (signature.result == "f32")
        value = b.CreateZExt(b.CreateBitCast(value, Type::getInt32Ty(context)),
                             i64);
      else if (returned->getType()->isIntegerTy() &&
               returned->getType()->getIntegerBitWidth() < 64)
        value = b.CreateZExt(value, i64);
      b.CreateRet(value);
    }
    std::string error;
    engine.reset(
        EngineBuilder(std::move(m))
            .setEngineKind(EngineKind::JIT)
            .setErrorStr(&error)
            .setMCJITMemoryManager(std::make_unique<SectionMemoryManager>())
            .create());
    if (!engine)
      throw Error("E_LLVM_JIT", error, 2);
    engine->finalizeObject();
    native = get<Entry>("zvril_native_adapter");
  }
  template <class F> F get(const char *name) {
    auto address = engine->getFunctionAddress(name);
    if (!address)
      throw Error("E_LLVM_JIT", std::string("Missing JIT symbol ") + name, 2);
    return reinterpret_cast<F>(address);
  }
};
static int signal_fd = -1;
static std::uintptr_t native_base = 0;
void signal_handler(int sig, siginfo_t *info, void *opaque) {
  auto *state = static_cast<ucontext_t *>(opaque);
  char data[1024];
  std::size_t at = 0;
  const auto literal = [&](const char *s) {
    while (*s)
      data[at++] = *s++;
  };
  const auto number = [&](std::uint64_t n) {
    char tmp[32];
    unsigned count = 0;
    do {
      tmp[count++] = char('0' + n % 10);
      n /= 10;
    } while (n);
    while (count)
      data[at++] = tmp[--count];
  };
  literal("{\"kind\":\"signal\",\"signal\":");
  number(sig);
  literal(",\"pc\":");
  number(state->uc_mcontext.gregs[REG_RIP] - native_base);
  literal(",\"address\":");
  number(reinterpret_cast<std::uintptr_t>(info->si_addr));
  literal(",\"fault_state\":{\"address_space\":\"native\",\"gpr\":[");
  const int registers[] = {REG_RAX, REG_RCX, REG_RDX, REG_RBX, REG_RSP, REG_RBP,
                           REG_RSI, REG_RDI, REG_R8,  REG_R9,  REG_R10, REG_R11,
                           REG_R12, REG_R13, REG_R14, REG_R15, REG_RIP};
  for (unsigned i = 0; i < 17; i++) {
    if (i)
      literal(",");
    number(state->uc_mcontext.gregs[registers[i]]);
  }
  literal("],\"flags\":");
  number(state->uc_mcontext.gregs[REG_EFL]);
  literal("}}");
  (void)!write(signal_fd, data, at);
  _exit(128 + sig);
}
Object observed(Engine &engine, const Image &image,
                const std::filesystem::path &original, const Case &input,
                const Contract &signature, const std::string &symbol,
                std::uint64_t entry, bool native, std::uint64_t timeout,
                NativeTrace *tracer) {
  if (native && tracer)
    tracer->enable_child();
  const std::uint64_t guest_bias =
      input.has_initial ? input.image_bias
                        : (image.type == 3 ? UINT64_C(0x4000000000) : 0);
  using Create = ZvrilRuntime *(*)(std::uint64_t, std::uint64_t);
  using Destroy = void (*)(ZvrilRuntime *);
  using Init = int (*)(ZvrilRuntime *, std::uint64_t);
  using Map = int (*)(ZvrilRuntime *, std::uint64_t, std::uint64_t, unsigned,
                      const void *, std::uint64_t, int);
  using Read = int (*)(ZvrilRuntime *, std::uint64_t, void *, std::uint64_t);
  using Write =
      int (*)(ZvrilRuntime *, std::uint64_t, const void *, std::uint64_t);
  using Status = ZvrilMemory *(*)(ZvrilRuntime *);
  using Set = void (*)(void *, std::uint32_t, std::uint64_t);
  using Get = std::uint64_t (*)(void *, std::uint32_t);
  std::vector<std::vector<std::uint8_t>> buffers;
  for (const auto &b : input.buffers)
    buffers.push_back(b.bytes);
  std::vector<void *> mappings;
  std::vector<std::size_t> mapping_sizes;
  std::vector<std::uint8_t *> native_buffers;
  if (native)
    for (const auto &buffer : buffers) {
      auto rounded = ((buffer.size() + 4095) / 4096) * 4096;
      if (!rounded)
        rounded = 4096;
      void *memory = mmap(nullptr, rounded + 8192, PROT_NONE,
                          MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
      if (memory == MAP_FAILED)
        throw Error("E_RESOURCE_LIMIT", "Cannot allocate guarded buffer", 1);
      auto *start = static_cast<std::uint8_t *>(memory) + 4096;
      mprotect(start, rounded, PROT_READ | PROT_WRITE);
      auto *data = start + rounded - buffer.size();
      if (!buffer.empty())
        std::memcpy(data, buffer.data(), buffer.size());
      mappings.push_back(memory);
      mapping_sizes.push_back(rounded + 8192);
      native_buffers.push_back(data);
    }
  for (std::size_t i = 0; i < input.buffers.size(); i++) {
    for (const auto &p : input.buffers[i].pointers) {
      auto found =
          std::find_if(input.buffers.begin(), input.buffers.end(),
                       [&](const auto &b) { return b.name == p.target; });
      if (found == input.buffers.end() || p.target_offset > found->bytes.size())
        throw Error("E_CASES", "Invalid pointer slot target");
      const auto index = std::size_t(found - input.buffers.begin());
      std::uint64_t address =
          (native ? reinterpret_cast<std::uint64_t>(native_buffers[index])
                  : found->guest) +
          p.target_offset;
      std::memcpy(buffers[i].data() + p.offset, &address, 8);
    }
    if (native) {
      if (!buffers[i].empty())
        std::memcpy(native_buffers[i], buffers[i].data(), buffers[i].size());
      if (input.buffers[i].permissions == 1)
        mprotect(static_cast<std::uint8_t *>(mappings[i]) + 4096,
                 mapping_sizes[i] - 8192, PROT_READ);
    }
  }
  std::vector<std::uint64_t> arguments;
  std::vector<std::vector<std::uint8_t>> aggregate_arguments(
      signature.arguments.size());
  std::vector<std::uint8_t> return_bytes(
      std::max<std::uint64_t>(1, signature.abi.result.size), 0);
  Object result{{"kind", "normal"}};
  const auto arg = [&](std::size_t index) {
    const auto &value = input.arguments[index];
    const auto &type = signature.arguments[index];
    if (type == "aggregate")
      return reinterpret_cast<std::uint64_t>(aggregate_arguments[index].data());
    if (type != "ptr")
      return scalar(value, type);
    auto *ref = value.getAsObject();
    if (!ref) {
      if (integer(value) == 0)
        return std::uint64_t(0);
      throw Error("E_ABI_UNKNOWN",
                  "Pointer arguments must name a buffer or be null");
    }
    auto name = ref->getString("buffer");
    if (!name)
      throw Error("E_CASES", "Pointer argument lacks buffer");
    for (std::size_t i = 0; i < input.buffers.size(); i++)
      if (input.buffers[i].name == *name) {
        auto offset = ref->getInteger("offset").value_or(0);
        if (offset < 0 ||
            static_cast<std::uint64_t>(offset) > input.buffers[i].bytes.size())
          throw Error(
              "E_CASES",
              "Pointer argument offset lies outside its declared buffer");
        return (native ? reinterpret_cast<std::uint64_t>(native_buffers[i])
                       : input.buffers[i].guest) +
               offset;
      }
    throw Error("E_CASES", "Unknown buffer reference");
  };
  for (unsigned i = 0; i < signature.abi.arguments.size(); i++)
    if (signature.abi.arguments[i].aggregate) {
      const auto &t = signature.abi.arguments[i];
      auto *packet = input.arguments[i].getAsObject();
      if (!packet)
        throw Error("E_CASES", "Aggregate arguments must be byte packets");
      auto data = decode(packet->getString("hex").value_or(""));
      if (data.size() > t.size)
        throw Error("E_CASES", "Aggregate packet exceeds its layout");
      data.resize(t.size);
      for (auto offset : t.pointer_offsets) {
        const auto *refs = packet->getObject("pointers");
        const auto *reference =
            refs ? refs->get(std::to_string(offset)) : nullptr;
        std::uint64_t address = 0;
        std::memcpy(&address, data.data() + offset, 8);
        if (reference) {
          auto *ref = reference->getAsObject();
          if (!ref || !ref->getString("buffer"))
            throw Error("E_CASES",
                        "Aggregate pointer needs a buffer reference");
          bool found = false;
          for (unsigned j = 0; j < input.buffers.size(); j++)
            if (input.buffers[j].name == *ref->getString("buffer")) {
              auto at = ref->getInteger("offset").value_or(0);
              if (at < 0 || std::uint64_t(at) > input.buffers[j].bytes.size())
                throw Error("E_CASES",
                            "Aggregate pointer offset exceeds its buffer");
              address =
                  (native ? reinterpret_cast<std::uint64_t>(native_buffers[j])
                          : input.buffers[j].guest) +
                  at;
              found = true;
              break;
            }
          if (!found)
            throw Error("E_CASES", "Unknown aggregate pointer buffer");
        } else if (address)
          throw Error("E_CASES",
                      "Aggregate pointers must be named references or null");
        std::memcpy(data.data() + offset, &address, 8);
      }
      aggregate_arguments[i] = std::move(data);
    }
  for (std::size_t i = 0; i < input.arguments.size(); i++)
    arguments.push_back(arg(i));
  std::uint64_t value = 0;
  const auto observe_globals = [&](auto reader) {
    Object globals;
    for (const auto &name : signature.globals) {
      const Symbol *selected = nullptr;
      for (const auto &s : image.symbols)
        if (s.name == name && s.type == 1 && s.section) {
          if (selected &&
              (s.value != selected->value || s.size != selected->size))
            throw Error("E_ABI_UNKNOWN", "Ambiguous global: " + name, 1);
          selected = &s;
        }
      if (!selected || !selected->size || selected->size > 65536)
        throw Error("E_ABI_UNKNOWN", "Missing or oversized object: " + name, 1);
      std::vector<std::uint8_t> bytes(selected->size);
      reader(selected->value, bytes);
      globals[name] = encode(bytes);
    }
    result["globals"] = std::move(globals);
  };
  if (native) {
    restrict_worker(original, timeout);
    void *handle = dlopen(original.c_str(), RTLD_NOW | RTLD_LOCAL);
    if (!handle)
      throw Error(
          "E_NATIVE_LOAD",
          dlerror() ? "Native ELF load failed" : "Native ELF load failed", 1);
    link_map *loaded = nullptr;
    if (dlinfo(handle, RTLD_DI_LINKMAP, &loaded) || !loaded)
      throw Error("E_NATIVE_LOAD", "No native load bias", 1);
    native_base = loaded->l_addr;
    if (tracer) {
      std::vector<std::uint64_t> bases;
      for (auto *p : native_buffers)
        bases.push_back(reinterpret_cast<std::uint64_t>(p));
      tracer->metadata_child(native_base, bases);
    }
    std::uintptr_t address = 0;
    if (const auto at = symbol.find('@'); at != std::string::npos) {
      auto name = symbol.substr(0, at), version = symbol.substr(at + 1);
      if (version.starts_with('@'))
        version.erase(0, 1);
      address = reinterpret_cast<std::uintptr_t>(
          dlvsym(handle, name.c_str(), version.c_str()));
      if (!address)
        throw Error("E_NATIVE_LOAD", "Native symbol version was not found", 1);
    } else
      address = reinterpret_cast<std::uintptr_t>(dlsym(handle, symbol.c_str()));
    if (!address)
      address = loaded->l_addr + entry;
    arguments.push_back(address);
    const auto call_start = std::chrono::steady_clock::now();
    value = engine.native(arguments.data(), return_bytes.data());
    result["_execution_ns"] = static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::steady_clock::now() - call_start)
            .count());
    observe_globals([&](std::uint64_t at, std::vector<std::uint8_t> &bytes) {
      std::memcpy(bytes.data(),
                  reinterpret_cast<const void *>(native_base + at),
                  bytes.size());
    });
  } else {
    restrict_worker(original, timeout);
    auto create = engine.get<Create>("zvril_runtime_create");
    auto destroy = engine.get<Destroy>("zvril_runtime_destroy");
    auto *runtime = create(128 * 1024 * 1024, 1000000);
    if (!runtime)
      throw Error("E_RESOURCE_LIMIT", "Cannot allocate guest context", 1);
    engine.get<int (*)(ZvrilRuntime *, unsigned)>(
        "zvril_runtime_set_rep_fault_flags")(runtime,
                                             input.rep_fault_restore_mask);
    struct Cleanup {
      ZvrilRuntime *r;
      Destroy d;
      ~Cleanup() { d(r); }
    } cleanup{runtime, destroy};
    if (!engine.get<Init>("zvril_init_image")(runtime, guest_bias))
      throw Error("E_RELOCATION", "Guest image initialization failed", 1);
    auto map = engine.get<Map>("zvril_runtime_map");
    auto read = engine.get<Read>("zvril_runtime_read");
    auto write = engine.get<Write>("zvril_runtime_write");
    for (std::size_t i = 0; i < input.buffers.size(); i++) {
      const auto &b = input.buffers[i];
      if (!b.bytes.empty() &&
          !map(runtime, b.guest, b.bytes.size(), b.permissions,
               buffers[i].data(), b.bytes.size(), 1))
        throw Error("E_MEMORY_FAULT", "Cannot map case buffer", 1);
    }
    const std::uint64_t stack =
                            input.has_initial
                                ? ((input.initial[4] - 32768) & ~UINT64_C(4095))
                                : UINT64_C(0x7fff00000000),
                        sentinel = input.has_initial
                                       ? input.return_pc
                                       : UINT64_C(0xfffffffffffffff0);
    if (!map(runtime, stack, input.has_initial ? 131072 : 65536, 3, nullptr, 0,
             input.has_initial ? 0 : 1))
      throw Error("E_MEMORY_FAULT", "Cannot map stack", 1);
    if (input.has_initial) {
      auto protect =
          engine.get<int (*)(ZvrilRuntime *, std::uint64_t, std::uint64_t,
                             unsigned)>("zvril_runtime_protect");
      for (const auto &snapshot : input.snapshots) {
        if (snapshot.image &&
            !protect(runtime, snapshot.address, snapshot.bytes.size(), 3))
          throw Error("E_TRACE_PROTOCOL", "Cannot prepare guest image snapshot",
                      1);
        if (!write(runtime, snapshot.address, snapshot.bytes.data(),
                   snapshot.bytes.size()))
          throw Error("E_TRACE_PROTOCOL",
                      "Cannot replay native memory snapshot", 1);
      }
      for (const auto &segment : image.segments)
        if (segment.memory_size &&
            !protect(runtime, guest_bias + segment.address, segment.memory_size,
                     ((segment.flags & 4) ? 1 : 0) |
                         ((segment.flags & 2) ? 2 : 0) |
                         ((segment.flags & 1) ? 4 : 0)))
          throw Error("E_TRACE_PROTOCOL",
                      "Cannot restore guest image permissions", 1);
      for (const auto &segment : image.metadata)
        if (segment.type == PT_GNU_RELRO && segment.memory_size &&
            !protect(runtime, guest_bias + segment.address, segment.memory_size,
                     1))
          throw Error("E_TRACE_PROTOCOL", "Cannot restore RELRO permissions",
                      1);
    }
    auto *status = engine.get<Status>("zvril_runtime_status")(runtime);
    status->return_pc = sentinel;
    engine.get<void (*)(ZvrilRuntime *, std::uint64_t)>(
        "zvril_runtime_set_flags_valid")(runtime,
                                         input.has_initial ? 0xcd5 : 0x400);
    std::vector<std::uint8_t> state(
        engine.get<std::uint64_t (*)()>("zvril_state_size")(), 0);
    auto set = engine.get<Set>("zvril_state_set");
    auto get = engine.get<Get>("zvril_state_get");
    if (input.has_initial) {
      for (unsigned i = 0; i < 17; i++)
        set(state.data(), i, input.initial[i]);
      const unsigned bits[] = {4, 0, 10, 11, 2, 7, 6};
      for (unsigned i = 0; i < 7; i++)
        set(state.data(), 17 + i, (input.initial_flags >> bits[i]) & 1);
      for (unsigned i = 0; i < 16; i++) {
        auto [offset, size] = engine.registers.at("XMM" + std::to_string(i));
        (void)size;
        std::memcpy(state.data() + offset, input.initial_xmm.data() + i * 16,
                    16);
      }
      if (engine.registers.contains("MXCSR")) {
        auto [offset, size] = engine.registers.at("MXCSR");
        (void)size;
        std::memcpy(state.data() + offset, &input.initial_mxcsr, 4);
      }
    }
    std::vector<ZvrilTraceRecord> trace(input.native_trace ? 4096 : 64);
    if (input.trace)
      engine.get<void (*)(ZvrilRuntime *, ZvrilTraceRecord *, std::uint64_t)>(
          "zvril_runtime_trace")(runtime, trace.data(), trace.size());
    const unsigned ids[] = {7, 6, 2, 1, 8, 9};
    const std::uint64_t sp =
        input.has_initial ? input.initial[4]
                          : ((stack + 65536 - 16 - signature.abi.stack_bytes) &
                             ~UINT64_C(15)) +
                                8;
    write(runtime, sp, &sentinel, 8);
    set(state.data(), 4, sp);
    constexpr std::uint64_t result_address = UINT64_C(0x58000000);
    if (signature.abi.result.memory()) {
      if (!map(runtime, result_address, signature.abi.result.size, 3, nullptr,
               0, 1))
        throw Error("E_MEMORY_FAULT", "Cannot map aggregate return storage", 1);
      set(state.data(), 7, result_address);
    }
    for (unsigned i = 0; i < signature.abi.arguments.size(); i++) {
      const auto &t = signature.abi.arguments[i];
      const auto &location = signature.abi.locations[i];
      const auto *bytes =
          t.aggregate ? aggregate_arguments[i].data()
                      : reinterpret_cast<const std::uint8_t *>(&arguments[i]);
      if (location.stack) {
        if (!write(runtime, sp + 8 + location.offset, bytes,
                   t.narrow_integer() ? 4 : t.size))
          throw Error("E_MEMORY_FAULT", "Cannot initialize stack argument", 1);
      } else
        for (unsigned j = 0; j < t.classes.size(); j++) {
          if (t.classes[j] == AbiClass::None)
            continue;
          std::uint64_t chunk = 0;
          auto n = std::min<std::uint64_t>(8, t.size - j * 8);
          std::memcpy(&chunk, bytes + j * 8, n);
          if (t.narrow_integer())
            chunk = arguments[i];
          if (t.classes[j] == AbiClass::Integer)
            set(state.data(), ids[location.registers[j]], chunk);
          else {
            auto [offset, size] = engine.registers.at(
                "XMM" + std::to_string(location.registers[j]));
            (void)size;
            std::memcpy(state.data() + offset, &chunk, n);
          }
        }
    }
    if (signature.variadic && !input.has_initial)
      set(state.data(), 0, signature.abi.sse_used);
    auto execute =
        engine.get<ZvrilRuntime *(*)(void *, std::uint64_t, ZvrilRuntime *)>(
            "zvril_lifted_v2");
    const auto call_start = std::chrono::steady_clock::now();
    execute(state.data(), entry + guest_bias, runtime);
    result["_execution_ns"] = static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::steady_clock::now() - call_start)
            .count());
    if (input.trace) {
      Array records;
      auto count = engine.get<std::uint64_t (*)(ZvrilRuntime *)>(
          "zvril_runtime_trace_count")(runtime);
      for (std::size_t i = 0; i < std::min<std::uint64_t>(count, trace.size());
           i++) {
        Array gpr;
        for (auto value : trace[i].gpr)
          gpr.push_back(hex(value));
        records.push_back(Object{{"pc", hex(trace[i].pc - guest_bias)},
                                 {"gpr", std::move(gpr)},
                                 {"flags", hex(trace[i].flags)},
                                 {"flags_valid", hex(trace[i].flags_valid)}});
      }
      result["trace"] = Object{{"total_instructions", count},
                               {"truncated", count > trace.size()},
                               {"records", std::move(records)}};
    }
    value = get(state.data(), 0);
    if (signature.abi.result.aggregate) {
      const auto &t = signature.abi.result;
      if (t.memory()) {
        if (!status->fault &&
            !read(runtime, result_address, return_bytes.data(), t.size))
          throw Error("E_MEMORY_FAULT", "Cannot observe aggregate return", 1);
      } else {
        unsigned gp = 0, fp = 0;
        for (unsigned j = 0; j < t.classes.size(); j++) {
          if (t.classes[j] == AbiClass::None)
            continue;
          std::uint64_t chunk = 0;
          auto n = std::min<std::uint64_t>(8, t.size - j * 8);
          if (t.classes[j] == AbiClass::Integer)
            chunk = get(state.data(), gp++ ? 2 : 0);
          else {
            auto [offset, size] =
                engine.registers.at("XMM" + std::to_string(fp++));
            (void)size;
            std::memcpy(&chunk, state.data() + offset, n);
          }
          std::memcpy(return_bytes.data() + j * 8, &chunk, n);
        }
      }
    }
    if (signature.result == "f64" || signature.result == "f32") {
      auto [offset, size] = engine.registers.at("XMM0");
      (void)size;
      value = 0;
      std::memcpy(&value, state.data() + offset,
                  signature.result == "f32" ? 4 : 8);
    }
    if (status->fault) {
      result["kind"] = (status->fault == 3 || status->fault == 6 ||
                        status->fault == 7 || status->fault == 8)
                           ? "unknown"
                           : "fault";
      result["fault"] = status->fault;
      result["pc"] = status->fault_pc >= guest_bias
                         ? status->fault_pc - guest_bias
                         : status->fault_pc;
      result["address"] = status->fault_address;
      Array registers;
      for (unsigned i = 0; i < 17; i++)
        registers.push_back(hex(get(state.data(), i)));
      std::uint64_t flags = 0;
      const unsigned bits[] = {4, 0, 10, 11, 2, 7, 6};
      for (unsigned i = 0; i < 7; i++)
        flags |= (get(state.data(), 17 + i) & 1) << bits[i];
      result["fault_state"] = Object{
          {"address_space", "guest"},
          {"gpr", std::move(registers)},
          {"flags", hex(flags)},
          {"flags_valid", hex(engine.get<std::uint64_t (*)(ZvrilRuntime *)>(
                              "zvril_runtime_flags_valid")(runtime))}};
    } else if (engine.get<std::uint64_t (*)(ZvrilRuntime *)>(
                   "zvril_runtime_unknown_flags")(runtime)) {
      result["kind"] = "unknown";
      result["code"] = "E_UNDEFINED_FLAGS";
      result["message"] =
          "A consumed initial/undefined FLAGS bit has no native ABI contract";
    }
    engine.get<void (*)(ZvrilRuntime *)>("zvril_runtime_clear_fault")(runtime);
    observe_globals([&](std::uint64_t at, std::vector<std::uint8_t> &bytes) {
      if (!read(runtime, at + guest_bias, bytes.data(), bytes.size()))
        throw Error("E_MEMORY_FAULT", "Cannot observe global", 1);
    });
    for (std::size_t i = 0; i < input.buffers.size(); i++)
      if (!buffers[i].empty())
        read(runtime, input.buffers[i].guest, buffers[i].data(),
             buffers[i].size());
  }
  if (signature.result == "void")
    value = 0;
  else if (signature.result == "i8" || signature.result == "u8")
    value = std::uint8_t(value);
  else if (signature.result == "i16" || signature.result == "u16")
    value = std::uint16_t(value);
  else if (signature.result == "i32" || signature.result == "u32" ||
           signature.result == "f32")
    value = std::uint32_t(value);
  if (signature.abi.result.aggregate) {
    for (auto offset : signature.abi.result.pointer_offsets) {
      std::uint64_t address;
      std::memcpy(&address, return_bytes.data() + offset, 8);
      if (!address)
        continue;
      bool known = false;
      for (unsigned i = 0; i < buffers.size(); i++) {
        auto base = native ? reinterpret_cast<std::uint64_t>(native_buffers[i])
                           : input.buffers[i].guest;
        if (address >= base && address - base <= buffers[i].size()) {
          address =
              UINT64_C(0x50000000) + i * UINT64_C(0x100000) + address - base;
          known = true;
          break;
        }
      }
      if (!known)
        for (const auto &segment : image.segments) {
          auto base = (native ? native_base : guest_bias) + segment.address;
          if (address >= base && address - base < segment.memory_size) {
            address =
                guest_bias + address - (native ? native_base : guest_bias);
            known = true;
            break;
          }
        }
      if (!known)
        result["kind"] = "unknown_pointer";
      std::memcpy(return_bytes.data() + offset, &address, 8);
    }
    for (unsigned i = 0; i < signature.abi.result.size; i++)
      if (!signature.abi.result.defined[i])
        return_bytes[i] = 0;
    result["return_bytes"] = encode(return_bytes);
  } else if (signature.result == "ptr" && value) {
    bool known = false;
    for (std::size_t i = 0; i < buffers.size(); i++) {
      const auto base = native
                            ? reinterpret_cast<std::uint64_t>(native_buffers[i])
                            : input.buffers[i].guest;
      if (value >= base && value - base <= buffers[i].size()) {
        result["pointer"] = Object{{"buffer", input.buffers[i].name},
                                   {"offset", hex(value - base)}};
        known = true;
        break;
      }
    }
    if (!known) {
      for (const auto &s : image.segments) {
        auto base = (native ? native_base : guest_bias) + s.address;
        if (value >= base && value - base < s.memory_size) {
          result["pointer"] =
              Object{{"image_offset",
                      hex(value - (native ? native_base : guest_bias))}};
          known = true;
          break;
        }
      }
    }
    if (!known)
      result["kind"] = "unknown_pointer";
  } else {
    result["return"] = hex(value);
    if (signature.comparison == "sign")
      result["return"] = std::int32_t(value) < 0 ? "negative"
                         : value                 ? "positive"
                                                 : "zero";
  }
  if (native)
    for (std::size_t i = 0; i < buffers.size(); i++) {
      if (!buffers[i].empty())
        std::memcpy(buffers[i].data(), native_buffers[i], buffers[i].size());
      munmap(mappings[i], mapping_sizes[i]);
    }
  Object observed_buffers;
  for (std::size_t i = 0; i < input.buffers.size(); i++)
    for (const auto &p : input.buffers[i].pointers) {
      std::uint64_t address;
      std::memcpy(&address, buffers[i].data() + p.offset, 8);
      if (!address)
        continue;
      bool known = false;
      for (std::size_t j = 0; j < input.buffers.size(); j++) {
        auto base = native ? reinterpret_cast<std::uint64_t>(native_buffers[j])
                           : input.buffers[j].guest;
        if (address >= base && address - base <= buffers[j].size()) {
          address =
              UINT64_C(0x50000000) + j * UINT64_C(0x100000) + address - base;
          std::memcpy(buffers[i].data() + p.offset, &address, 8);
          known = true;
          break;
        }
      }
      if (!known)
        result["kind"] = "unknown_pointer";
    }
  for (std::size_t i = 0; i < buffers.size(); i++)
    observed_buffers[input.buffers[i].name] = encode(buffers[i]);
  result["buffers"] = std::move(observed_buffers);
  return result;
}
Object worker(Engine &engine, const Image &image,
              const std::filesystem::path &original, const Case &input,
              const Contract &signature, const std::string &symbol,
              std::uint64_t entry, bool native, std::uint64_t timeout) {
  std::unique_ptr<NativeTrace> tracer;
  if (native && input.native_trace)
    tracer = std::make_unique<NativeTrace>(image, engine.pcs,
                                           signature.abi.stack_bytes);
  int descriptors[2];
  if (pipe2(descriptors, O_CLOEXEC))
    throw Error("E_WORKER", "Cannot create worker pipe", 2);
  pid_t pid = fork();
  if (pid < 0) {
    close(descriptors[0]);
    close(descriptors[1]);
    throw Error("E_WORKER", "Cannot fork worker", 2);
  }
  if (!pid) {
    close(descriptors[0]);
    signal_fd = descriptors[1];
    struct sigaction action{};
    action.sa_sigaction = signal_handler;
    action.sa_flags = SA_SIGINFO;
    for (int sig : {SIGSEGV, SIGBUS, SIGILL, SIGFPE, SIGABRT})
      sigaction(sig, &action, nullptr);
    int sink = open("/dev/null", O_RDWR);
    if (sink >= 0) {
      dup2(sink, 0);
      dup2(sink, 1);
      dup2(sink, 2);
      if (sink > 2)
        close(sink);
    }
    Object observation;
    try {
      observation = observed(engine, image, original, input, signature, symbol,
                             entry, native, timeout, tracer.get());
    } catch (const Error &e) {
      observation = Object{{"kind", "unknown"},
                           {"code", e.code},
                           {"message", std::string(e.what())}};
    } catch (const std::exception &e) {
      observation = Object{{"kind", "unknown"},
                           {"code", "E_WORKER"},
                           {"message", std::string(e.what())}};
    }
    auto bytes = llvm::formatv("{0}", Value(std::move(observation))).str();
    std::size_t at = 0;
    while (at < bytes.size()) {
      auto n = write(descriptors[1], bytes.data() + at, bytes.size() - at);
      if (n <= 0)
        break;
      at += n;
    }
    _exit(0);
  }
  close(descriptors[1]);
  fcntl(descriptors[0], F_SETFL, O_NONBLOCK);
  std::string bytes;
  int status = 0;
  bool done = false, timed = false;
  rusage usage{};
  auto deadline =
      std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout);
  while (!done) {
    char buffer[8192];
    ssize_t n = 0;
    while ((n = read(descriptors[0], buffer, sizeof(buffer))) > 0) {
      bytes.append(buffer, n);
      if (bytes.size() > 8 * 1024 * 1024) {
        kill(pid, SIGKILL);
        timed = true;
        break;
      }
    }
    auto waited = wait4(pid, &status, WNOHANG, &usage);
    if (waited == pid && WIFSTOPPED(status) && tracer) {
      if (timed || std::chrono::steady_clock::now() >= deadline) {
        kill(pid, SIGKILL);
        while (wait4(pid, &status, 0, &usage) < 0 && errno == EINTR) {
        }
        done = true;
        timed = true;
        continue;
      }
      if (!tracer->stopped(pid, status)) {
        kill(pid, SIGKILL);
        timed = true;
      }
      continue;
    }
    if (waited == pid)
      done = true;
    else if (std::chrono::steady_clock::now() >= deadline || timed) {
      kill(pid, SIGKILL);
      while (wait4(pid, &status, 0, &usage) < 0 && errno == EINTR) {
      }
      done = true;
      timed = true;
    } else {
      pollfd p{descriptors[0], POLLIN, 0};
      poll(&p, 1, 5);
    }
  }
  char buffer[8192];
  ssize_t n;
  while ((n = read(descriptors[0], buffer, sizeof(buffer))) > 0)
    bytes.append(buffer, n);
  close(descriptors[0]);
  if (timed)
    return Object{{"kind", "unknown"},
                  {"code", "E_RESOURCE_LIMIT"},
                  {"message", "Worker timed out or exceeded protocol budget"}};
  if (bytes.empty())
    return Object{{"kind", "unknown"},
                  {"code", "E_WORKER"},
                  {"message", "Worker exited without an observation"}};
  auto parsed = json(bytes);
  auto *object = parsed.getAsObject();
  if (!object)
    return Object{{"kind", "unknown"}, {"code", "E_WORKER"}};
  (*object)["_worker_peak_rss_kib"] =
      static_cast<std::uint64_t>(usage.ru_maxrss);
  if (tracer)
    (*object)["trace"] = tracer->result();
  return *object;
}
bool equal_observations(const Object &native, const Object &translated) {
  auto left = native, right = translated;
  for (const char *key : {"_execution_ns", "_worker_peak_rss_kib", "trace"}) {
    left.erase(key);
    right.erase(key);
  }
  return Value(std::move(left)) == Value(std::move(right));
}
void replay_native_initial(const Image &image, const Contract &signature,
                           Case &input, Object &native) {
  auto *trace = native.getObject("trace");
  if (!trace)
    return;
  auto *records = trace->getArray("records");
  auto *bases = trace->getArray("buffer_bases");
  if (!records || records->empty() || !bases)
    return;
  auto *first = (*records)[0].getAsObject();
  auto *initial = first->getArray("gpr");
  if (!initial || initial->size() != 17)
    throw Error("E_TRACE_PROTOCOL", "Native initial GPR set is incomplete", 2);
  (void)image;
  (void)signature;
  if (!trace->get("image_base") || !trace->get("return_pc") ||
      !first->get("flags") || !trace->getArray("memory") ||
      bases->size() < input.buffers.size())
    throw Error("E_TRACE_PROTOCOL", "Incomplete native snapshot", 2);
  input.image_bias = integer(*trace->get("image_base"));
  input.return_pc = integer(*trace->get("return_pc"));
  input.initial_xmm = decode(trace->getString("initial_xmm").value_or(""));
  if (input.initial_xmm.size() != 256 || !trace->get("initial_mxcsr"))
    throw Error("E_TRACE_PROTOCOL", "Incomplete native SSE snapshot", 2);
  input.initial_mxcsr = integer(*trace->get("initial_mxcsr"));
  for (unsigned i = 0; i < 17; i++)
    input.initial[i] = integer((*initial)[i]);
  for (unsigned i = 0; i < input.buffers.size(); i++)
    input.buffers[i].guest = integer((*bases)[i]);
  for (const auto &row : *trace->getArray("memory")) {
    auto *snapshot = row.getAsObject();
    if (!snapshot || !snapshot->get("address"))
      throw Error("E_TRACE_PROTOCOL", "Malformed native memory snapshot", 2);
    input.snapshots.push_back(
        {integer(*snapshot->get("address")),
         decode(snapshot->getString("hex").value_or("")),
         snapshot->getString("kind").value_or("") == "image"});
  }
  input.initial_flags = integer(*first->get("flags"));
  input.has_initial = true;
  (*trace)["replay"] =
      "Native virtual addresses with independent guest backing; initial "
      "GPR/FLAGS/XMM/MXCSR, writable image and bounded entry stack snapshot";
}
} // namespace
Verification verify(const Image &image, const std::filesystem::path &original,
                    const std::filesystem::path &output,
                    const std::filesystem::path &cases,
                    const std::string &symbol, std::uint64_t timeout,
                    bool native_trace) {
  if (native_trace && !ptrace_available())
    throw Error(
        "E_TRACE_UNAVAILABLE",
        "Host denied ptrace; native instruction tracing cannot be enabled", 1);
  auto path =
      std::filesystem::is_directory(cases) ? cases / "cases.json" : cases;
  auto source = text_file(path);
  auto document = json(source);
  auto *object = document.getAsObject();
  if (!object)
    throw Error("E_CASES", "Cases must be a JSON object");
  auto signature = contract(*object);
  auto *rows = object->getArray("cases");
  if (!rows || rows->empty() || rows->size() > 10000)
    throw Error("E_CASES", "Supply 1..10000 cases");
  auto lifted = json(text_file(output / "report.json"));
  auto *lifting = lifted.getAsObject()->getObject("lifting");
  if (!lifting)
    throw Error("E_LLVM_VERIFY", "No successful lift report", 2);
  auto entry = integer(*lifting->get("entry"));
  if (native_trace && signature.abi.aggregate)
    throw Error(
        "E_TRACE_UNSUPPORTED",
        "Aggregate trace replay is not available; use scalar verification", 1);
  if (native_trace &&
      (lifting->getString("isa").value_or("") != "amd64" ||
       std::any_of(image.metadata.begin(), image.metadata.end(),
                   [](const auto &r) { return r.type == PT_TLS; })))
    throw Error(
        "E_TRACE_UNSUPPORTED",
        "Native trace replay currently requires baseline amd64 without TLS", 1);
  if (native_trace && rows->size() > 4)
    throw Error("E_RESOURCE_LIMIT",
                "Native tracing is limited to 4 cases per invocation", 1);
  if (native_trace && lifting->getArray("external_bindings") &&
      !lifting->getArray("external_bindings")->empty())
    throw Error("E_TRACE_UNSUPPORTED",
                "Instruction comparison requires a closed call graph without "
                "external model calls",
                1);
  const auto rep_profile = native_rep_fault_profile();
  Engine engine(output / "module.bc", signature, native_trace);
  Array records;
  Value reproducer = nullptr;
  std::uint64_t passed = 0, mismatches = 0, unknown = 0;
  const auto target = std::filesystem::absolute(original);
  for (std::size_t i = 0; i < rows->size(); i++) {
    auto *record = (*rows)[i].getAsObject();
    if (!record)
      throw Error("E_CASES", "Case must be an object");
    auto input = parse_case(*record, i, signature);
    input.rep_fault_restore_mask = rep_profile;
    input.native_trace = native_trace;
    input.trace = native_trace;
    auto native = worker(engine, image, target, input, signature, symbol, entry,
                         true, timeout);
    if (native_trace)
      replay_native_initial(image, signature, input, native);
    auto translated = worker(engine, image, target, input, signature, symbol,
                             entry, false, timeout);
    const auto n = native.getString("kind").value_or("unknown"),
               t = translated.getString("kind").value_or("unknown");
    std::string verdict;
    if (n == "unknown" || t == "unknown" || n == "unknown_pointer" ||
        t == "unknown_pointer") {
      verdict = "UNKNOWN";
      unknown++;
    } else if (n == "signal" && t == "fault") {
      auto sig = native.getInteger("signal").value_or(0),
           fault = translated.getInteger("fault").value_or(0);
      bool equal =
          ((sig == SIGFPE && fault == 5) || (sig == SIGILL && fault == 9) ||
           ((sig == SIGSEGV || sig == SIGBUS) && (fault == 1 || fault == 2))) &&
          native.getInteger("pc") == translated.getInteger("pc");
      verdict = equal ? "PASS" : "MISMATCH";
      if (equal)
        passed++;
      else
        mismatches++;
    } else if (n == "normal" && t == "normal" &&
               equal_observations(native, translated)) {
      verdict = "PASS";
      passed++;
    } else {
      verdict = "MISMATCH";
      mismatches++;
    }
    Object trace_comparison;
    if (native_trace) {
      auto *left = native.getObject("trace");
      auto *right = translated.getObject("trace");
      if (left && right)
        trace_comparison = compare_instruction_traces(*left, *right);
      else
        trace_comparison = Object{{"status", "UNKNOWN"},
                                  {"reason", "Trace records unavailable"}};
      auto status = trace_comparison.getString("status").value_or("UNKNOWN");
      if (verdict == "PASS" && status != "PASS") {
        passed--;
        verdict = status.str();
        if (verdict == "MISMATCH")
          mismatches++;
        else
          unknown++;
      }
    }
    if (verdict != "PASS" && reproducer.kind() == Value::Null) {
      reproducer =
          Object{{"signature", Object(*object->getObject("signature"))},
                 {"cases", Array{Object(*record)}}};
      input.trace = true;
      auto detail = worker(engine, image, target, input, signature, symbol,
                           entry, false, timeout);
      if (auto *trace = detail.getObject("trace"))
        translated["trace"] = Object(*trace);
    }
    records.push_back(Object{{"trace_comparison", std::move(trace_comparison)},
                             {"id", input.id},
                             {"status", verdict},
                             {"native", std::move(native)},
                             {"lifted", std::move(translated)}});
  }
  Object report{
      {"schema_version", "0.1"},
      {"contract_sha256",
       digest(
           llvm::formatv("{0}", Value(Object(*object->getObject("signature"))))
               .str())},
      {"cases_sha256", digest(source)},
      {"cases", rows->size()},
      {"passed", passed},
      {"mismatches", mismatches},
      {"unknown", unknown},
      {"comparison_contract",
       "Declared SysV scalar return and named input buffers; defined machine "
       "state is covered separately by ISA tests"},
      {"return_comparison", signature.comparison},
      {"first_failure_reproducer", std::move(reproducer)},
      {"native_instruction_trace",
       native_trace
           ? "ptrace GPR and defined FLAGS with replayed initial registers"
       : ptrace_available() ? "not requested"
                            : "unavailable: ptrace denied by host"},
      {"sandbox",
       Object{{"filesystem", "Landlock read-only allowlist"},
              {"network", "seccomp denied"},
              {"process_creation", "denied"},
              {"timeout_ms", timeout},
              {"address_space_limit", hex(2ULL * 1024 * 1024 * 1024)}}},
      {"cpu_profile",
       Object{{"rep_fault_restore_mask", rep_profile},
              {"source", "independent fixed native calibration"}}},
      {"records", std::move(records)}};
  std::ofstream file(output / "validation.json");
  file << llvm::formatv("{0:2}\n", Value(Object(report))).str();
  file.close();
  if (!file)
    throw Error("E_OUTPUT", "Cannot write validation report", 2);
  return {std::move(report), mismatches ? 4 : unknown ? 1 : 0};
}
} // namespace zvril
