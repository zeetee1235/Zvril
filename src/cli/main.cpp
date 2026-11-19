#include "zvril/batch.h"
#include "zvril/elf/image.h"
#include "zvril/lift.h"
#ifdef ZVRIL_HAS_REMILL
#include "demo_fixture.h"
#include "zvril/process.h"
#include "zvril/verify.h"
#endif
#include <llvm/Support/ErrorHandling.h>
#include <llvm/Support/FileSystem.h>
#ifdef ZVRIL_HAS_REMILL
#include <glog/logging.h>
#endif

#include <llvm/Config/llvm-config.h>
#include <llvm/Support/FormatVariadic.h>
#include <llvm/Support/JSON.h>
#include <llvm/Support/SHA256.h>
#include <llvm/Support/raw_ostream.h>

#include <algorithm>
#include <charconv>
#include <chrono>
#include <fcntl.h>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
#include <optional>
#include <poll.h>
#include <set>
#include <signal.h>
#include <sstream>
#include <string_view>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>

namespace {
#ifdef ZVRIL_SANITIZED
constexpr bool sanitized_build = true;
#else
constexpr bool sanitized_build = false;
#endif
using llvm::json::Array;
using llvm::json::Object;
using llvm::json::Value;

std::string safe(const std::string &value) {
  return llvm::json::isUTF8(value) ? value : llvm::json::fixUTF8(value);
}

std::string hex(std::uint64_t value) {
  std::ostringstream stream;
  stream << "0x" << std::hex << value;
  return stream.str();
}

std::string bytes_hex(llvm::ArrayRef<std::uint8_t> bytes) {
  constexpr char digits[] = "0123456789abcdef";
  std::string result;
  result.reserve(bytes.size() * 2);
  for (const auto byte : bytes) {
    result.push_back(digits[byte >> 4]);
    result.push_back(digits[byte & 15]);
  }
  return result;
}

void raw_name(Object &object, const std::string &name) {
  if (!llvm::json::isUTF8(name))
    object["name_raw_hex"] = bytes_hex(
        {reinterpret_cast<const std::uint8_t *>(name.data()), name.size()});
}

std::uint64_t number(const std::string &text, bool allow_hex = false) {
  std::string_view view(text);
  int base = 10;
  if (allow_hex && view.starts_with("0x")) {
    view.remove_prefix(2);
    base = 16;
  }
  std::uint64_t value = 0;
  const auto result =
      std::from_chars(view.data(), view.data() + view.size(), value, base);
  if (view.empty() || result.ec != std::errc() ||
      result.ptr != view.data() + view.size())
    throw zvril::Error("E_CLI", "Invalid unsigned number: " + text);
  return value;
}

struct Options {
  std::string command, input, output;
  bool json = false, help = false, quiet = false;
  bool bounded_worker = false;
  std::filesystem::path stage;
  zvril::Limits limits;
  std::map<std::string, std::string> values;
  std::set<std::string> flags;
  std::vector<std::string> arguments, environment;
};

void usage() {
  std::cout
      << "Zvril " ZVRIL_VERSION " — x86-64 ELF to LLVM IR\n"
         "Usage:\n"
         "  zvril doctor [--json]\n"
         "  zvril inspect INPUT [--json] [--out DIR] [--max-bytes N]\n"
         "  zvril functions INPUT [--json] [--out DIR] [--max-bytes N]\n"
         "             [--discover-calls] [--max-instructions N] "
         "[--max-functions N]\n"
         "  zvril demo [--json]\n"
         "  zvril run INPUT --allow-exec --out DIR [--stdin FILE] [--env "
         "NAME=VALUE]\n"
         "             [--max-steps N] [--max-modules N] [--timeout-ms N] "
         "[--memory-mb N]\n"
         "             [--resident-modules N] [--sysroot DIR]\n"
         "             [--isa amd64|amd64_avx|amd64_avx512] [-- ARG...]\n"
         "  zvril lift INPUT (--symbol NAME | --address VA) --out DIR "
         "[--json]\n"
         "             [--size N] [--max-instructions N] [--strict] "
         "[--max-bytes N]\n"
         "             [--abi FILE] [--isa amd64|amd64_avx|amd64_avx512]\n"
         "             [--max-functions N] [--max-blocks N] [--timeout-ms N] "
         "[--memory-mb N]\n"
         "  zvril batch INPUT --out DIR [--jobs N] [--json] [--max-bytes N]\n"
         "  zvril verify INPUT --symbol NAME --cases DIR --allow-exec [--out "
         "DIR] [--json]\n"
         "             [--max-bytes N] [--native-trace] [--timeout-ms N]\n"
         "lift uses Remill with an explicit machine-state/guest-memory ABI.\n"
         "batch runs bounded workers; verify executes only with --allow-exec.\n"
         "demo lifts and verifies bundled trusted examples when available.\n";
}

Options options(int argc, char **argv) {
  Options o;
  if (argc < 2)
    throw zvril::Error("E_CLI", "A command is required; use --help");
  o.command = argv[1];
  if (o.command == "--help" || o.command == "-h") {
    o.help = true;
    return o;
  }
  const std::set<std::string> commands{"doctor", "inspect", "functions", "demo",
                                       "lift",   "batch",   "verify",    "run"};
  if (!commands.contains(o.command))
    throw zvril::Error("E_CLI", "Unknown command: " + o.command);
  const std::map<std::string, std::set<std::string>> allowed{
      {"doctor", {}},
      {"demo", {}},
      {"inspect",
       {"--out", "--max-bytes", "--discover-calls", "--max-instructions",
        "--max-functions"}},
      {"functions",
       {"--out", "--max-bytes", "--discover-calls", "--max-instructions",
        "--max-functions"}},
      {"lift",
       {"--out", "--symbol", "--address", "--size", "--isa", "--abi",
        "--max-instructions", "--max-functions", "--max-blocks", "--timeout-ms",
        "--memory-mb", "--max-bytes", "--strict", "--allow-partial"}},
      {"batch",
       {"--out", "--jobs", "--symbols", "--isa", "--timeout-ms",
        "--max-bytes"}},
      {"run",
       {"--out", "--allow-exec", "--stdin", "--sysroot", "--env", "--isa",
        "--max-steps", "--max-modules", "--resident-modules", "--timeout-ms",
        "--memory-mb", "--max-bytes"}},
      {"verify",
       {"--out", "--symbol", "--cases", "--isa", "--allow-exec",
        "--native-trace", "--timeout-ms", "--max-bytes"}}};
  for (int i = 2; i < argc; ++i) {
    const std::string arg(argv[i]);
    if (arg == "--" && o.command == "run") {
      while (++i < argc)
        o.arguments.emplace_back(argv[i]);
      break;
    }
    if (arg == "--env" && o.command == "run") {
      if (++i >= argc)
        throw zvril::Error("E_CLI", "--env requires NAME=VALUE");
      std::string entry(argv[i]);
      const auto separator = entry.find('=');
      if (!separator || separator == std::string::npos)
        throw zvril::Error("E_CLI",
                           "--env requires a nonempty name followed by =VALUE");
      o.environment.push_back(std::move(entry));
      continue;
    }

    if (arg == "--help" || arg == "-h") {
      o.help = true;
      continue;
    }
    if (arg == "--json") {
      if (o.json)
        throw zvril::Error("E_CLI", "Repeated --json");
      o.json = true;
      continue;
    }
    if (arg.starts_with('-')) {
      if (!allowed.at(o.command).contains(arg))
        throw zvril::Error("E_CLI", "Unknown option for command: " + arg);
      if (o.flags.contains(arg) || o.values.contains(arg))
        throw zvril::Error("E_CLI", "Repeated option: " + arg);
      if (arg == "--strict" || arg == "--allow-partial" ||
          arg == "--allow-exec" || arg == "--native-trace" ||
          arg == "--discover-calls") {
        o.flags.insert(arg);
        continue;
      }
      if (++i >= argc || std::string_view(argv[i]).starts_with("--") ||
          !*argv[i])
        throw zvril::Error("E_CLI", "Option requires a value: " + arg);
      o.values.emplace(arg, argv[i]);
    } else {
      if (!o.input.empty() || o.command == "doctor" || o.command == "demo")
        throw zvril::Error("E_CLI", "Unexpected positional argument");
      o.input = arg;
    }
  }
  if (o.help)
    return o;
  if (o.command != "doctor" && o.command != "demo" && o.input.empty())
    throw zvril::Error("E_CLI", "An input ELF is required");
  if (o.values.contains("--out"))
    o.output = o.values.at("--out");
  if (o.values.contains("--max-bytes")) {
    o.limits.max_bytes = number(o.values.at("--max-bytes"));
    if (!o.limits.max_bytes)
      throw zvril::Error("E_CLI", "--max-bytes must be positive");
  }
  if (o.values.contains("--address"))
    (void)number(o.values.at("--address"), true);
  if (o.values.contains("--isa") &&
      !std::set<std::string>{"amd64", "amd64_avx", "amd64_avx512"}.contains(
          o.values.at("--isa")))
    throw zvril::Error("E_CLI", "Unknown ISA feature set");
  for (const auto *key :
       {"--size", "--max-instructions", "--max-functions", "--max-blocks",
        "--memory-mb", "--max-steps", "--max-modules", "--resident-modules"})
    if (o.values.contains(key) && !number(o.values.at(key), true))
      throw zvril::Error("E_CLI", std::string(key) + " must be positive");
  if (o.values.contains("--memory-mb") &&
      number(o.values.at("--memory-mb")) > 65536)
    throw zvril::Error("E_CLI", "--memory-mb exceeds 65536");
  if (o.values.contains("--jobs") && !number(o.values.at("--jobs")))
    throw zvril::Error("E_CLI", "--jobs must be positive");
  if (o.values.contains("--jobs") && number(o.values.at("--jobs")) > 32)
    throw zvril::Error("E_CLI", "--jobs exceeds 32");
  if (o.values.contains("--timeout-ms") &&
      (!number(o.values.at("--timeout-ms")) ||
       number(o.values.at("--timeout-ms")) > 3600000))
    throw zvril::Error("E_CLI",
                       "Worker timeout must be 1..3600000 milliseconds");
  if (o.flags.contains("--strict") && o.flags.contains("--allow-partial"))
    throw zvril::Error("E_CLI",
                       "--strict and --allow-partial are mutually exclusive");
  if (o.command == "lift" &&
      (o.values.contains("--symbol") == o.values.contains("--address")))
    throw zvril::Error("E_CLI",
                       "lift requires exactly one of --symbol and --address");
  if ((o.command == "lift" || o.command == "batch" || o.command == "run") &&
      o.output.empty())
    throw zvril::Error("E_CLI", "This command requires --out");
  if (o.command == "run" && !o.flags.contains("--allow-exec"))
    throw zvril::Error("E_CLI", "run requires --allow-exec");
  if (o.command == "verify" &&
      (!o.values.contains("--symbol") || !o.values.contains("--cases") ||
       !o.flags.contains("--allow-exec")))
    throw zvril::Error("E_CLI",
                       "verify requires --symbol, --cases and --allow-exec");
  return o;
}

Object diagnostic(const std::string &code, const std::string &message,
                  const std::string &severity = "error") {
  return Object{
      {"code", code},        {"severity", severity},     {"pc", nullptr},
      {"function", nullptr}, {"message", safe(message)}, {"evidence", Array{}}};
}

Object empty_report(const std::string &path) {
  return Object{
      {"schema_version", "0.1"},
      {"tool_version", ZVRIL_VERSION},
      {"source_path", safe(path)},
      {"source_sha256", nullptr},
      {"elf_type", nullptr},
      {"machine", nullptr},
      {"backend", "none"},
      {"llvm_version", LLVM_VERSION_STRING},
      {"status", "BLOCKED"},
      {"functions", Array{}},
      {"diagnostics", Array{}},
      {"artifacts", Array{}},
      {"timings", Object{}},
      {"resources", Object{}},
      {"analysis_scope",
       "ELF metadata only; no decode, CFG recovery, lifting or execution"}};
}

Object report(const zvril::Image &image, const std::string &path) {
  auto root = empty_report(path);
  const auto digest = llvm::SHA256::hash(image.bytes);
  root["source_sha256"] = bytes_hex(digest);
  root["elf_type"] = image.type == 2 ? "ET_EXEC" : "ET_DYN";
  root["machine"] = "EM_X86_64";
  root["entry"] = hex(image.entry);
  root["status"] = "INSPECTED";
  root["resources"] = Object{{"input_bytes", hex(image.bytes.size())}};
  Array segments;
  for (const auto &s : image.segments) {
    const std::string flags = std::string(s.flags & 4 ? "R" : "-") +
                              (s.flags & 2 ? "W" : "-") +
                              (s.flags & 1 ? "X" : "-");
    segments.push_back(
        Object{{"address", hex(s.address)},
               {"offset", hex(s.offset)},
               {"file_size", hex(s.file_size)},
               {"memory_size", hex(s.memory_size)},
               {"zero_fill_size", hex(s.memory_size - s.file_size)},
               {"alignment", hex(s.alignment)},
               {"permissions", flags}});
  }
  root["segments"] = std::move(segments);
  Array sections;
  for (const auto &s : image.sections) {
    Object item{{"name", safe(s.name)},      {"type", s.type},
                {"address", hex(s.address)}, {"offset", hex(s.offset)},
                {"size", hex(s.size)},       {"flags", hex(s.flags)}};
    raw_name(item, s.name);
    sections.push_back(std::move(item));
  }
  root["sections"] = std::move(sections);
  Array functions;
  for (const auto &f : image.functions) {
    Object item{{"name", safe(f.name)},
                {"address", hex(f.address)},
                {"size", hex(f.size)},
                {"section_index", f.section},
                {"binding", f.binding},
                {"discovery_evidence", Array{f.source}},
                {"boundary_known", f.size != 0},
                {"status", "INSPECTED"},
                {"instruction_count", nullptr},
                {"unsupported_instructions", Array{}},
                {"unresolved_edges", Array{}},
                {"llvm_verified", false},
                {"tested_cases", 0}};
    raw_name(item, f.name);
    functions.push_back(std::move(item));
  }
  root["functions"] = std::move(functions);
  Array imports;
  for (const auto &i : image.imports) {
    Object item{{"name", safe(i.name)},
                {"source", i.source},
                {"binding", i.binding},
                {"type", i.type}};
    raw_name(item, i.name);
    imports.push_back(std::move(item));
  }
  root["imports"] = std::move(imports);
  Array versions;
  for (const auto &v : image.symbol_versions)
    versions.push_back(Object{{"symbol", safe(v.symbol)},
                              {"version", safe(v.version)},
                              {"provider", safe(v.provider)},
                              {"defined", v.defined},
                              {"hidden", v.hidden},
                              {"address", hex(v.value)},
                              {"symbol_index", hex(v.symbol_index)},
                              {"symbol_table_offset", hex(v.table_offset)}});
  root["symbol_versions"] = std::move(versions);
  Array relocations;
  for (const auto &r : image.relocations)
    relocations.push_back(
        Object{{"source", safe(r.source)},
               {"offset", hex(r.offset)},
               {"type", r.type},
               {"symbol", safe(r.symbol)},
               {"symbol_index", hex(r.symbol_index)},
               {"addend", r.explicit_addend ? Value(std::to_string(r.addend))
                                            : Value(nullptr)},
               {"applied", false}});
  root["relocations"] = std::move(relocations);
  auto *diagnostics = root.getArray("diagnostics");
  root["dynamic_metadata_complete"] = image.dynamic_complete;
  for (const auto &warning : image.warnings)
    diagnostics->push_back(diagnostic("W_METADATA", warning, "warning"));
  for (auto &f : *root.getArray("functions")) {
    auto *object = f.getAsObject();
    const auto *evidence = object->getArray("discovery_evidence");
    const auto source = (*evidence)[0].getAsString().value_or("");
    (*object)["confidence"] = source.starts_with("direct_call:")
                                  ? "call_target_only"
                              : source == "eh_frame"  ? "unwind_range"
                              : source == "elf_entry" ? "entry_only"
                                                      : "symbol";
  }
  if (image.sections.empty())
    diagnostics->push_back(
        diagnostic("W_SECTIONLESS",
                   "Section table absent; dynamic and unwind recovery use "
                   "program headers. Function discovery can remain incomplete.",
                   "warning"));
  if (std::none_of(
          image.functions.begin(), image.functions.end(), [](const auto &f) {
            return f.source.starts_with("symtab:") ||
                   f.source.starts_with("dynsym:") || f.source == "dynamic";
          }))
    diagnostics->push_back(diagnostic("W_NO_FUNCTION_SYMBOLS",
                                      "No defined STT_FUNC candidates found; "
                                      "this does not imply absence of code",
                                      "warning"));
  return root;
}

void output_json(const Object &object) {
  llvm::outs() << llvm::formatv("{0:2}\n", Value(Object(object)));
  llvm::outs().flush();
}

void write_report(const Options &o, const Object &object) {
  if (o.output.empty())
    return;
  std::error_code ec;
  std::filesystem::create_directories(o.output, ec);
  if (ec)
    throw zvril::Error("E_OUTPUT",
                       "Cannot create output directory: " + ec.message(), 2);
  const auto path = std::filesystem::path(o.output) / "report.json";
  if (!o.input.empty() && std::filesystem::equivalent(path, o.input, ec) && !ec)
    throw zvril::Error("E_OUTPUT",
                       "Refusing to overwrite input ELF with report.json", 2);
  ec.clear();
  if (std::filesystem::is_symlink(std::filesystem::symlink_status(path, ec)))
    throw zvril::Error("E_OUTPUT", "Refusing to follow a report.json symlink",
                       2);
  std::ofstream file(path, std::ios::binary | std::ios::trunc);
  if (!file)
    throw zvril::Error("E_OUTPUT", "Cannot open report.json", 2);
  file << llvm::formatv("{0:2}\n", Value(Object(object))).str();
  file.close();
  if (!file)
    throw zvril::Error("E_OUTPUT", "Cannot finish writing report.json", 2);
}

int bounded_lift(const Options &, Object &);
int run(const Options &o, Object &root) {
  if (o.command == "lift" && !o.bounded_worker)
    return bounded_lift(o, root);
  if (o.command == "doctor") {
    root = Object{
        {"schema_version", "0.1"},
        {"tool_version", ZVRIL_VERSION},
        {"llvm_version", LLVM_VERSION_STRING},
        {"backend", zvril::remill_available() ? "remill" : "none"},
        {"semantics_path", zvril::default_semantics_path().string()},
        {"capabilities",
         Object{{"elf_inspection", true},
                {"symbol_functions", true},
                {"relocation_metadata", true},
                {"relocation_application", zvril::remill_available()},
                {"remill", zvril::remill_available()},
                {"llvm_lifting", zvril::remill_available() &&
                                     std::filesystem::is_regular_file(
                                         zvril::default_semantics_path())},
                {"dynamic_process_execution", zvril::remill_available()},
                {"dynamic_loader", zvril::remill_available()},
                {"cooperative_guest_threads", zvril::remill_available()},
                {"complete_linux_process", false},
                {"complete_linux_syscalls", false},
                {"cpp_exceptions", zvril::remill_available()},
                {"guest_pthread_create_join", zvril::remill_available()},
                {"dlopen_via_original_loader", zvril::remill_available()},
                {"signal_delivery", zvril::remill_available()},
                {"guest_filesystem", zvril::remill_available()},
                {"native_execution",
                 zvril::remill_available() && !sanitized_build},
                {"sanitized_build", sanitized_build},
#ifdef ZVRIL_HAS_REMILL
                {"execution_sandbox", zvril::sandbox_available()},
                {"ptrace", zvril::ptrace_available()},
#endif
                {"batch", true}}}};
    if (o.json)
      output_json(root);
    else
      std::cout << "Zvril " ZVRIL_VERSION " | LLVM " LLVM_VERSION_STRING "\n"
                   "ELF inspection: available\n"
                << "Remill: "
                << (zvril::remill_available() ? "available" : "unavailable")
                << "\nNative verification: "
                << (zvril::remill_available() && !sanitized_build
                        ? "available with explicit cases and --allow-exec"
                        : "unavailable")
                << "\n";
    return 0;
  }
  if (o.command == "demo") {
    Array cases;
    for (int i = 0; i < 3; ++i) {
      const auto image = zvril::parse(zvril::demo_elf(i != 0, i == 2));
      if (image.segments.size() != 1 ||
          image.segments[0].memory_size - image.segments[0].file_size != 32)
        throw zvril::Error("E_INTERNAL", "Built-in ELF analysis fixture failed",
                           2);
      cases.push_back(Object{{"name", i == 0   ? "ET_EXEC"
                                      : i == 1 ? "ET_DYN"
                                               : "sectionless ET_DYN"},
                             {"status", "INSPECTED"},
                             {"input_executed", false}});
    }
#if defined(ZVRIL_HAS_REMILL) && !defined(ZVRIL_SANITIZED)
    llvm::SmallString<256> temporary;
    if (auto error =
            llvm::sys::fs::createUniqueDirectory("zvril-demo", temporary))
      throw zvril::Error("E_OUTPUT", error.message(), 2);
    const std::filesystem::path directory(temporary.str().str());
    struct RemoveDemo {
      std::filesystem::path p;
      ~RemoveDemo() {
        std::error_code error;
        std::filesystem::remove_all(p, error);
      }
    } cleanup{directory};
    const auto fixture = directory / "trusted.so";
    {
      std::ofstream file(fixture, std::ios::binary);
      file.write(reinterpret_cast<const char *>(zvril_demo_bytes),
                 sizeof(zvril_demo_bytes));
      if (!file)
        throw zvril::Error("E_OUTPUT", "Cannot write demo fixture", 2);
    }
    const std::vector<std::pair<std::string, std::string>> examples{
        {"demo_add",
         R"({"signature":{"return":"u64","arguments":["u64","u64"]},"cases":[{"arguments":[40,2]},{"arguments":["0xffffffffffffffff",1]}]})"},
        {"demo_sum",
         R"({"signature":{"return":"u64","arguments":["ptr","u64"]},"cases":[{"arguments":[{"buffer":"input"},4],"buffers":{"input":{"hex":"01020304"}}}]})"},
        {"demo_float",
         R"({"signature":{"return":"f64","arguments":["f64","f64"]},"cases":[{"arguments":[1.5,2.25]}]})"}};
    for (const auto &[symbol, document] : examples) {
      const auto contract = directory / (symbol + ".json");
      {
        std::ofstream file(contract);
        file << document;
      }
      Options invocation;
      invocation.command = "verify";
      invocation.input = fixture.string();
      invocation.output = (directory / symbol).string();
      invocation.quiet = true;
      invocation.values = {{"--symbol", symbol},
                           {"--cases", contract.string()}};
      invocation.flags.insert("--allow-exec");
      Object result;
      if (auto code = run(invocation, result)) {
        root = std::move(result);
        if (o.json)
          output_json(root);
        return code;
      }
      cases.push_back(
          Object{{"name", symbol},
                 {"status", "TESTED"},
                 {"input_executed", true},
                 {"validation", std::move(*result.getObject("validation"))}});
    }
#endif
    root = Object{{"schema_version", "0.1"},
                  {"tool_version", ZVRIL_VERSION},
                  {"demo_scope",
                   cases.size() > 3
                       ? "ELF parsing, Remill lifting, LLVM verification and "
                         "sandboxed native differential"
                       : "ELF parsing only in this backend/sanitizer build"},
                  {"cases", std::move(cases)}};
    if (o.json)
      output_json(root);
    else
      std::cout << "Built-in demo passed: " << root.getArray("cases")->size()
                << " fixtures.\n";
    return 0;
  }
  const auto start = std::chrono::steady_clock::now();
  auto image = zvril::load(o.input, o.limits);
  Object code_discovery;
  if (o.flags.contains("--discover-calls"))
    code_discovery =
        zvril::discover_calls(image,
                              o.values.contains("--max-instructions")
                                  ? number(o.values.at("--max-instructions"))
                                  : 100000,
                              o.values.contains("--max-functions")
                                  ? number(o.values.at("--max-functions"))
                                  : 4096);
  root = report(image, o.input);
  if (!code_discovery.empty()) {
    root["code_discovery"] = std::move(code_discovery);
    root["analysis_scope"] = "ELF metadata and bounded direct-call discovery; "
                             "no lifting or execution";
  }
  root["timings"] =
      Object{{"inspection_ms", std::chrono::duration<double, std::milli>(
                                   std::chrono::steady_clock::now() - start)
                                   .count()}};
  if (o.command == "run") {
#ifndef ZVRIL_HAS_REMILL
    throw zvril::Error("E_BACKEND_UNAVAILABLE",
                       "Process execution requires Remill", 1);
#else
    std::error_code error;
    std::filesystem::create_directories(o.output, error);
    if (error || !std::filesystem::is_empty(o.output))
      throw zvril::Error("E_OUTPUT",
                         "run requires a new or empty output directory", 2);
    zvril::ProcessOptions execution;
    execution.output = o.output;
    if (o.values.contains("--sysroot"))
      execution.sysroot = o.values.at("--sysroot");
    execution.arguments.push_back(o.input);
    execution.arguments.insert(execution.arguments.end(), o.arguments.begin(),
                               o.arguments.end());
    execution.environment = o.environment;
    if (o.values.contains("--isa"))
      execution.architecture = o.values.at("--isa");
    if (o.values.contains("--max-steps"))
      execution.max_steps = number(o.values.at("--max-steps"));
    if (o.values.contains("--max-modules"))
      execution.max_modules = number(o.values.at("--max-modules"));
    if (o.values.contains("--resident-modules"))
      execution.resident_modules = number(o.values.at("--resident-modules"));
    if (o.values.contains("--memory-mb"))
      execution.memory_bytes = number(o.values.at("--memory-mb")) * 1024 * 1024;
    if (o.values.contains("--timeout-ms"))
      execution.timeout_ms = number(o.values.at("--timeout-ms"));
    if (o.values.contains("--stdin")) {
      const auto &path = o.values.at("--stdin");
      if (!std::filesystem::is_regular_file(path, error) || error ||
          std::filesystem::file_size(path, error) > 1024 * 1024 || error)
        throw zvril::Error("E_CLI",
                           "--stdin requires a regular file of at most 1 MiB");
      std::ifstream file(path, std::ios::binary);
      if (!file)
        throw zvril::Error("E_CLI", "Cannot read --stdin file");
      char bytes[8192];
      while (file.read(bytes, sizeof(bytes)) || file.gcount()) {
        if (execution.standard_input.size() + file.gcount() > 1024 * 1024)
          throw zvril::Error("E_CLI", "--stdin exceeds 1 MiB");
        execution.standard_input.insert(execution.standard_input.end(), bytes,
                                        bytes + file.gcount());
      }
      if (file.bad())
        throw zvril::Error("E_CLI", "Cannot read --stdin file");
    }
    auto executed = zvril::execute_process(image, execution);
    root["status"] =
        executed.report.getString("status").value_or("BLOCKED").str();
    root["backend"] = "remill";
    root["analysis_scope"] = "Dynamic process execution through verified "
                             "instruction LLVM modules; observed paths only";
    if (auto *failed = executed.report.getObject("error")) {
      auto item =
          diagnostic(failed->getString("code").value_or("E_PROCESS").str(),
                     failed->getString("message").value_or("").str());
      item["pc"] = failed->getString("pc").value_or("").str();
      root.getArray("diagnostics")->push_back(std::move(item));
    }
    root["process"] = std::move(executed.report);
    Array artifacts{"image.bc", "image.ll", "stdout.bin", "stderr.bin",
                    "LICENSE.remill"};
    for (const auto &step : *root.getObject("process")->getArray("modules")) {
      artifacts.push_back(
          step.getAsObject()->getString("module").value_or("").str());
      artifacts.push_back(
          step.getAsObject()->getString("ir").value_or("").str());
    }
    root["artifacts"] = std::move(artifacts);
    (*root.getObject("timings"))["process_ms"] =
        std::chrono::duration<double, std::milli>(
            std::chrono::steady_clock::now() - start)
            .count();
    write_report(o, root);
    if (o.json)
      output_json(root);
    else
      std::cout << root.getString("status").value_or("BLOCKED").str()
                << ": process output and per-instruction LLVM IR in "
                << o.output << "\n";
    return executed.exit_code;
#endif
  }
  if (o.command == "lift") {
    root["backend"] = zvril::remill_available() ? "remill" : "none";
    zvril::LiftOptions target;
    if (o.values.contains("--symbol"))
      target.symbol = o.values.at("--symbol");
    if (o.values.contains("--address"))
      target.address = number(o.values.at("--address"), true);
    if (o.values.contains("--size"))
      target.size = number(o.values.at("--size"), true);
    if (o.values.contains("--max-instructions"))
      target.max_instructions = number(o.values.at("--max-instructions"));
    if (o.values.contains("--max-functions"))
      target.max_functions = number(o.values.at("--max-functions"));
    if (o.values.contains("--max-blocks"))
      target.max_blocks = number(o.values.at("--max-blocks"));
    if (o.values.contains("--isa"))
      target.architecture = o.values.at("--isa");
    target.allow_partial = o.flags.contains("--allow-partial");
    if (o.values.contains("--abi"))
      target.abi_contract = o.values.at("--abi");
    std::error_code ec;
    std::filesystem::create_directories(o.output, ec);
    if (ec)
      throw zvril::Error("E_OUTPUT", "Cannot create output directory", 2);
    const std::vector<std::string> names{
        "cfg.dot",     "functions.json", "module.ll",         "module.bc",
        "pcmap.json",  "cfg.json",       "state_layout.json", "LICENSE.remill",
        "report.json", "validation.json"};
    for (const auto &name : names) {
      const auto path = std::filesystem::path(o.output) / name;
      ec.clear();
      if (std::filesystem::equivalent(path, o.input, ec) && !ec)
        throw zvril::Error("E_OUTPUT",
                           "Refusing to overwrite input ELF: " + name, 2);
      if (!target.abi_contract.empty()) {
        ec.clear();
        if (std::filesystem::equivalent(path, target.abi_contract, ec) && !ec)
          throw zvril::Error("E_OUTPUT",
                             "Refusing to overwrite ABI contract: " + name, 2);
      }
      ec.clear();
      if (std::filesystem::is_symlink(
              std::filesystem::symlink_status(path, ec)))
        throw zvril::Error("E_OUTPUT", "Refusing artifact symlink: " + name, 2);
    }
    // A new attempt invalidates only artifacts explicitly owned by a prior
    // successful Zvril manifest. Unknown files are never removed or replaced.
    std::set<std::string> owned;
    const auto previous_path = std::filesystem::path(o.output) / "report.json";
    ec.clear();
    if (std::filesystem::is_regular_file(previous_path, ec) && !ec &&
        std::filesystem::file_size(previous_path, ec) <= 64ULL * 1024 * 1024 &&
        !ec) {
      std::ifstream file(previous_path);
      const std::string text((std::istreambuf_iterator<char>(file)), {});
      auto previous = llvm::json::parse(text);
      if (previous) {
        if (const auto *object = previous->getAsObject();
            object &&
            object->getString("schema_version").value_or("") == "0.1" &&
            object->getString("backend").value_or("") == "remill") {
          if (object->getObject("validation"))
            owned.insert("validation.json");
          if (const auto *artifacts = object->getArray("artifacts"))
            for (const auto &value : *artifacts)
              if (auto name = value.getAsString())
                owned.insert(name->str());
        }
      } else
        llvm::consumeError(previous.takeError());
    }
    for (const auto &name : names) {
      if (name == "report.json")
        continue;
      const auto path = std::filesystem::path(o.output) / name;
      ec.clear();
      if (std::filesystem::exists(path, ec)) {
        if (!owned.contains(name) || !std::filesystem::is_regular_file(path))
          throw zvril::Error("E_OUTPUT",
                             "Output contains an unowned artifact: " + name, 2);
      }
    }
    for (const auto &name : names)
      if (name != "report.json" && owned.contains(name)) {
        std::filesystem::remove(std::filesystem::path(o.output) / name, ec);
        if (ec)
          throw zvril::Error("E_OUTPUT",
                             "Cannot invalidate old artifact: " + name, 2);
      }
    llvm::SmallString<256> stage;
    if (o.stage.empty())
      ec = llvm::sys::fs::createUniqueDirectory(
          (std::filesystem::absolute(o.output) / ".zvril-stage").string(),
          stage);
    else
      stage = o.stage.string();
    if (ec)
      throw zvril::Error("E_OUTPUT",
                         "Cannot create staging directory: " + ec.message(), 2);
    struct Cleanup {
      std::filesystem::path path;
      std::vector<std::filesystem::path> published;
      bool committed = false;
      ~Cleanup() {
        std::error_code e;
        if (!committed)
          for (const auto &file : published)
            std::filesystem::remove(file, e);
        std::filesystem::remove_all(path, e);
      }
    } cleanup{stage.str().str(), {}, false};
    target.output = cleanup.path;
    auto result = zvril::lift(image, target);
    root["functions"] = std::move(*result.getArray("functions"));
    result.erase("functions");
    const bool partial = result.getString("status").value_or("") == "PARTIAL";
    root["lifting"] = std::move(result);
    root["backend"] = "remill";
    root["status"] = partial ? "PARTIAL" : "LIFTED";
    if (partial)
      root.getArray("diagnostics")
          ->push_back(
              diagnostic("E_PARTIAL_LIFT",
                         "Analysis-only IR contains blocked instruction paths; "
                         "execution equivalence is not established"));
    root["analysis_scope"] =
        partial ? "Analysis-only partial CFG and IR; unresolved execution "
                  "paths remain"
                : "Closed selected function/call CFG with declared runtime "
                  "models; LLVM verifier passed; execution untested";
    Array artifacts;
    for (const auto &name : names) {
      if (name == "report.json" || name == "validation.json")
        continue;
      std::filesystem::rename(cleanup.path / name,
                              std::filesystem::path(o.output) / name, ec);
      if (ec)
        throw zvril::Error("E_OUTPUT", "Cannot publish artifact " + name, 2);
      cleanup.published.push_back(std::filesystem::path(o.output) / name);
      artifacts.push_back(name);
    }
    root["artifacts"] = std::move(artifacts);
    rusage usage{};
    if (!getrusage(RUSAGE_SELF, &usage))
      (*root.getObject("resources"))["peak_rss_kib"] =
          static_cast<std::uint64_t>(usage.ru_maxrss);
    (*root.getObject("resources"))["module_bytes"] = std::filesystem::file_size(
        std::filesystem::path(o.output) / "module.bc");
    root.getObject("timings")->operator[]("lift_ms") =
        std::chrono::duration<double, std::milli>(
            std::chrono::steady_clock::now() - start)
            .count();
    write_report(o, root);
    cleanup.committed = true;
    if (!o.quiet) {
      if (o.json)
        output_json(root);
      else
        std::cout << (partial ? "PARTIAL: " : "LIFTED: ") << o.input << " -> "
                  << o.output
                  << "/module.ll and module.bc\nLLVM verifier: passed. "
                     "Execution equivalence: untested.\n";
    }
    return partial ? 1 : 0;
  }
  if (o.command == "batch") {
    std::vector<std::string> selection;
    if (o.values.contains("--symbols")) {
      std::istringstream s(o.values.at("--symbols"));
      std::string item;
      while (std::getline(s, item, ','))
        if (!item.empty())
          selection.push_back(item);
    }
    auto batch = zvril::batch(
        image, o.output,
        o.values.contains("--jobs") ? number(o.values.at("--jobs")) : 1,
        o.values.contains("--timeout-ms") ? number(o.values.at("--timeout-ms"))
                                          : 30000,
        selection,
        [&](const zvril::Function &function,
            const std::filesystem::path &directory, Object &report) {
          Options worker = o;
          worker.command = "lift";
          worker.bounded_worker = true;
          worker.quiet = true;
          worker.output = directory.string();
          worker.values.erase("--symbol");
          worker.values["--address"] = hex(function.address);
          worker.values["--size"] = hex(function.size);
          report = empty_report(o.input);
          try {
            return run(worker, report);
          } catch (const zvril::Error &e) {
            report["status"] = "BLOCKED";
            auto item = diagnostic(e.code, e.what());
            if (e.pc)
              item["pc"] = hex(*e.pc);
            report.getArray("diagnostics")->push_back(std::move(item));
            if (e.code != "E_OUTPUT")
              try {
                write_report(worker, report);
              } catch (...) {
              }
            return e.exit_code;
          }
        });
    root["functions"] = std::move(batch.functions);
    root["status"] = batch.blocked || !batch.lifted ? "BLOCKED" : "LIFTED";
    root["batch"] = Object{{"lifted", batch.lifted},
                           {"blocked", batch.blocked},
                           {"total", batch.lifted + batch.blocked}};
    root["analysis_scope"] =
        "Independent selected-function static lifting attempts; per-function "
        "output retains failures; no input execution";
    root["backend"] = zvril::remill_available() ? "remill" : "none";
    if (batch.blocked || !batch.lifted)
      root.getArray("diagnostics")
          ->push_back(diagnostic("E_BATCH_INCOMPLETE",
                                 "Some function candidates were blocked; "
                                 "inspect per-function output"));
    write_report(o, root);
    if (o.json)
      output_json(root);
    else
      std::cout << "Batch: lifted=" << batch.lifted
                << " blocked=" << batch.blocked << "\n";
    return batch.blocked || !batch.lifted ? 1 : 0;
  }
#ifdef ZVRIL_HAS_REMILL
  if (o.command == "verify") {
#ifdef ZVRIL_SANITIZED
    throw zvril::Error("E_VERIFY_ENVIRONMENT",
                       "Native sandbox workers require a non-sanitized build; "
                       "ASan reserves virtual space beyond the worker limit",
                       1);
#endif
    Options invocation = o;
    invocation.command = "lift";
    invocation.quiet = true;
    if (invocation.output.empty()) {
      llvm::SmallString<256> directory;
      auto error =
          llvm::sys::fs::createUniqueDirectory("zvril-verify", directory);
      if (error)
        throw zvril::Error("E_OUTPUT", error.message(), 2);
      invocation.output = directory.str().str();
    }
    auto cases = std::filesystem::path(o.values.at("--cases"));
    if (std::filesystem::is_directory(cases))
      cases /= "cases.json";
    for (const char *name :
         {"module.ll", "module.bc", "pcmap.json", "cfg.json", "cfg.dot",
          "functions.json", "state_layout.json", "LICENSE.remill",
          "report.json", "validation.json"}) {
      std::error_code error;
      if (std::filesystem::equivalent(
              std::filesystem::path(invocation.output) / name, cases, error) &&
          !error)
        throw zvril::Error("E_OUTPUT",
                           "Output would overwrite verification cases", 2);
    }
    const auto validation_path =
        std::filesystem::path(invocation.output) / "validation.json";
    std::error_code ec;
    if (std::filesystem::equivalent(validation_path, o.input, ec) && !ec)
      throw zvril::Error("E_OUTPUT", "Validation output would overwrite input",
                         2);
    ec.clear();
    if (std::filesystem::is_symlink(
            std::filesystem::symlink_status(validation_path, ec)))
      throw zvril::Error("E_OUTPUT", "Validation output is a symlink", 2);
    run(invocation, root);
    auto verified = zvril::verify(
        image, o.input, invocation.output, o.values.at("--cases"),
        o.values.at("--symbol"),
        o.values.contains("--timeout-ms") ? number(o.values.at("--timeout-ms"))
                                          : 5000,
        o.flags.contains("--native-trace"));
    root["validation"] = std::move(verified.report);
    root["analysis_scope"] =
        "Selected function execution under the recorded SysV scalar and memory "
        "observation contract; input tests are not a formal equivalence proof";
    root.getArray("artifacts")->push_back("validation.json");
    root["status"] = verified.exit_code ? "BLOCKED" : "TESTED";
    const auto entry =
        root.getObject("lifting")->getString("entry").value_or("");
    for (auto &row : *root.getArray("functions"))
      if (auto *f = row.getAsObject();
          f && f->getString("address").value_or("") == entry) {
        (*f)["status"] = verified.exit_code == 4 ? "BLOCKED"
                         : verified.exit_code    ? "LIFTED"
                                                 : "TESTED";
        (*f)["tested_cases"] = *root.getObject("validation")->get("passed");
      }
    if (verified.exit_code)
      root.getArray("diagnostics")
          ->push_back(diagnostic(
              verified.exit_code == 4 ? "E_DIFFERENTIAL_MISMATCH"
                                      : "E_VERIFY_UNKNOWN",
              "See validation records for mismatches or uncomparable cases"));
    root["output_path"] = invocation.output;
    {
      std::ofstream functions(std::filesystem::path(invocation.output) /
                                  "functions.json",
                              std::ios::binary | std::ios::trunc);
      functions << llvm::formatv(
                       "{0:2}\n",
                       Value(Object{
                           {"schema_version", "0.1"},
                           {"functions", Array(*root.getArray("functions"))}}))
                       .str();
      functions.close();
      if (!functions)
        throw zvril::Error("E_OUTPUT",
                           "Cannot update function validation statuses", 2);
    }
    write_report(invocation, root);
    if (!o.quiet && o.json)
      output_json(root);
    else if (!o.quiet)
      std::cout << "Verification: "
                << (verified.exit_code ? "incomplete or mismatched" : "TESTED")
                << "\n";
    return verified.exit_code;
  }
#endif
  if (o.command == "verify") {
    root["status"] = "BLOCKED";
    if (auto *functions = root.getArray("functions"))
      for (auto &f : *functions)
        (*f.getAsObject())["status"] = "BLOCKED";
    root.getArray("diagnostics")
        ->push_back(diagnostic("E_BACKEND_UNAVAILABLE",
                               "This build has no Remill backend for native "
                               "verification. No input code was executed."));
    write_report(o, root);
    if (o.json)
      output_json(root);
    else
      std::cerr << "E_BACKEND_UNAVAILABLE: The requested batch/verify command "
                   "requires a Remill-enabled build.\n";
    return 1;
  }
  write_report(o, root);
  if (o.json)
    output_json(root);
  else {
    std::cout << "INSPECTED: " << safe(o.input) << "\n"
              << (image.type == 2 ? "ET_EXEC" : "ET_DYN")
              << " EM_X86_64 | PT_LOAD=" << image.segments.size()
              << " | function symbols=" << image.functions.size()
              << " | relocations=" << image.relocations.size() << "\n";
    if (o.command == "functions")
      for (const auto &f : image.functions)
        std::cout << hex(f.address) << " " << hex(f.size) << " " << safe(f.name)
                  << " [" << f.source << "]\n";
    std::cout << "Scope: symbol/ELF metadata; no CFG, semantics or execution "
                 "verified.\n";
  }
  return 0;
}

int bounded_lift(const Options &o, Object &root) {
  std::error_code error;
  std::filesystem::create_directories(o.output, error);
  if (error)
    throw zvril::Error("E_OUTPUT", "Cannot create lift output directory", 2);
  const std::set<std::string> names{
      "module.ll",         "module.bc",      "functions.json",
      "cfg.json",          "cfg.dot",        "pcmap.json",
      "state_layout.json", "LICENSE.remill", "validation.json"};
  std::set<std::string> existed, owned;
  for (const auto &name : names)
    if (std::filesystem::exists(std::filesystem::path(o.output) / name))
      existed.insert(name);
  const auto manifest = std::filesystem::path(o.output) / "report.json";
  if (std::filesystem::is_regular_file(manifest, error) && !error &&
      std::filesystem::file_size(manifest, error) < 64 * 1024 * 1024 &&
      !error) {
    std::ifstream file(manifest);
    std::string contents((std::istreambuf_iterator<char>(file)), {});
    auto parsed = llvm::json::parse(contents);
    if (parsed) {
      if (auto *object = parsed->getAsObject();
          object && object->getString("schema_version").value_or("") == "0.1" &&
          object->getString("backend").value_or("") == "remill") {
        if (auto *files = object->getArray("artifacts"))
          for (const auto &f : *files)
            if (auto n = f.getAsString(); n && names.contains(n->str()))
              owned.insert(n->str());
        if (object->getObject("validation"))
          owned.insert("validation.json");
      }
    } else
      llvm::consumeError(parsed.takeError());
  }
  llvm::SmallString<256> stage;
  error = llvm::sys::fs::createUniqueDirectory(
      (std::filesystem::absolute(o.output) / ".zvril-stage").string(), stage);
  if (error)
    throw zvril::Error("E_OUTPUT", "Cannot reserve bounded lift stage", 2);
  struct Stage {
    std::filesystem::path path;
    ~Stage() {
      std::error_code e;
      std::filesystem::remove_all(path, e);
    }
  } cleanup{stage.str().str()};
  const auto invalidate = [&] {
    for (const auto &name : names) {
      if (existed.contains(name) && !owned.contains(name))
        continue;
      auto path = std::filesystem::path(o.output) / name;
      std::error_code e;
      if (std::filesystem::is_symlink(std::filesystem::symlink_status(path, e)))
        continue;
      e.clear();
      if (std::filesystem::equivalent(path, o.input, e) && !e)
        continue;
      bool protected_input = false;
      for (const auto *key : {"--abi", "--cases"})
        if (o.values.contains(key)) {
          e.clear();
          if (std::filesystem::equivalent(path, o.values.at(key), e) && !e)
            protected_input = true;
        }
      if (!protected_input && std::filesystem::is_regular_file(path, e))
        std::filesystem::remove(path, e);
    }
  };
  int fd[2];
  if (pipe2(fd, O_CLOEXEC))
    throw zvril::Error("E_WORKER", "Cannot open lift result pipe", 2);
  const auto parent = getpid();
  pid_t pid = fork();
  if (pid < 0) {
    close(fd[0]);
    close(fd[1]);
    throw zvril::Error("E_WORKER", "Cannot fork lift worker", 2);
  }
  const auto timeout = o.values.contains("--timeout-ms")
                           ? number(o.values.at("--timeout-ms"))
                           : 30000;
  const auto memory = o.values.contains("--memory-mb")
                          ? number(o.values.at("--memory-mb"))
                          : 2048;
  if (!pid) {
    close(fd[0]);
    llvm::remove_bad_alloc_error_handler();
    llvm::install_bad_alloc_error_handler(
        [](void *, const char *, bool) { _exit(71); });
    prctl(PR_SET_PDEATHSIG, SIGKILL);
    if (getppid() != parent)
      _exit(2);
    Object result = empty_report(o.input), failure;
    int code = 2;
    try {
      rlim_t allowance = memory * 1024 * 1024;
#ifdef ZVRIL_SANITIZED
      std::ifstream statm("/proc/self/statm");
      std::uint64_t pages = 0;
      if (!(statm >> pages) ||
          pages > UINT64_MAX / std::uint64_t(sysconf(_SC_PAGESIZE)))
        throw zvril::Error("E_RESOURCE_LIMIT",
                           "Cannot account for sanitizer virtual memory", 1);
      allowance += pages * std::uint64_t(sysconf(_SC_PAGESIZE));
#endif
      const rlimit cpu{(timeout + 999) / 1000 + 1, (timeout + 999) / 1000 + 1},
          as{allowance, allowance};
      if (setrlimit(RLIMIT_CPU, &cpu) || setrlimit(RLIMIT_AS, &as))
        throw zvril::Error("E_RESOURCE_LIMIT",
                           "Cannot install lift worker limits", 1);
      Options worker = o;
      worker.bounded_worker = true;
      worker.quiet = true;
      worker.stage = cleanup.path;
      code = run(worker, result);
    } catch (const zvril::Error &e) {
      failure = Object{{"code", e.code},
                       {"message", std::string(e.what())},
                       {"pc", e.pc ? Value(hex(*e.pc)) : Value(nullptr)}};
      code = e.exit_code;
    } catch (const std::bad_alloc &) {
      failure =
          Object{{"code", "E_RESOURCE_LIMIT"},
                 {"message", "Lift worker exhausted its memory allowance"}};
      code = 1;
    } catch (const std::exception &e) {
      failure =
          Object{{"code", "E_INTERNAL"}, {"message", std::string(e.what())}};
      code = 2;
    }
    std::string bytes =
        llvm::formatv("{0}", Value(Object{{"root", std::move(result)},
                                          {"error", std::move(failure)},
                                          {"exit_code", code}}))
            .str();
    std::size_t at = 0;
    while (at < bytes.size()) {
      auto n = write(fd[1], bytes.data() + at, bytes.size() - at);
      if (n < 0 && errno == EINTR)
        continue;
      if (n <= 0)
        break;
      at += n;
    }
    _exit(0);
  }
  close(fd[1]);
  fcntl(fd[0], F_SETFL, O_NONBLOCK);
  std::string bytes;
  int status = 0;
  bool ended = false, limited = false;
  const auto deadline =
      std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout);
  while (!ended) {
    char buffer[8192];
    ssize_t n;
    while ((n = read(fd[0], buffer, sizeof(buffer))) > 0) {
      bytes.append(buffer, n);
      if (bytes.size() > 64 * 1024 * 1024) {
        limited = true;
        break;
      }
    }
    if (waitpid(pid, &status, WNOHANG) == pid)
      ended = true;
    else if (limited || std::chrono::steady_clock::now() >= deadline) {
      kill(pid, SIGKILL);
      while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {
      }
      ended = true;
      limited = true;
    } else {
      pollfd p{fd[0], POLLIN, 0};
      poll(&p, 1, 5);
    }
  }
  char buffer[8192];
  ssize_t n;
  while ((n = read(fd[0], buffer, sizeof(buffer))) > 0)
    bytes.append(buffer, n);
  close(fd[0]);
  const bool memory_limited = WIFEXITED(status) && WEXITSTATUS(status) == 71;
  if (limited || !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
    invalidate();
    throw zvril::Error(
        limited || memory_limited || WTERMSIG(status) == SIGXCPU ||
                WTERMSIG(status) == SIGKILL
            ? "E_RESOURCE_LIMIT"
            : "E_WORKER",
        memory_limited ? "Lift worker exhausted its memory allowance"
        : limited      ? "Lift deadline or result budget exceeded"
                  : "Lift worker terminated before producing a valid result",
        limited || memory_limited || WTERMSIG(status) == SIGXCPU ||
                WTERMSIG(status) == SIGKILL
            ? 1
            : 2);
  }
  auto payload = llvm::json::parse(bytes);
  if (!payload) {
    llvm::consumeError(payload.takeError());
    invalidate();
    throw zvril::Error("E_WORKER", "Invalid lift worker protocol", 2);
  }
  auto *object = payload->getAsObject();
  if (!object || !object->getObject("root") ||
      !object->getInteger("exit_code")) {
    invalidate();
    throw zvril::Error("E_WORKER", "Incomplete lift worker protocol", 2);
  }
  root = std::move(*object->getObject("root"));
  if (auto *failed = object->getObject("error"); failed && !failed->empty()) {
    zvril::Error e(
        failed->getString("code").value_or("E_WORKER").str(),
        failed->getString("message").value_or("Lift worker failed").str(),
        *object->getInteger("exit_code"));
    if (auto pc = failed->getString("pc"))
      e.pc = number(pc->str(), true);
    throw e;
  }
  if (!o.quiet) {
    if (o.json)
      output_json(root);
    else
      std::cout << root.getString("status").value_or("BLOCKED").str() << ": "
                << o.input << " -> " << o.output << "\n";
  }
  return *object->getInteger("exit_code");
}

} // namespace

int main(int argc, char **argv) {
#ifdef ZVRIL_HAS_REMILL
  google::InitGoogleLogging(argv[0]);
  FLAGS_minloglevel = 3;
  FLAGS_logtostderr = true;
#endif
  bool json_requested = false;
  for (int i = 1; i < argc; ++i)
    if (std::string_view(argv[i]) == "--json")
      json_requested = true;
  Options o;
  Object root = empty_report("");
  try {
    if (argc == 2 && std::string_view(argv[1]) == "--version") {
      std::cout << ZVRIL_VERSION << "\n";
      return 0;
    }
    o = options(argc, argv);
    if (o.help) {
      usage();
      return 0;
    }
    return run(o, root);
  } catch (const zvril::Error &error) {
    root["status"] = "BLOCKED";
    root["source_path"] = safe(o.input);
    auto item = diagnostic(error.code, error.what());
    if (error.pc)
      item["pc"] = hex(*error.pc);
    if (o.command == "lift" && o.values.contains("--symbol"))
      item["function"] = safe(o.values.at("--symbol"));
    if (o.command == "lift")
      if (auto *functions = root.getArray("functions"))
        for (auto &f : *functions) {
          auto *object = f.getAsObject();
          if (object &&
              object->getString("status").value_or("") == "INSPECTED" &&
              ((o.values.contains("--symbol") &&
                object->getString("name").value_or("") ==
                    safe(o.values.at("--symbol"))) ||
               (o.values.contains("--address") &&
                object->getString("address").value_or("") ==
                    hex(number(o.values.at("--address"), true)))))
            (*object)["status"] = "BLOCKED";
        }
    root.getArray("diagnostics")->push_back(std::move(item));
    if (!o.output.empty() && error.code != "E_OUTPUT") {
      try {
        write_report(o, root);
      } catch (const zvril::Error &output_error) {
        root.getArray("diagnostics")
            ->push_back(diagnostic(output_error.code, output_error.what()));
        if (json_requested)
          output_json(root);
        else
          std::cerr << output_error.code << ": " << output_error.what() << "\n";
        return output_error.exit_code;
      }
    }
    if (json_requested)
      output_json(root);
    else
      std::cerr << error.code << ": " << error.what() << "\n";
    return error.exit_code;
  } catch (const std::exception &error) {
    // Never include arbitrary parser state or dump input bytes on an internal
    // error.
    auto failure = empty_report(o.input);
    failure.getArray("diagnostics")
        ->push_back(diagnostic("E_INTERNAL", error.what()));
    if (json_requested)
      output_json(failure);
    else
      std::cerr << "E_INTERNAL: " << error.what() << "\n";
    return 2;
  }
}
