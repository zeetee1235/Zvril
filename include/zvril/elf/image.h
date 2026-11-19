#pragma once

#include <cstdint>
#include <filesystem>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

namespace zvril {

struct Error : std::runtime_error {
  std::string code;
  int exit_code;
  std::optional<std::uint64_t> pc;
  Error(std::string code, std::string message, int exit_code = 3)
      : std::runtime_error(std::move(message)), code(std::move(code)),
        exit_code(exit_code) {}
};

struct Limits {
  std::uint64_t max_bytes = 256ULL * 1024 * 1024;
  std::uint64_t max_entries = 1000000;
  std::uint64_t max_string_bytes = 64ULL * 1024 * 1024;
};

struct Segment {
  std::uint64_t offset, address, file_size, memory_size, alignment;
  std::uint32_t flags;
};

struct Section {
  std::string name;
  std::uint32_t type, link;
  std::uint64_t address, offset, size, flags, entry_size;
};

struct Function {
  std::string name, source;
  std::uint64_t address, size;
  std::uint32_t section;
  std::uint8_t binding;
};

struct Import {
  std::string name, source;
  std::uint8_t binding, type;
};

struct Relocation {
  std::string source, symbol;
  std::uint64_t offset, symbol_index;
  std::uint32_t type;
  std::int64_t addend;
  bool explicit_addend;
  std::uint64_t symbol_value = 0, symbol_size = 0;
  std::uint32_t symbol_section = 0;
  std::uint8_t symbol_type = 0, symbol_binding = 0;
  bool active_dynamic = false;
  std::uint64_t file_offset = 0, symbol_table_offset = 0;
};
struct Symbol {
  std::string name, source;
  std::uint64_t value, size;
  std::uint32_t section;
  std::uint8_t type, binding;
};
struct MetadataRange {
  std::uint32_t type;
  std::uint64_t address, offset, file_size, memory_size, alignment;
};
struct SymbolVersion {
  std::uint64_t table_offset, symbol_index, value, size;
  std::string symbol, version, provider;
  bool defined, hidden;
  std::uint8_t type;
};

struct Image {
  std::uint16_t type = 0;
  std::uint64_t entry = 0;
  std::uint64_t program_header_count = 0;
  std::vector<std::uint8_t> bytes;
  std::vector<Segment> segments;
  std::vector<Section> sections;
  std::vector<Function> functions;
  std::vector<Import> imports;
  std::vector<Relocation> relocations;
  std::vector<Symbol> symbols;
  std::vector<MetadataRange> metadata;
  std::vector<SymbolVersion> symbol_versions;
  std::vector<std::string> warnings;
  std::vector<std::string> unsupported_loader_features;
  bool dynamic_complete = true;
};

void discover_metadata(Image &, const Limits &);
void discover_versions(Image &, const Limits &);
const SymbolVersion *symbol_version(const Image &, const Relocation &);

Image parse(std::vector<std::uint8_t> bytes, const Limits &limits = {});
Image load(const std::filesystem::path &path, const Limits &limits = {});
std::vector<std::uint8_t> demo_elf(bool dynamic, bool stripped);

} // namespace zvril
