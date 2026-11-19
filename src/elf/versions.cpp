#include "zvril/elf/image.h"
#include <algorithm>
#include <cstring>
#include <elf.h>
#include <map>
#include <set>
#include <tuple>

namespace zvril {
namespace {
struct Reader {
  const Image &image;
  std::uint64_t budget;
  void use(std::uint64_t n) {
    if (n > budget) throw Error("E_RESOURCE_LIMIT", "Symbol version metadata exceeds budget", 1);
    budget -= n;
  }
  std::uint64_t offset(std::uint64_t address, std::uint64_t size) const {
    for (const auto &s : image.segments)
      if (address >= s.address && address - s.address <= s.file_size &&
          size <= s.file_size - (address - s.address))
        return s.offset + address - s.address;
    throw Error("E_ELF_RANGE", "Symbol version address is not file backed");
  }
  static std::uint64_t add(std::uint64_t a, std::uint64_t b) {
    if (b > UINT64_MAX - a) throw Error("E_ELF_RANGE", "Symbol version chain address wraps");
    return a + b;
  }
  template<class T> T get(std::uint64_t address) {
    return file<T>(offset(address, sizeof(T)));
  }
  template<class T> T file(std::uint64_t at) {
    use(1);
    if (at > image.bytes.size() || sizeof(T) > image.bytes.size() - at)
      throw Error("E_ELF_RANGE", "Symbol version record exceeds file");
    T result; std::memcpy(&result, image.bytes.data() + at, sizeof(T)); return result;
  }
  std::string string(std::uint64_t base, std::uint64_t size, std::uint64_t index) {
    if (index >= size) throw Error("E_ELF_RANGE", "Symbol version string exceeds table");
    auto at = offset(base, size);
    auto *data = reinterpret_cast<const char*>(image.bytes.data() + at + index);
    auto *end = static_cast<const char*>(std::memchr(data, 0, std::min<std::uint64_t>(size - index, 1048576)));
    if (!end) throw Error("E_ELF_INVALID", "Unterminated symbol version string");
    use(end - data); return {data, end};
  }
};
std::uint32_t elf_hash(const std::string &name) {
  std::uint32_t h = 0;
  for (unsigned char c : name) {
    h = (h << 4) + c; auto high = h & 0xf0000000u;
    if (high) h ^= high >> 24;
    h &= ~high;
  }
  return h;
}
}
void discover_versions(Image &image, const Limits &limits) {
  Reader r{image, limits.max_entries * 16};
  for (const auto &dynamic : image.metadata) if (dynamic.type == PT_DYNAMIC) {
    std::map<std::int64_t, std::uint64_t> tags;
    for (std::uint64_t at = 0; at + sizeof(Elf64_Dyn) <= dynamic.file_size; at += sizeof(Elf64_Dyn)) {
      auto d = r.file<Elf64_Dyn>(Reader::add(dynamic.offset, at));
      if (d.d_tag == DT_NULL) break;
      tags[d.d_tag] = d.d_un.d_val;
    }
    if (!tags.contains(DT_VERSYM) && !tags.contains(DT_VERNEED) && !tags.contains(DT_VERDEF) &&
        !tags.contains(DT_VERNEEDNUM) && !tags.contains(DT_VERDEFNUM)) continue;
    if (std::count_if(image.metadata.begin(), image.metadata.end(), [](const auto &m) { return m.type == PT_DYNAMIC; }) != 1)
      throw Error("E_ELF_INVALID", "Ambiguous dynamic symbol version tables");
    if (!tags.contains(DT_STRTAB) || !tags.contains(DT_STRSZ) || !tags.contains(DT_SYMTAB))
      throw Error("E_ELF_INVALID", "Symbol version tables lack dynamic strings/symbols");
    const auto text = [&](std::uint64_t index) { return r.string(tags[DT_STRTAB], tags[DT_STRSZ], index); };
    struct Version {std::string name, provider; bool defined;};
    std::map<unsigned, Version> names;
    const auto put = [&](unsigned index, std::string name, std::string provider, bool defined) {
      if (!index || names.contains(index)) throw Error("E_ELF_INVALID", "Duplicate/invalid symbol version index");
      names.emplace(index, Version{std::move(name), std::move(provider), defined});
    };
    for (bool defined : {false, true}) {
      auto pointer = defined ? DT_VERDEF : DT_VERNEED;
      auto number = defined ? DT_VERDEFNUM : DT_VERNEEDNUM;
      if (tags.contains(pointer) != tags.contains(number))
        throw Error("E_ELF_INVALID", "Incomplete symbol version descriptors");
      if (!tags.contains(pointer)) continue;
      auto count = tags[number], address = tags[pointer];
      if (!count || count > limits.max_entries) throw Error("E_RESOURCE_LIMIT", "Invalid symbol version chain count", 1);
      for (std::uint64_t i = 0; i < count; i++) {
        std::uint64_t next = 0;
        if (defined) {
          auto v = r.get<Elf64_Verdef>(address);
          if (v.vd_version != VER_DEF_CURRENT || !v.vd_cnt || v.vd_cnt > limits.max_entries || v.vd_aux < sizeof(v))
            throw Error("E_ELF_INVALID", "Invalid version definition header");
          auto aux = Reader::add(address, v.vd_aux);
          for (unsigned j = 0; j < v.vd_cnt; j++) {
            auto a = r.get<Elf64_Verdaux>(aux); auto name = text(a.vda_name);
            if (!j) {
              if (elf_hash(name) != v.vd_hash) throw Error("E_ELF_INVALID", "Version definition name/hash mismatch");
              put(v.vd_ndx & 0x7fff, name, tags.contains(DT_SONAME) ? text(tags[DT_SONAME]) : "", true);
            }
            if ((j + 1 == v.vd_cnt) != (a.vda_next == 0) || (a.vda_next && a.vda_next < sizeof(a)))
              throw Error("E_ELF_INVALID", "Malformed version definition auxiliary chain");
            aux = Reader::add(aux, a.vda_next);
          }
          next = v.vd_next;
          if (next && next < sizeof(v)) throw Error("E_ELF_INVALID", "Invalid version definition link");
        } else {
          auto v = r.get<Elf64_Verneed>(address);
          if (v.vn_version != VER_NEED_CURRENT || !v.vn_cnt || v.vn_cnt > limits.max_entries || v.vn_aux < sizeof(v))
            throw Error("E_ELF_INVALID", "Invalid version requirement header");
          auto provider = text(v.vn_file);
          auto aux = Reader::add(address, v.vn_aux);
          for (unsigned j = 0; j < v.vn_cnt; j++) {
            auto a = r.get<Elf64_Vernaux>(aux); auto name = text(a.vna_name);
            if ((a.vna_other & 0x7fff) < 2 || elf_hash(name) != a.vna_hash)
              throw Error("E_ELF_INVALID", "Invalid version requirement index/hash");
            put(a.vna_other & 0x7fff, name, provider, false);
            if ((j + 1 == v.vn_cnt) != (a.vna_next == 0) || (a.vna_next && a.vna_next < sizeof(a)))
              throw Error("E_ELF_INVALID", "Malformed version requirement auxiliary chain");
            aux = Reader::add(aux, a.vna_next);
          }
          next = v.vn_next;
          if (next && next < sizeof(v)) throw Error("E_ELF_INVALID", "Invalid version requirement link");
        }
        if ((i + 1 == count) != (next == 0)) throw Error("E_ELF_INVALID", "Symbol version chain count mismatch");
        address = Reader::add(address, next);
      }
    }
    if (!tags.contains(DT_VERSYM)) continue;
    auto symbols = r.offset(tags[DT_SYMTAB], sizeof(Elf64_Sym));
    std::uint64_t count = 0;
    for (const auto &s : image.sections) if (s.type == SHT_DYNSYM && s.offset == symbols) count = s.size / sizeof(Elf64_Sym);
    if (image.sections.empty()) count = image.symbols.size();
    if (!count) {
      image.dynamic_complete = false;
      image.warnings.push_back("W_SYMBOL_VERSIONS: Cannot bound dynamic symbol version array");
      continue;
    }
    if (count > limits.max_entries) throw Error("E_RESOURCE_LIMIT", "Dynamic symbol versions exceed budget", 1);
    r.offset(tags[DT_VERSYM], count * sizeof(Elf64_Half));
    for (std::uint64_t i = 0; i < count; i++) {
      auto encoded = r.get<Elf64_Half>(Reader::add(tags[DT_VERSYM], i * 2));
      unsigned index = encoded & 0x7fff;
      if (index < 2) continue;
      auto version = names.find(index);
      if (version == names.end()) throw Error("E_ELF_INVALID", "Unknown dynamic symbol version index");
      auto s = r.get<Elf64_Sym>(Reader::add(tags[DT_SYMTAB], i * sizeof(Elf64_Sym)));
      auto name = text(s.st_name);
      if (version->second.defined && s.st_shndx == SHN_UNDEF)
        throw Error("E_ELF_INVALID", "Undefined symbol refers to a version definition");
      const auto &v = version->second;
      image.symbol_versions.push_back({symbols, i, s.st_value, s.st_size, name, v.name, v.provider,
                                       s.st_shndx != SHN_UNDEF, bool(encoded & 0x8000), std::uint8_t(ELF64_ST_TYPE(s.st_info))});
    }
  }
  std::sort(image.symbol_versions.begin(), image.symbol_versions.end(), [](const auto &a, const auto &b) {
    return std::tie(a.table_offset, a.symbol_index) < std::tie(b.table_offset, b.symbol_index);
  });
  std::vector<Function> aliases;
  std::map<std::pair<std::uint64_t, std::string>, const SymbolVersion *> hidden;
  std::set<std::pair<std::uint64_t, std::string>> defaults;
  for (const auto &v : image.symbol_versions) if (v.defined && v.type == STT_FUNC) {
    auto key = std::make_pair(v.value, v.symbol);
    if (v.hidden) hidden.emplace(key, &v); else defaults.insert(key);
  }
  for (auto &f : image.functions) {
    auto key = std::make_pair(f.address, f.name); auto v = hidden.find(key);
    if (v != hidden.end() && !defaults.contains(key) &&
        (f.source.starts_with("dynsym:") || f.source == "dynamic"))
      f.name += "@" + v->second->version;
  }
  for (const auto &v : image.symbol_versions) if (v.defined && v.type == STT_FUNC) {
    aliases.push_back({v.symbol + "@" + v.version, "symbol_version", v.value, v.size, 0, 0});
    if (!v.hidden) aliases.push_back({v.symbol + "@@" + v.version, "symbol_version", v.value, v.size, 0, 0});
    if (image.functions.size() > limits.max_entries || aliases.size() > limits.max_entries - image.functions.size())
      throw Error("E_RESOURCE_LIMIT", "Versioned function aliases exceed metadata budget", 1);
  }
  image.functions.insert(image.functions.end(), aliases.begin(), aliases.end());
}
const SymbolVersion *symbol_version(const Image &image, const Relocation &r) {
  const auto key = std::make_pair(r.symbol_table_offset, r.symbol_index);
  auto found = std::lower_bound(image.symbol_versions.begin(), image.symbol_versions.end(), key,
      [](const auto &v, const auto &k) { return std::make_pair(v.table_offset, v.symbol_index) < k; });
  return found != image.symbol_versions.end() && std::make_pair(found->table_offset, found->symbol_index) == key ? &*found : nullptr;
}
} // namespace zvril
