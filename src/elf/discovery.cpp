#include "zvril/elf/image.h"
#include <algorithm>
#include <array>
#include <cstring>
#include <elf.h>
#include <llvm/DebugInfo/DWARF/DWARFDataExtractor.h>
#include <llvm/DebugInfo/DWARF/DWARFDebugFrame.h>
#include <llvm/Support/Error.h>
#include <map>
#include <set>
#include <sstream>

namespace zvril {
namespace {
struct View {
  const Image &image;
  std::uint64_t budget;
  void use(std::uint64_t n = 1) {
    if (n > budget)
      throw Error("E_RESOURCE_LIMIT", "Dynamic metadata budget exceeded", 1);
    budget -= n;
  }
  void range(std::uint64_t off, std::uint64_t size) const {
    if (off > image.bytes.size() || size > image.bytes.size() - off)
      throw Error("E_ELF_RANGE", "Dynamic metadata exceeds file");
  }
  template <class T> T get(std::uint64_t off) {
    use();
    range(off, sizeof(T));
    T v;
    std::memcpy(&v, image.bytes.data() + off, sizeof(v));
    return v;
  }
  std::uint64_t offset(std::uint64_t va, std::uint64_t n = 1) const {
    for (const auto &s : image.segments)
      if (va >= s.address && va - s.address <= s.file_size &&
          n <= s.file_size - (va - s.address))
        return s.offset + va - s.address;
    throw Error("E_ELF_RANGE", "Dynamic virtual address is not file backed");
  }
  bool code(std::uint64_t va, std::uint64_t size) const {
    for (const auto &s : image.segments)
      if ((s.flags & PF_X) && va >= s.address && va - s.address < s.file_size &&
          size <= s.file_size - (va - s.address))
        return true;
    return false;
  }
  std::string string(std::uint64_t off, std::uint64_t size,
                     std::uint64_t index) {
    if (index >= size)
      throw Error("E_ELF_RANGE", "Invalid dynamic string offset");
    range(off, size);
    const char *p =
        reinterpret_cast<const char *>(image.bytes.data() + off + index);
    auto *end = static_cast<const char *>(
        std::memchr(p, 0, std::min<std::uint64_t>(size - index, 1024 * 1024)));
    if (!end)
      throw Error("E_ELF_INVALID", "Unterminated dynamic string");
    use(end - p);
    return {p, end};
  }
};
std::string name(std::uint64_t a) {
  std::ostringstream s;
  s << "fde_" << std::hex << a;
  return s.str();
}
void frame(Image &image, View &view, std::uint64_t off, std::uint64_t size,
           std::uint64_t address) {
  view.range(off, size);
  // LLVM's CFI reader assumes a supported CIE address size and can terminate
  // the process when malformed records violate it. Validate record boundaries
  // and CIE headers before exposing input bytes to that API.
  for (std::uint64_t cursor = 0; cursor < size;) {
    if (size - cursor < 4)
      throw Error("E_ELF_RANGE", "Truncated EH record length");
    std::uint64_t length = view.get<std::uint32_t>(off + cursor), prefix = 4;
    if (!length) break;
    if (length == UINT32_MAX) {
      if (size - cursor < 12) throw Error("E_ELF_RANGE", "Truncated extended EH record");
      prefix = 12;
      length = view.get<std::uint64_t>(off + cursor + 4);
    }
    if (length < 4 || length > size - cursor - prefix)
      throw Error("E_ELF_RANGE", "EH record exceeds its declared extent");
    if (view.get<std::uint32_t>(off + cursor + prefix) == 0) {
      auto header = cursor + prefix + 4, end = cursor + prefix + length;
      if (header == end) throw Error("E_ELF_RANGE", "Truncated CIE version");
      auto version = view.get<std::uint8_t>(off + header++);
      if (version != 1 && version != 3 && version != 4)
        throw Error("E_ELF_INVALID", "Unsupported CIE version");
      bool terminated = false;
      while (header < end) {
        if (!view.get<std::uint8_t>(off + header++)) { terminated = true; break; }
      }
      if (!terminated) throw Error("E_ELF_INVALID", "Unterminated CIE augmentation");
      if (version == 4 &&
          (end - header < 2 || view.get<std::uint8_t>(off + header) != 8 ||
           view.get<std::uint8_t>(off + header + 1) != 0))
        throw Error("E_ELF_INVALID", "Unsupported x86-64 CIE address/segment size");
    }
    cursor += prefix + length;
  }
  // LLVM validates encodings and entry lengths; byte budget bounds work before
  // parsing.
  view.use(size / 4);
  llvm::DWARFDebugFrame frames(llvm::Triple::x86_64, true, address);
  llvm::DWARFDataExtractor data(
      llvm::StringRef(reinterpret_cast<const char *>(image.bytes.data() + off),
                      size),
      true, 8);
  if (auto error = frames.parse(data)) {
    image.warnings.push_back("E_EH_FRAME: " + llvm::toString(std::move(error)));
    return;
  }
  for (const auto &entry : frames.entries())
    if (const auto *f = llvm::dyn_cast<llvm::dwarf::FDE>(&entry)) {
      auto start = f->getInitialLocation(), length = f->getAddressRange();
      if (!length || !view.code(start, length))
        continue;
      auto found =
          std::find_if(image.functions.begin(), image.functions.end(),
                       [&](const auto &v) { return v.address == start; });
      if (found == image.functions.end())
        image.functions.push_back(
            {name(start), "eh_frame", start, length, 0, 0});
      else if (found->size && found->size != length)
        image.warnings.push_back("W_FUNCTION_RANGE_CONFLICT: " + name(start));
      else if (!found->size) {
        found->size = length;
        found->source += "+eh_frame";
      }
    }
}
} // namespace
void discover_metadata(Image &image, const Limits &limits) {
  View view{image, limits.max_entries * 16};
  image.dynamic_complete = !image.sections.empty();
  for (const auto &section : image.sections)
    if (section.name == ".eh_frame" && section.type == SHT_PROGBITS)
      frame(image, view, section.offset, section.size, section.address);
  if (image.sections.empty())
    for (const auto &header : image.metadata)
      if (header.type == PT_GNU_EH_FRAME && header.file_size >= 8) {
        view.range(header.offset, header.file_size);
        const auto *bytes = image.bytes.data() + header.offset;
        if (bytes[0] != 1 || (bytes[1] & 0x80)) {
          image.warnings.push_back("Unsupported .eh_frame_hdr encoding");
          continue;
        }
        llvm::DWARFDataExtractor data(
            llvm::StringRef(reinterpret_cast<const char *>(bytes),
                            header.file_size),
            true, 8);
        std::uint64_t cursor = 4;
        const auto encoded = [&](std::uint8_t encoding) -> std::optional<std::uint64_t> {
          if (encoding == 0xff || (encoding & 0x80)) return std::nullopt;
          const auto before = cursor;
          auto value = data.getEncodedPointer(&cursor, encoding & 0x0f, 0);
          if (!value || cursor == before || cursor > header.file_size) return std::nullopt;
          switch (encoding & 0x70) {
          case 0: return value;
          case 0x10: return *value + header.address + before;
          case 0x30: return *value + header.address;
          default: return std::nullopt;
          }
        };
        auto address = encoded(bytes[1]);
        auto count = (bytes[2] & 0xf0) ? std::nullopt : encoded(bytes[2]);
        if (!address || !count || bytes[3] == 0xff) {
          image.warnings.push_back("Unsupported .eh_frame_hdr pointer/count/table");
          continue;
        }
        if (*count > limits.max_entries)
          throw Error("E_RESOURCE_LIMIT", "EH search table exceeds metadata budget", 1);
        view.use(*count * 2 + 1);
        std::uint64_t end = *address, previous_pc = 0;
        bool supported = true;
        for (std::uint64_t i = 0; i < *count; i++) {
          auto pc = encoded(bytes[3]), fde = encoded(bytes[3]);
          if (!pc || !fde) { supported = false; break; }
          if ((i && *pc < previous_pc) || *fde < *address)
            throw Error("E_ELF_INVALID", "Malformed EH binary search table");
          previous_pc = *pc;
          auto off = view.offset(*fde, 4);
          std::uint64_t prefix = 4, length = view.get<std::uint32_t>(off);
          if (!length) throw Error("E_ELF_INVALID", "EH search entry points to a terminator");
          if (length == UINT32_MAX) {
            prefix = 12;
            off = view.offset(*fde, 12);
            length = view.get<std::uint64_t>(off + 4);
          }
          if (length > UINT64_MAX - prefix || *fde > UINT64_MAX - prefix - length)
            throw Error("E_ELF_RANGE", "EH record extent wraps address space");
          view.offset(*fde, prefix + length);
          end = std::max(end, *fde + prefix + length);
        }
        if (!supported) {
          image.warnings.push_back("Unsupported EH binary search table encoding");
          continue;
        }
        if (end > *address)
          frame(image, view, view.offset(*address, end - *address), end - *address, *address);
      }
  if (image.entry && view.code(image.entry, 1) &&
      std::none_of(image.functions.begin(), image.functions.end(),
                   [&](const auto &f) { return f.address == image.entry; }))
    image.functions.push_back({"_entry", "elf_entry", image.entry, 0, 0, 0});
  // Sections already provide validated symbol/relocation tables. PT_DYNAMIC is
  // still checked, and is the source of truth when section headers are absent.
  std::map<std::uint64_t, std::size_t> relocation_files;
  for (std::size_t i = 0; i < image.relocations.size(); i++)
    relocation_files[image.relocations[i].file_offset] = i;
  for (const auto &dynamic : image.metadata)
    if (dynamic.type == PT_DYNAMIC) {
      std::map<std::int64_t, std::uint64_t> tags;
      bool terminated = false;
      for (std::uint64_t p = 0; p + sizeof(Elf64_Dyn) <= dynamic.file_size;
           p += sizeof(Elf64_Dyn)) {
        auto d = view.get<Elf64_Dyn>(dynamic.offset + p);
        if (d.d_tag == DT_NULL) {
          terminated = true;
          break;
        }
        tags[d.d_tag] = d.d_un.d_val;
      }
      if (!terminated)
        throw Error("E_ELF_INVALID", "Unterminated PT_DYNAMIC");
      for (const auto &descriptor : {std::array<std::int64_t,4>{DT_RELA, DT_RELASZ, DT_RELAENT, 24},
                                     std::array<std::int64_t,4>{DT_REL, DT_RELSZ, DT_RELENT, 16}}) {
        if (tags.contains(descriptor[0]) != tags.contains(descriptor[1]) ||
            (tags.contains(descriptor[2]) && tags[descriptor[2]] != std::uint64_t(descriptor[3])))
          throw Error("E_ELF_INVALID", "Malformed REL/RELA dynamic descriptors");
      }
      if ((tags.contains(DT_JMPREL) != tags.contains(DT_PLTRELSZ)) ||
          (tags.contains(DT_JMPREL) && (!tags.contains(DT_PLTREL) ||
           (tags[DT_PLTREL] != DT_RELA && tags[DT_PLTREL] != DT_REL))))
        throw Error("E_ELF_INVALID", "Malformed PLT relocation descriptors");
      if (tags.contains(DT_RELR) || tags.contains(DT_RELRSZ) ||
          tags.contains(DT_RELRENT)) {
        if (!tags.contains(DT_RELR) || !tags.contains(DT_RELRSZ) ||
            !tags.contains(DT_RELRENT) || tags[DT_RELRENT] != 8 ||
            tags[DT_RELRSZ] % 8)
          throw Error("E_ELF_INVALID",
                      "Incomplete or malformed DT_RELR descriptors");
        auto bytes = tags[DT_RELRSZ], off = view.offset(tags[DT_RELR], bytes);
        std::uint64_t cursor = 0;
        bool anchored = false;
        std::set<std::uint64_t> targets;
        const auto append = [&](std::uint64_t address, std::uint64_t entry) {
          view.use();
          if (address > UINT64_MAX - 8)
            throw Error("E_ELF_RANGE", "RELR target wraps address space");
          if (image.relocations.size() >= limits.max_entries)
            throw Error("E_RESOURCE_LIMIT",
                        "RELR expansion exceeds relocation budget", 1);
          bool mapped = false;
          for (const auto &s : image.segments)
            if (address >= s.address && address - s.address <= s.memory_size &&
                8 <= s.memory_size - (address - s.address))
              mapped = true;
          if (!mapped || !targets.insert(address).second)
            throw Error("E_ELF_INVALID", "Unmapped or duplicate RELR target");
          image.relocations.push_back({"DT_RELR", "", address, 0,
                                       R_X86_64_RELATIVE, 0, false, 0, 0,
                                       SHN_ABS, 0, 0, true, entry, 0});
        };
        for (std::uint64_t i = 0; i < bytes; i += 8) {
          auto word = view.get<std::uint64_t>(off + i);
          if (!(word & 1)) {
            append(word, off + i);
            cursor = word + 8;
            anchored = true;
          } else {
            if (!anchored || cursor > UINT64_MAX - 63 * 8)
              throw Error("E_ELF_INVALID", "RELR bitmap has no valid anchor");
            for (unsigned bit = 1; bit < 64; bit++)
              if (word & (UINT64_C(1) << bit))
                append(cursor + (bit - 1) * 8, off + i);
            cursor += 63 * 8;
          }
        }
      }
      if (!image.sections.empty()) {
        const auto mark = [&](std::int64_t pointer, std::int64_t length,
                              bool addend) {
          if (!tags.contains(pointer) || !tags.contains(length))
            return;
          const auto width = addend ? sizeof(Elf64_Rela) : sizeof(Elf64_Rel),
                     bytes = tags[length];
          if (bytes % width || bytes / width > limits.max_entries)
            throw Error("E_ELF_INVALID",
                        "Invalid active relocation table size");
          auto off = view.offset(tags[pointer], bytes);
          auto sym =
              tags.contains(DT_SYMTAB) ? view.offset(tags[DT_SYMTAB]) : 0;
          for (std::uint64_t at = 0; at < bytes; at += width) {
            auto found = relocation_files.find(off + at);
            if (found == relocation_files.end()) {
              image.dynamic_complete = false;
              continue;
            }
            auto &r = image.relocations[found->second];
            if (r.explicit_addend != addend || r.symbol_table_offset != sym) {
              image.dynamic_complete = false;
              continue;
            }
            r.active_dynamic = true;
          }
        };
        mark(DT_RELA, DT_RELASZ, true);
        mark(DT_REL, DT_RELSZ, false);
        if (tags.contains(DT_JMPREL) && tags.contains(DT_PLTRELSZ)) {
          if (tags[DT_PLTREL] != DT_RELA && tags[DT_PLTREL] != DT_REL)
            throw Error("E_ELF_INVALID", "Invalid DT_PLTREL");
          mark(DT_JMPREL, DT_PLTRELSZ, tags[DT_PLTREL] == DT_RELA);
        }
        continue;
      }
      if (!tags.contains(DT_SYMTAB) || !tags.contains(DT_STRTAB) ||
          !tags.contains(DT_STRSZ)) {
        image.dynamic_complete = false;
        continue;
      }
      if (tags.contains(DT_SYMENT) && tags[DT_SYMENT] != sizeof(Elf64_Sym))
        throw Error("E_ELF_INVALID", "Invalid DT_SYMENT");
      auto str = view.offset(tags[DT_STRTAB], tags[DT_STRSZ]),
           symbols = view.offset(tags[DT_SYMTAB]);
      std::uint64_t count = 0;
      if (tags.contains(DT_HASH))
        count = view.get<std::uint32_t>(view.offset(tags[DT_HASH], 8) + 4);
      else if (tags.contains(DT_GNU_HASH)) {
        auto hash = view.offset(tags[DT_GNU_HASH], 16);
        auto buckets = view.get<std::uint32_t>(hash),
             first = view.get<std::uint32_t>(hash + 4),
             bloom = view.get<std::uint32_t>(hash + 8);
        if (buckets > limits.max_entries || bloom > limits.max_entries)
          throw Error("E_RESOURCE_LIMIT", "GNU hash header exceeds budget", 1);
        auto table = hash + 16 + std::uint64_t(bloom) * 8;
        view.range(table, std::uint64_t(buckets) * 4);
        count = first;
        for (std::uint64_t i = 0; i < buckets; i++) {
          auto index = view.get<std::uint32_t>(table + i * 4);
          if (!index)
            continue;
          if (index < first)
            throw Error("E_ELF_INVALID", "Invalid GNU hash bucket");
          while (true) {
            if (index >= limits.max_entries)
              throw Error("E_RESOURCE_LIMIT", "GNU hash chain exceeds budget",
                          1);
            auto value =
                view.get<std::uint32_t>(table + std::uint64_t(buckets) * 4 +
                                        std::uint64_t(index - first) * 4);
            count = std::max(count, std::uint64_t(index) + 1);
            if (value & 1)
              break;
            index++;
          }
        }
      } else {
        image.dynamic_complete = false;
        continue;
      }
      if (count > limits.max_entries)
        throw Error("E_RESOURCE_LIMIT", "Dynamic symbol count exceeds budget",
                    1);
      view.range(symbols, count * sizeof(Elf64_Sym));
      std::vector<Symbol> dyn;
      for (std::uint64_t i = 0; i < count; i++) {
        auto s = view.get<Elf64_Sym>(symbols + i * sizeof(Elf64_Sym));
        auto n = view.string(str, tags[DT_STRSZ], s.st_name);
        Symbol symbol{n,
                      "dynamic",
                      s.st_value,
                      s.st_size,
                      s.st_shndx,
                      std::uint8_t(ELF64_ST_TYPE(s.st_info)),
                      std::uint8_t(ELF64_ST_BIND(s.st_info))};
        dyn.push_back(symbol);
        image.symbols.push_back(symbol);
        if (s.st_shndx == SHN_UNDEF) {
          if (!n.empty())
            image.imports.push_back(
                {n, "dynamic", symbol.binding, symbol.type});
        } else if (symbol.type == STT_FUNC && view.code(s.st_value, s.st_size))
          image.functions.push_back({n, "dynamic", s.st_value, s.st_size,
                                     s.st_shndx, symbol.binding});
      }
      const auto rels = [&](std::uint64_t va, std::uint64_t bytes, bool addend,
                            const std::string &source) {
        auto width = addend ? sizeof(Elf64_Rela) : sizeof(Elf64_Rel);
        if (bytes % width)
          throw Error("E_ELF_INVALID", "Invalid dynamic relocation size");
        auto off = view.offset(va, bytes);
        if (bytes / width > limits.max_entries)
          throw Error("E_RESOURCE_LIMIT", "Too many relocations", 1);
        for (std::uint64_t at = 0; at < bytes; at += width) {
          auto r = view.get<Elf64_Rel>(off + at);
          auto index = ELF64_R_SYM(r.r_info);
          if (index >= dyn.size())
            throw Error("E_ELF_INVALID",
                        "Dynamic relocation symbol out of range");
          const auto &s = dyn[index];
          image.relocations.push_back(
              {source, s.name, r.r_offset, index,
               std::uint32_t(ELF64_R_TYPE(r.r_info)),
               addend ? view.get<Elf64_Rela>(off + at).r_addend : 0, addend,
               s.value, s.size, s.section, s.type, s.binding, true, off + at,
               symbols});
        }
      };
      if (tags.contains(DT_RELA) && tags.contains(DT_RELASZ))
        rels(tags[DT_RELA], tags[DT_RELASZ], true, "DT_RELA");
      if (tags.contains(DT_REL) && tags.contains(DT_RELSZ))
        rels(tags[DT_REL], tags[DT_RELSZ], false, "DT_REL");
      if (tags.contains(DT_JMPREL) && tags.contains(DT_PLTRELSZ))
        rels(tags[DT_JMPREL], tags[DT_PLTRELSZ], tags[DT_PLTREL] == DT_RELA,
             "DT_JMPREL");
      image.dynamic_complete = true;
    }
}
} // namespace zvril
