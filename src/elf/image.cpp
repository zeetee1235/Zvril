#include "zvril/elf/image.h"

#include <algorithm>
#include <bit>
#include <cstring>
#include <elf.h>
#include <fstream>
#include <limits>
#include <span>
#include <tuple>

namespace zvril {
namespace {

[[noreturn]] void invalid(const std::string &message) {
  throw Error("E_ELF_INVALID", message);
}

class Reader {
  std::span<const std::uint8_t> bytes_;
  Limits limits_;
  std::uint64_t entries_ = 0;
  std::uint64_t strings_ = 0;

public:
  Reader(const std::vector<std::uint8_t> &bytes, Limits limits)
      : bytes_(bytes), limits_(limits) {}

  void range(std::uint64_t offset, std::uint64_t length) const {
    if (offset > bytes_.size() || length > bytes_.size() - offset)
      throw Error("E_ELF_RANGE",
                  "File range exceeds input: offset=" + std::to_string(offset) +
                      " size=" + std::to_string(length));
  }

  template <class T> T get(std::uint64_t offset) const {
    range(offset, sizeof(T));
    T value;
    std::memcpy(&value, bytes_.data() + offset, sizeof(T));
    return value;
  }

  void table(std::uint64_t offset, std::uint64_t count, std::uint64_t width) {
    if (!width || offset > bytes_.size() ||
        count > (bytes_.size() - offset) / width)
      throw Error("E_ELF_RANGE", "ELF table extends beyond input");
    if (count > limits_.max_entries - entries_)
      throw Error("E_RESOURCE_LIMIT", "ELF table entry budget exceeded", 1);
    entries_ += count;
  }

  std::string string(const Section &section, std::uint64_t offset) {
    if (section.type != SHT_STRTAB || offset >= section.size)
      invalid("Invalid string table reference");
    range(section.offset, section.size);
    const auto *begin =
        reinterpret_cast<const char *>(bytes_.data() + section.offset + offset);
    const auto available = section.size - offset;
    constexpr std::uint64_t max_length = 1024 * 1024;
    const auto scanned = std::min(available, max_length + 1);
    const auto *end =
        static_cast<const char *>(std::memchr(begin, '\0', scanned));
    if (!end) {
      if (available > max_length)
        throw Error("E_RESOURCE_LIMIT", "ELF string exceeds 1 MiB", 1);
      invalid("Unterminated ELF string");
    }
    const auto length = static_cast<std::uint64_t>(end - begin);
    if (length > limits_.max_string_bytes - strings_)
      throw Error("E_RESOURCE_LIMIT", "ELF metadata string budget exceeded", 1);
    strings_ += length;
    return std::string(begin, end);
  }
};

bool wraps(std::uint64_t address, std::uint64_t length) {
  return length > std::numeric_limits<std::uint64_t>::max() - address;
}

bool executable(const std::vector<Segment> &segments, std::uint64_t address,
                std::uint64_t size) {
  auto next = std::upper_bound(
      segments.begin(), segments.end(), address,
      [](auto pc, const auto &segment) { return pc < segment.address; });
  if (next == segments.begin())
    return false;
  const auto &segment = *std::prev(next);
  const auto relative = address - segment.address;
  return relative < segment.memory_size &&
         size <= segment.memory_size - relative;
}

} // namespace

Image load(const std::filesystem::path &path, const Limits &limits) {
  std::error_code ec;
  if (!std::filesystem::is_regular_file(path, ec) || ec)
    throw Error("E_INPUT", "Input must be a readable regular file");
  const auto size = std::filesystem::file_size(path, ec);
  if (ec)
    throw Error("E_INPUT", "Cannot stat input");
  if (size > limits.max_bytes ||
      size > std::numeric_limits<std::size_t>::max() ||
      size > static_cast<std::uint64_t>(
                 std::numeric_limits<std::streamsize>::max()))
    throw Error("E_RESOURCE_LIMIT", "Input exceeds --max-bytes", 1);
  std::ifstream stream(path, std::ios::binary);
  if (!stream)
    throw Error("E_INPUT", "Cannot open input");
  std::vector<std::uint8_t> bytes(static_cast<std::size_t>(size));
  if (size && !stream.read(reinterpret_cast<char *>(bytes.data()),
                           static_cast<std::streamsize>(size)))
    throw Error("E_INPUT", "Cannot read complete input");
  if (stream.peek() != std::char_traits<char>::eof())
    throw Error("E_INPUT", "Input size changed while reading");
  return parse(std::move(bytes), limits);
}

Image parse(std::vector<std::uint8_t> bytes, const Limits &limits) {
  static_assert(std::endian::native == std::endian::little,
                "This baseline supports little-endian hosts");
  if (bytes.size() > limits.max_bytes)
    throw Error("E_RESOURCE_LIMIT", "Input exceeds byte budget", 1);
  Image image;
  image.bytes = std::move(bytes);
  Reader reader(image.bytes, limits);
  reader.range(0, EI_NIDENT);
  const auto *ident = image.bytes.data();
  if (std::memcmp(ident, ELFMAG, SELFMAG))
    invalid("Missing ELF magic");
  if (ident[EI_CLASS] != ELFCLASS64 || ident[EI_DATA] != ELFDATA2LSB)
    invalid("Only ELF64 little-endian input is supported");
  if (ident[EI_VERSION] != EV_CURRENT)
    invalid("Invalid ELF identification version");
  const auto header = reader.get<Elf64_Ehdr>(0);
  if (header.e_machine != EM_X86_64)
    invalid("Only EM_X86_64 is supported");
  if (header.e_type != ET_EXEC && header.e_type != ET_DYN)
    invalid("Only ET_EXEC and ET_DYN are supported");
  if (header.e_version != EV_CURRENT || header.e_ehsize != sizeof(Elf64_Ehdr))
    invalid("Invalid ELF header version or size");
  image.type = header.e_type;
  image.entry = header.e_entry;
  std::uint64_t section_count = header.e_shnum;
  std::uint64_t program_count = header.e_phnum;
  std::uint64_t names_index = header.e_shstrndx;
  if (header.e_shoff) {
    if (header.e_shentsize != sizeof(Elf64_Shdr))
      invalid("Invalid section header entry size");
    const auto first = reader.get<Elf64_Shdr>(header.e_shoff);
    if (first.sh_type != SHT_NULL)
      invalid("Section zero must be SHT_NULL");
    if (!section_count)
      section_count = first.sh_size;
    if (!section_count)
      invalid("Section table has no section zero");
    if (program_count == PN_XNUM)
      program_count = first.sh_info;
    if (names_index == SHN_XINDEX)
      names_index = first.sh_link;
  } else if (section_count || names_index != SHN_UNDEF ||
             program_count == PN_XNUM) {
    invalid("Missing section table for declared section metadata");
  }
  if (program_count) {
    if (!header.e_phoff || header.e_phentsize != sizeof(Elf64_Phdr))
      invalid("Invalid program header table");
    reader.table(header.e_phoff, program_count, sizeof(Elf64_Phdr));
  }
  image.program_header_count = program_count;
  for (std::uint64_t i = 0; i < program_count; ++i) {
    const auto ph =
        reader.get<Elf64_Phdr>(header.e_phoff + i * sizeof(Elf64_Phdr));
    reader.range(ph.p_offset, ph.p_filesz);
    if (ph.p_type == PT_DYNAMIC || ph.p_type == PT_TLS ||
        ph.p_type == PT_INTERP || ph.p_type == PT_GNU_EH_FRAME ||
        ph.p_type == PT_GNU_RELRO) {
      if (ph.p_filesz > ph.p_memsz || wraps(ph.p_vaddr, ph.p_memsz) ||
          (ph.p_align > 1 && (ph.p_align & (ph.p_align - 1))))
        invalid("Invalid program metadata extent or alignment");
      image.metadata.push_back({ph.p_type, ph.p_vaddr, ph.p_offset, ph.p_filesz,
                                ph.p_memsz, ph.p_align});
    }
    if (ph.p_type != PT_LOAD)
      continue;
    if (ph.p_filesz > ph.p_memsz || wraps(ph.p_vaddr, ph.p_memsz))
      invalid("Invalid PT_LOAD memory size or address overflow");
    if (ph.p_align > 1 &&
        ((ph.p_align & (ph.p_align - 1)) ||
         (ph.p_vaddr % ph.p_align != ph.p_offset % ph.p_align)))
      invalid("Invalid PT_LOAD alignment");
    image.segments.push_back({ph.p_offset, ph.p_vaddr, ph.p_filesz, ph.p_memsz,
                              ph.p_align, ph.p_flags});
  }
  std::sort(image.segments.begin(), image.segments.end(),
            [](const auto &a, const auto &b) {
              return std::tie(a.address, a.offset) <
                     std::tie(b.address, b.offset);
            });
  std::uint64_t last_end = 0;
  for (const auto &segment : image.segments) {
    if (!segment.memory_size)
      continue;
    if (segment.address < last_end)
      invalid("Overlapping PT_LOAD segments are unsupported");
    last_end = segment.address + segment.memory_size;
  }
  std::vector<Segment> executable_segments;
  for (const auto &segment : image.segments)
    if ((segment.flags & PF_X) && segment.memory_size)
      executable_segments.push_back(segment);
  if (section_count)
    reader.table(header.e_shoff, section_count, sizeof(Elf64_Shdr));
  for (std::uint64_t i = 0; i < section_count; ++i) {
    const auto sh =
        reader.get<Elf64_Shdr>(header.e_shoff + i * sizeof(Elf64_Shdr));
    // sh_size in section zero may encode the extended section count.
    if (i && sh.sh_type != SHT_NOBITS)
      reader.range(sh.sh_offset, sh.sh_size);
    if (wraps(sh.sh_addr, sh.sh_size))
      invalid("Section address overflow");
    if (sh.sh_addralign > 1 && (sh.sh_addralign & (sh.sh_addralign - 1)))
      invalid("Invalid section alignment");
    image.sections.push_back({"", sh.sh_type, sh.sh_link, sh.sh_addr,
                              sh.sh_offset, sh.sh_size, sh.sh_flags,
                              sh.sh_entsize});
  }
  if (names_index != SHN_UNDEF) {
    if (names_index >= section_count)
      invalid("Section name table index is out of range");
    for (std::uint64_t i = 0; i < section_count; ++i) {
      const auto sh =
          reader.get<Elf64_Shdr>(header.e_shoff + i * sizeof(Elf64_Shdr));
      image.sections[i].name =
          reader.string(image.sections[names_index], sh.sh_name);
    }
  }
  const auto sym_at = [&](const Section &table, std::uint64_t index) {
    return reader.get<Elf64_Sym>(table.offset + index * sizeof(Elf64_Sym));
  };
  const auto symbol_section = [&](std::uint64_t table, std::uint64_t index,
                                  const Elf64_Sym &symbol) -> std::uint32_t {
    if (symbol.st_shndx != SHN_XINDEX)
      return symbol.st_shndx;
    const Section *indices = nullptr;
    for (const auto &s : image.sections)
      if (s.type == SHT_SYMTAB_SHNDX && s.link == table) {
        if (indices)
          invalid("Duplicate extended symbol index tables");
        indices = &s;
      }
    if (!indices || indices->entry_size != 4 ||
        indices->size != image.sections[table].size / sizeof(Elf64_Sym) * 4)
      invalid("Missing or malformed extended symbol index table");
    const auto value = reader.get<std::uint32_t>(indices->offset + index * 4);
    if (value >= section_count)
      invalid("Extended symbol section index is out of range");
    return value;
  };
  for (std::size_t i = 0; i < image.sections.size(); ++i) {
    const auto &section = image.sections[i];
    if (section.type != SHT_SYMTAB && section.type != SHT_DYNSYM)
      continue;
    if (section.entry_size != sizeof(Elf64_Sym) ||
        section.size % sizeof(Elf64_Sym))
      invalid("Invalid symbol table entry size");
    if (section.link >= section_count ||
        image.sections[section.link].type != SHT_STRTAB)
      invalid("Invalid symbol string table link");
    const auto count = section.size / sizeof(Elf64_Sym);
    reader.table(section.offset, count, sizeof(Elf64_Sym));
    const auto source = (section.type == SHT_SYMTAB ? "symtab:" : "dynsym:") +
                        std::to_string(i);
    for (std::uint64_t index = 0; index < count; ++index) {
      const auto sym = sym_at(section, index);
      const auto name =
          reader.string(image.sections[section.link], sym.st_name);
      const auto shndx = symbol_section(i, index, sym);
      image.symbols.push_back(
          {name, source, sym.st_value, sym.st_size, shndx,
           static_cast<std::uint8_t>(ELF64_ST_TYPE(sym.st_info)),
           static_cast<std::uint8_t>(ELF64_ST_BIND(sym.st_info))});
      if (shndx < SHN_LORESERVE && shndx >= section_count)
        invalid("Symbol section index is out of range");
      if (shndx == SHN_UNDEF) {
        if (!name.empty())
          image.imports.push_back(
              {name, source,
               static_cast<std::uint8_t>(ELF64_ST_BIND(sym.st_info)),
               static_cast<std::uint8_t>(ELF64_ST_TYPE(sym.st_info))});
        continue;
      }
      if (ELF64_ST_TYPE(sym.st_info) != STT_FUNC ||
          (sym.st_shndx != SHN_XINDEX && shndx >= SHN_LORESERVE))
        continue;
      const auto &owner = image.sections[shndx];
      if (wraps(sym.st_value, sym.st_size) || sym.st_value < owner.address ||
          sym.st_value - owner.address > owner.size ||
          sym.st_size > owner.size - (sym.st_value - owner.address))
        invalid("Function symbol extends beyond its section");
      if (!(owner.flags & SHF_EXECINSTR) ||
          !executable(executable_segments, sym.st_value, sym.st_size))
        invalid("Function symbol is outside executable PT_LOAD memory");
      image.functions.push_back(
          {name, source, sym.st_value, sym.st_size, shndx,
           static_cast<std::uint8_t>(ELF64_ST_BIND(sym.st_info))});
    }
  }
  for (const auto &section : image.sections) {
    if (section.type != SHT_REL && section.type != SHT_RELA)
      continue;
    const auto width =
        section.type == SHT_RELA ? sizeof(Elf64_Rela) : sizeof(Elf64_Rel);
    if (section.entry_size != width || section.size % width)
      invalid("Invalid relocation entry size");
    if (section.link >= section_count)
      invalid("Relocation symbol table link is out of range");
    const auto &symbols = image.sections[section.link];
    // A relocation section may reference the reserved null symbol when it has
    // no symbolic relocations at all (for example static IRELATIVE entries).
    // Such sections legitimately carry sh_link == 0.
    const bool null_symbols =
        symbols.type != SHT_SYMTAB && symbols.type != SHT_DYNSYM;
    if (null_symbols && section.link != 0)
      invalid("Relocation does not link a symbol table");
    reader.table(section.offset, section.size / width, width);
    for (std::uint64_t i = 0; i < section.size / width; ++i) {
      const auto at = section.offset + i * width;
      const auto rel = reader.get<Elf64_Rel>(at);
      const auto sym_index = ELF64_R_SYM(rel.r_info);
      if (null_symbols && sym_index != 0)
        invalid("Relocation references a missing symbol table");
      if (!null_symbols && sym_index >= symbols.size / sizeof(Elf64_Sym))
        invalid("Relocation symbol index is out of range");
      const auto sym = null_symbols ? Elf64_Sym{} : sym_at(symbols, sym_index);
      const auto symbol_name =
          null_symbols
              ? std::string{}
              : reader.string(image.sections[symbols.link], sym.st_name);
      const bool has_addend = section.type == SHT_RELA;
      const auto addend = has_addend ? reader.get<Elf64_Rela>(at).r_addend : 0;
      image.relocations.push_back(
          {section.name, symbol_name, rel.r_offset, sym_index,
           static_cast<std::uint32_t>(ELF64_R_TYPE(rel.r_info)), addend,
           has_addend, sym.st_value, sym.st_size,
           null_symbols ? std::uint32_t{0}
                        : symbol_section(section.link, sym_index, sym),
           static_cast<std::uint8_t>(ELF64_ST_TYPE(sym.st_info)),
           static_cast<std::uint8_t>(ELF64_ST_BIND(sym.st_info)), false, at,
           symbols.offset});
    }
  }
  discover_metadata(image, limits);
  discover_versions(image, limits);
  std::sort(image.functions.begin(), image.functions.end(),
            [](const auto &a, const auto &b) {
              return std::tie(a.address, a.name, a.source) <
                     std::tie(b.address, b.name, b.source);
            });
  std::sort(image.imports.begin(), image.imports.end(),
            [](const auto &a, const auto &b) {
              return std::tie(a.name, a.source) < std::tie(b.name, b.source);
            });
  return image;
}

std::vector<std::uint8_t> demo_elf(bool dynamic, bool stripped) {
  // Self-contained data fixture, never mapped executable or invoked.
  std::vector<std::uint8_t> bytes(512, 0);
  Elf64_Ehdr eh{};
  std::memcpy(eh.e_ident, ELFMAG, SELFMAG);
  eh.e_ident[EI_CLASS] = ELFCLASS64;
  eh.e_ident[EI_DATA] = ELFDATA2LSB;
  eh.e_ident[EI_VERSION] = EV_CURRENT;
  eh.e_type = dynamic ? ET_DYN : ET_EXEC;
  eh.e_machine = EM_X86_64;
  eh.e_version = EV_CURRENT;
  eh.e_ehsize = sizeof(eh);
  eh.e_phoff = sizeof(eh);
  eh.e_phentsize = sizeof(Elf64_Phdr);
  eh.e_phnum = 1;
  eh.e_entry = dynamic ? 0x100 : 0x400100;
  Elf64_Phdr ph{};
  ph.p_type = PT_LOAD;
  ph.p_flags = PF_R | PF_X;
  ph.p_vaddr = dynamic ? 0 : 0x400000;
  ph.p_filesz = bytes.size();
  ph.p_memsz = bytes.size() + 32;
  ph.p_align = 4096;
  bytes[256] = 0xc3; // ret, used only as opaque file bytes by the analyzer.
  if (!stripped) {
    eh.e_shoff = 320;
    eh.e_shentsize = sizeof(Elf64_Shdr);
    eh.e_shnum = 3;
    Elf64_Shdr text{};
    text.sh_type = SHT_PROGBITS;
    text.sh_flags = SHF_ALLOC | SHF_EXECINSTR;
    text.sh_addr = eh.e_entry;
    text.sh_offset = 256;
    text.sh_size = 1;
    text.sh_addralign = 1;
    Elf64_Shdr bss{};
    bss.sh_type = SHT_NOBITS;
    bss.sh_flags = SHF_ALLOC;
    bss.sh_addr = ph.p_vaddr + bytes.size();
    bss.sh_offset = bytes.size();
    bss.sh_size = 32;
    bss.sh_addralign = 1;
    std::memcpy(bytes.data() + eh.e_shoff + sizeof(Elf64_Shdr), &text,
                sizeof(text));
    std::memcpy(bytes.data() + eh.e_shoff + 2 * sizeof(Elf64_Shdr), &bss,
                sizeof(bss));
  }
  std::memcpy(bytes.data(), &eh, sizeof(eh));
  std::memcpy(bytes.data() + eh.e_phoff, &ph, sizeof(ph));
  return bytes;
}

} // namespace zvril
