#include "zvril/elf/image.h"
#include "zvril/process_files.h"
#include <algorithm>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <fstream>
#include <limits>
#include <map>
#include <set>
#include <sys/stat.h>
#include <unistd.h>

namespace zvril {
namespace {
constexpr std::uint64_t limit = 64 * 1024 * 1024, io_limit = 1024 * 1024;
std::uint64_t failure(int e) { return std::uint64_t(0) - unsigned(e); }
std::string normalized(const std::string &path) {
  std::vector<std::string> components;
  std::size_t at = 0;
  while (at < path.size()) {
    auto end = path.find('/', at);
    if (end == std::string::npos)
      end = path.size();
    auto part = path.substr(at, end - at);
    at = end + 1;
    if (part == "..") {
      if (!components.empty())
        components.pop_back();
    } else if (!part.empty() && part != ".")
      components.push_back(std::move(part));
  }
  std::string result = "/";
  for (auto &part : components) {
    if (result.size() > 1)
      result += '/';
    result += part;
  }
  return result;
}
struct GuestStat {
  std::uint64_t dev = 1, ino = 1, nlink = 1;
  std::uint32_t mode = 0100644, uid = 1000, gid = 1000, pad = 0;
  std::uint64_t rdev = 0;
  std::int64_t size = 0, blksize = 4096, blocks = 0;
  std::int64_t atime = 0, atime_ns = 0, mtime = 0, mtime_ns = 0, ctime = 0,
               ctime_ns = 0, reserved[3]{};
};
static_assert(sizeof(GuestStat) == 144);
struct GuestStatFS {
  std::int64_t type = 0x01021994, block_size = 4096, blocks = 1 << 20,
               blocks_free = 1 << 19, blocks_available = 1 << 19,
               files = 1 << 20, files_free = 1 << 19;
  std::int32_t fsid[2]{};
  std::int64_t name_length = 255, fragment_size = 4096, flags = 0,
               spare[4]{};
};
static_assert(sizeof(GuestStatFS) == 120);
struct GuestStatXTimestamp {
  std::int64_t seconds = 0;
  std::uint32_t nanoseconds = 0;
  std::int32_t reserved = 0;
};
struct GuestStatX {
  std::uint32_t mask = 0x7ff, block_size = 4096;
  std::uint64_t attributes = 0;
  std::uint32_t links = 1, uid = 1000, gid = 1000;
  std::uint16_t mode = 0100644, spare0 = 0;
  std::uint64_t inode = 1, size = 0, blocks = 0, attributes_mask = 0;
  GuestStatXTimestamp atime, btime, ctime, mtime;
  std::uint32_t rdev_major = 0, rdev_minor = 0, dev_major = 0, dev_minor = 0;
  std::uint64_t spare[14]{};
};
static_assert(sizeof(GuestStatX) == 256);
struct Node {
  std::string path;
  std::vector<std::uint8_t> bytes;
  GuestStat stat;
  bool changed = false;
};
struct Description {
  std::shared_ptr<Node> node;
  std::uint64_t offset = 0;
  int flags = 0, console = -1;
};
struct Descriptor {
  std::shared_ptr<Description> description;
  bool close_exec = false;
};
} // namespace
std::filesystem::path process_host_path(const std::filesystem::path &root,
                                        const std::string &guest) {
  if (root.empty())
    throw Error("E_PROCESS_FILESYSTEM", "Host-backed files require --sysroot",
                1);
  std::error_code error;
  auto base = std::filesystem::canonical(root, error);
  if (error)
    throw Error("E_PROCESS_FILESYSTEM", "Invalid sysroot", 3);
  auto candidate =
      std::filesystem::canonical(base / normalized(guest).substr(1), error);
  if (error)
    return {};
  auto relative = candidate.lexically_relative(base);
  if (relative.empty() || (*relative.begin()) == "..")
    return {};
  return candidate;
}
struct ProcessFiles::Impl {
  ZvrilRuntime *memory;
  std::filesystem::path root;
  std::string executable, cwd = "/";
  std::map<std::string, std::shared_ptr<Node>> nodes;
  std::set<std::string> removed;
  std::map<int, Descriptor> descriptors;
  std::vector<std::uint8_t> input, stdout_data, stderr_data;
  std::uint64_t next_inode = 2;
  Impl(ZvrilRuntime *r, const std::filesystem::path &p,
       const std::vector<std::uint8_t> &in, const std::string &exe)
      : memory(r), root(p), executable(exe), input(in) {
    for (int i = 0; i < 3; i++) {
      auto d = std::make_shared<Description>();
      d->console = i;
      d->flags = i ? O_WRONLY : O_RDONLY;
      descriptors.emplace(i, Descriptor{std::move(d), false});
    }
  }
  bool read(std::uint64_t address, void *data, std::uint64_t size) {
    if (zvril_runtime_read(memory, address, data, size))
      return true;
    zvril_runtime_clear_fault(memory);
    return false;
  }
  bool write(std::uint64_t address, const void *data, std::uint64_t size) {
    if (zvril_runtime_write(memory, address, data, size))
      return true;
    zvril_runtime_clear_fault(memory);
    return false;
  }
  bool path(std::uint64_t address, std::string &out) {
    out.clear();
    for (unsigned i = 0; i < 4096; i++) {
      char c;
      if (address > UINT64_MAX - i || !read(address + i, &c, 1))
        return false;
      if (!c)
        return true;
      out += c;
    }
    return false;
  }
  bool resolve(std::uint64_t dir, std::uint64_t address, std::string &name,
               int &error) {
    if (!path(address, name)) {
      error = EFAULT;
      return false;
    }
    if (name.empty()) {
      error = ENOENT;
      return false;
    }
    if (name[0] != '/') {
      std::string base = cwd;
      if (std::int32_t(dir) != -100) {
        auto f = descriptors.find(int(dir));
        if (dir > INT32_MAX || f == descriptors.end()) {
          error = EBADF;
          return false;
        }
        if (!f->second.description->node ||
            !S_ISDIR(f->second.description->node->stat.mode)) {
          error = ENOTDIR;
          return false;
        }
        base = f->second.description->node->path;
      }
      name = base + "/" + name;
    }
    name = normalized(name);
    return true;
  }
  std::shared_ptr<Node> node(const std::string &name, int &error) {
    if (removed.contains(name)) {
      error = ENOENT;
      return {};
    }
    if (auto i = nodes.find(name); i != nodes.end())
      return i->second;
    if (root.empty()) {
      error = ENOENT;
      return {};
    }
    auto host = process_host_path(root, name);
    if (host.empty()) {
      error = ENOENT;
      return {};
    }
    struct stat st{};
    if (::stat(host.c_str(), &st)) {
      error = errno;
      return {};
    }
    if (!S_ISREG(st.st_mode) && !S_ISDIR(st.st_mode)) {
      error = ENODEV;
      return {};
    }
    if (S_ISREG(st.st_mode) &&
        (st.st_size < 0 || std::uint64_t(st.st_size) > limit)) {
      error = EFBIG;
      return {};
    }
    auto n = std::make_shared<Node>();
    n->path = name;
    n->stat.dev = st.st_dev;
    n->stat.ino = st.st_ino;
    n->stat.nlink = st.st_nlink;
    n->stat.mode = st.st_mode;
    n->stat.uid = st.st_uid;
    n->stat.gid = st.st_gid;
    n->stat.rdev = st.st_rdev;
    n->stat.size = st.st_size;
    n->stat.blksize = st.st_blksize;
    n->stat.blocks = st.st_blocks;
    n->stat.atime = st.st_atim.tv_sec;
    n->stat.atime_ns = st.st_atim.tv_nsec;
    n->stat.mtime = st.st_mtim.tv_sec;
    n->stat.mtime_ns = st.st_mtim.tv_nsec;
    n->stat.ctime = st.st_ctim.tv_sec;
    n->stat.ctime_ns = st.st_ctim.tv_nsec;
    if (S_ISREG(st.st_mode)) {
      std::ifstream file(host, std::ios::binary);
      if (!file) {
        error = EACCES;
        return {};
      }
      n->bytes.resize(st.st_size);
      file.read(reinterpret_cast<char *>(n->bytes.data()), n->bytes.size());
      if (std::size_t(file.gcount()) != n->bytes.size()) {
        error = EIO;
        return {};
      }
    }
    nodes.emplace(name, n);
    return n;
  }
  int allocate(Descriptor descriptor, int minimum = 0) {
    for (int i = std::max(minimum, 0); i < 1024; i++)
      if (!descriptors.contains(i)) {
        descriptors.emplace(i, std::move(descriptor));
        return i;
      }
    return -1;
  }
  std::uint64_t open(std::uint64_t dir, std::uint64_t address,
                     std::uint64_t flags, std::uint64_t mode) {
    constexpr unsigned supported = O_ACCMODE | O_CREAT | O_EXCL | O_TRUNC |
                                   O_APPEND | O_CLOEXEC | O_DIRECTORY |
                                   O_NOFOLLOW | O_LARGEFILE | O_NONBLOCK;
    if (flags & ~std::uint64_t(supported))
      throw Error("E_PROCESS_FILESYSTEM", "Unmodeled open flags", 1);
    if ((flags & O_ACCMODE) == 3)
      return failure(EINVAL);
    std::string name;
    int error = 0;
    if (!resolve(dir, address, name, error))
      return failure(error);
    if ((flags & O_NOFOLLOW) && !root.empty()) {
      std::error_code ec;
      if (std::filesystem::is_symlink(root / name.substr(1), ec))
        return failure(ELOOP);
    }
    auto n = node(name, error);
    if (n && (flags & O_CREAT) && (flags & O_EXCL))
      return failure(EEXIST);
    if (!n) {
      if (!(flags & O_CREAT) || error != ENOENT)
        return failure(error);
      auto parent =
          node(std::filesystem::path(name).parent_path().string(), error);
      if (!parent || !S_ISDIR(parent->stat.mode))
        return failure(parent ? ENOTDIR : error);
      n = std::make_shared<Node>();
      n->path = name;
      n->stat.ino = next_inode++;
      n->stat.mode = 0100000 | (mode & 0777);
      n->changed = true;
      removed.erase(name);
      nodes[name] = n;
    }
    if ((flags & O_DIRECTORY) && !S_ISDIR(n->stat.mode))
      return failure(ENOTDIR);
    if (S_ISDIR(n->stat.mode) && (flags & O_ACCMODE) != O_RDONLY)
      return failure(EISDIR);
    if (flags & O_TRUNC) {
      if ((flags & O_ACCMODE) == O_RDONLY)
        return failure(EINVAL);
      n->bytes.clear();
      n->stat.size = 0;
      n->stat.blocks = 0;
      n->changed = true;
    }
    auto d = std::make_shared<Description>();
    d->node = n;
    d->flags = flags & ~(O_CREAT | O_EXCL | O_TRUNC | O_CLOEXEC);
    int fd = allocate({d, (flags & O_CLOEXEC) != 0});
    return fd < 0 ? failure(EMFILE) : std::uint64_t(fd);
  }
  std::uint64_t transfer(std::uint64_t fd, std::uint64_t address,
                         std::uint64_t count, bool writing,
                         std::optional<std::uint64_t> position = {}) {
    if (fd > INT32_MAX || !descriptors.contains(int(fd)))
      return failure(EBADF);
    auto &d = *descriptors.at(int(fd)).description;
    if ((writing && (d.flags & O_ACCMODE) == O_RDONLY) ||
        (!writing && (d.flags & O_ACCMODE) == O_WRONLY))
      return failure(EBADF);
    if (position && d.console >= 0)
      return failure(ESPIPE);
    if (d.node && S_ISDIR(d.node->stat.mode))
      return failure(EISDIR);
    auto at = position.value_or(d.offset);
    if (writing && d.node && (d.flags & O_APPEND))
      at = d.node->bytes.size();
    if (position && std::int64_t(*position) < 0)
      return failure(EINVAL);
    count = std::min(count, io_limit);
    auto *bytes = d.console == 0   ? &input
                  : d.console == 1 ? &stdout_data
                  : d.console == 2 ? &stderr_data
                                   : &d.node->bytes;
    if (!writing)
      count = at >= bytes->size()
                  ? 0
                  : std::min<std::uint64_t>(count, bytes->size() - at);
    if (!count)
      return 0;
    if (writing) {
      if (d.console >= 0)
        at = bytes->size();
      auto maximum = d.console >= 0 ? io_limit : limit;
      if (at > maximum || count > maximum - at)
        return failure(EFBIG);
      std::vector<std::uint8_t> data(count);
      if (!read(address, data.data(), count))
        return failure(EFAULT);
      if (at + count > bytes->size())
        bytes->resize(at + count);
      std::copy(data.begin(), data.end(), bytes->begin() + at);
      if (d.node) {
        d.node->stat.size = bytes->size();
        d.node->stat.blocks = (bytes->size() + 511) / 512;
        d.node->changed = true;
      }
    } else if (!write(address, bytes->data() + at, count))
      return failure(EFAULT);
    if (!position)
      d.offset = at + count;
    return count;
  }
  std::uint64_t mkdir_at(std::uint64_t dir, std::uint64_t path_address,
                         std::uint64_t mode) {
    std::string name;
    int error = 0;
    if (!resolve(dir, path_address, name, error))
      return failure(error);
    if (node(name, error))
      return failure(EEXIST);
    if (error != ENOENT)
      return failure(error);
    auto parent = node(std::filesystem::path(name).parent_path().string(),
                       error);
    if (!parent)
      return failure(error);
    if (!S_ISDIR(parent->stat.mode))
      return failure(ENOTDIR);
    auto n = std::make_shared<Node>();
    n->path = name;
    n->stat.ino = next_inode++;
    n->stat.mode = S_IFDIR | (mode & 07777);
    n->stat.nlink = 2;
    n->changed = true;
    removed.erase(name);
    nodes[name] = n;
    return 0;
  }
  std::uint64_t remove_entry(std::uint64_t dir, std::uint64_t path_address,
                             std::uint64_t flags) {
    if (flags & ~std::uint64_t(0x200))
      return failure(EINVAL);
    std::string name;
    int error = 0;
    if (!resolve(dir, path_address, name, error))
      return failure(error);
    auto n = node(name, error);
    if (!n)
      return failure(error);
    if (S_ISDIR(n->stat.mode)) {
      if (!(flags & 0x200))
        return failure(EISDIR);
      auto prefix = name == "/" ? std::string("/") : name + "/";
      for (const auto &[child, _] : nodes)
        if (child.starts_with(prefix) && child.size() > prefix.size() &&
            child.find('/', prefix.size()) == std::string::npos)
          return failure(ENOTEMPTY);
      if (!root.empty()) {
        auto host = process_host_path(root, name);
        std::error_code ec;
        if (!host.empty() &&
            std::filesystem::directory_iterator(host, ec) !=
                std::filesystem::directory_iterator())
          return failure(ENOTEMPTY);
      }
    }
    nodes.erase(name);
    removed.insert(name);
    return 0;
  }
  std::uint64_t rename_entry(std::uint64_t old_dir, std::uint64_t old_address,
                             std::uint64_t new_dir, std::uint64_t new_address,
                             std::uint64_t flags) {
    if (flags)
      return failure(EINVAL);
    std::string old_name, new_name;
    int error = 0;
    if (!resolve(old_dir, old_address, old_name, error) ||
        !resolve(new_dir, new_address, new_name, error))
      return failure(error);
    auto source = node(old_name, error);
    if (!source)
      return failure(error);
    auto parent = node(std::filesystem::path(new_name).parent_path().string(),
                       error);
    if (!parent)
      return failure(error);
    if (!S_ISDIR(parent->stat.mode))
      return failure(ENOTDIR);
    if (S_ISDIR(source->stat.mode) && old_name != new_name)
      return failure(EINVAL); // Host-backed directory moves are not virtualized.
    if (auto destination = node(new_name, error)) {
      if (S_ISDIR(destination->stat.mode) != S_ISDIR(source->stat.mode))
        return failure(S_ISDIR(source->stat.mode) ? EISDIR : ENOTDIR);
      nodes.erase(new_name);
    }
    removed.erase(new_name);
    nodes.erase(old_name);
    removed.insert(old_name);
    source->path = new_name;
    source->changed = true;
    nodes[new_name] = source;
    return 0;
  }
  std::uint64_t set_mode(std::uint64_t fd, std::uint64_t mode) {
    if (fd > INT32_MAX || !descriptors.contains(int(fd)))
      return failure(EBADF);
    auto &d = *descriptors.at(int(fd)).description;
    if (!d.node)
      return failure(EBADF);
    d.node->stat.mode = (d.node->stat.mode & 0170000) | (mode & 07777);
    d.node->changed = true;
    return 0;
  }
  std::uint64_t set_mode_path(std::uint64_t dir, std::uint64_t path_address,
                              std::uint64_t mode) {
    std::string name;
    int error = 0;
    if (!resolve(dir, path_address, name, error))
      return failure(error);
    auto n = node(name, error);
    if (!n)
      return failure(error);
    n->stat.mode = (n->stat.mode & 0170000) | (mode & 07777);
    n->changed = true;
    return 0;
  }
  std::uint64_t resize_node(const std::shared_ptr<Node> &node,
                            std::uint64_t size) {
    if (!node || S_ISDIR(node->stat.mode))
      return failure(EISDIR);
    if (size > 64 * 1024 * 1024)
      return failure(EFBIG);
    node->bytes.resize(size);
    node->stat.size = size;
    node->stat.blocks = (size + 511) / 512;
    node->changed = true;
    return 0;
  }
  std::uint64_t truncate_fd(std::uint64_t fd, std::uint64_t size) {
    if (fd > INT32_MAX || !descriptors.contains(int(fd)))
      return failure(EBADF);
    auto &description = *descriptors.at(int(fd)).description;
    if ((description.flags & O_ACCMODE) == O_RDONLY)
      return failure(EINVAL);
    return resize_node(description.node, size);
  }
  std::uint64_t truncate_path(std::uint64_t dir, std::uint64_t path_address,
                              std::uint64_t size) {
    std::string name;
    int error = 0;
    if (!resolve(dir, path_address, name, error))
      return failure(error);
    auto node = this->node(name, error);
    if (!node)
      return failure(error);
    return resize_node(node, size);
  }
  std::uint64_t sync_fd(std::uint64_t fd) {
    if (fd > INT32_MAX || !descriptors.contains(int(fd)))
      return failure(EBADF);
    return 0;
  }
  std::uint64_t stat_fd(std::uint64_t fd, std::uint64_t address) {
    if (fd > INT32_MAX || !descriptors.contains(int(fd)))
      return failure(EBADF);
    const auto &d = *descriptors.at(int(fd)).description;
    GuestStat stat;
    if (d.node)
      stat = d.node->stat;
    else {
      stat.mode = 0010600;
      stat.size = 0;
    }
    return write(address, &stat, sizeof(stat)) ? 0 : failure(EFAULT);
  }
  std::uint64_t getdents(std::uint64_t fd, std::uint64_t address,
                         std::uint64_t count) {
    if (fd > INT32_MAX || !descriptors.contains(int(fd)))
      return failure(EBADF);
    auto &d = *descriptors.at(int(fd)).description;
    if (!d.node || !S_ISDIR(d.node->stat.mode))
      return failure(ENOTDIR);
    if (count < 24)
      return failure(EINVAL);
    auto host = root.empty()
                    ? std::filesystem::path{}
                    : process_host_path(root, d.node->path);
    const bool virtual_directory = nodes.contains(d.node->path);
    if (host.empty() && !virtual_directory)
      return failure(ENOENT);
    struct Entry {
      std::string name;
      std::uint32_t ino;
      std::uint8_t type;
    };
    std::vector<Entry> ordered{{".", (std::uint32_t)d.node->stat.ino, 4},
                               {"..", (std::uint32_t)d.node->stat.ino, 4}};
    std::vector<Entry> children;
    std::error_code ec;
    if (!host.empty()) {
      for (const auto &entry : std::filesystem::directory_iterator(host, ec)) {
        struct stat st{};
        if (::lstat(entry.path().c_str(), &st))
          continue;
        auto name = entry.path().filename().string();
        auto full = d.node->path == "/" ? "/" + name : d.node->path + "/" + name;
        if (removed.contains(full))
          continue;
        auto type = S_ISREG(st.st_mode)   ? 8
                    : S_ISDIR(st.st_mode) ? 4
                    : S_ISLNK(st.st_mode) ? 10
                    : S_ISCHR(st.st_mode) ? 2
                    : S_ISBLK(st.st_mode) ? 6
                    : S_ISFIFO(st.st_mode) ? 1
                    : S_ISSOCK(st.st_mode) ? 12
                                           : 0;
        children.push_back(
            {name, (std::uint32_t)st.st_ino, (std::uint8_t)type});
      }
      if (ec)
        return failure(ENOENT);
    }
    const auto prefix = d.node->path == "/" ? std::string("/")
                                            : d.node->path + "/";
    for (const auto &[path, child] : nodes) {
      if (!path.starts_with(prefix) || path.size() <= prefix.size() ||
          path.find('/', prefix.size()) != std::string::npos)
        continue;
      if (std::any_of(children.begin(), children.end(),
                      [&](const Entry &entry) {
                        return entry.name == path.substr(prefix.size());
                      }))
        continue;
      auto type = S_ISREG(child->stat.mode)   ? 8
                  : S_ISDIR(child->stat.mode) ? 4
                                              : 0;
      children.push_back({path.substr(prefix.size()),
                          (std::uint32_t)child->stat.ino,
                          (std::uint8_t)type});
    }
    std::sort(children.begin(), children.end(),
              [](const Entry &a, const Entry &b) { return a.name < b.name; });
    ordered.insert(ordered.end(), children.begin(), children.end());
    std::vector<std::uint8_t> buffer;
    std::uint64_t index = d.offset;
    while (index < ordered.size()) {
      const auto &entry = ordered[index];
      const std::uint64_t name_bytes = entry.name.size() + 1;
      const std::uint64_t reclen = (19 + name_bytes + 7) & ~std::uint64_t(7);
      if (buffer.size() + reclen > count)
        break;
      auto base = buffer.size();
      buffer.resize(base + reclen, 0);
      std::memcpy(buffer.data() + base, &entry.ino, 8);
      std::int64_t next = index + 1;
      std::memcpy(buffer.data() + base + 8, &next, 8);
      std::uint16_t length = reclen;
      std::memcpy(buffer.data() + base + 16, &length, 2);
      buffer[base + 18] = entry.type;
      std::memcpy(buffer.data() + base + 19, entry.name.c_str(), name_bytes);
      ++index;
    }
    if (buffer.empty())
      return 0;
    if (!write(address, buffer.data(), buffer.size()))
      return failure(EFAULT);
    d.offset = index;
    return buffer.size();
  }
};
ProcessFiles::ProcessFiles(ZvrilRuntime *m, const std::filesystem::path &root,
                           const std::vector<std::uint8_t> &input,
                           const std::string &exe)
    : impl(std::make_unique<Impl>(m, root, input, exe)) {}
ProcessFiles::~ProcessFiles() = default;
const std::vector<std::uint8_t> &ProcessFiles::output(bool error) const {
  return error ? impl->stderr_data : impl->stdout_data;
}
bool ProcessFiles::mapping(std::uint64_t fd, std::uint64_t offset,
                           std::uint64_t size,
                           std::vector<std::uint8_t> &initial) {
  if (fd > INT32_MAX || !impl->descriptors.contains(int(fd)))
    return false;
  auto &d = *impl->descriptors.at(int(fd)).description;
  if (!d.node || !S_ISREG(d.node->stat.mode) ||
      (d.flags & O_ACCMODE) == O_WRONLY)
    return false;
  auto n = offset >= d.node->bytes.size()
               ? 0
               : std::min<std::uint64_t>(size, d.node->bytes.size() - offset);
  initial.assign(d.node->bytes.begin() +
                     std::min<std::uint64_t>(offset, d.node->bytes.size()),
                 d.node->bytes.begin() +
                     std::min<std::uint64_t>(offset, d.node->bytes.size()) + n);
  return true;
}
std::optional<std::uint64_t>
ProcessFiles::call(std::uint64_t number,
                   const std::array<std::uint64_t, 6> &a) {
  auto &p = *impl;
  switch (number) {
  case 0:
    return p.transfer(a[0], a[1], a[2], false);
  case 1:
    return p.transfer(a[0], a[1], a[2], true);
  case 2:
    return p.open(-100, a[0], a[1], a[2]);
  case 3:
    if (a[0] > INT32_MAX || !p.descriptors.erase(int(a[0])))
      return failure(EBADF);
    return 0;
  case 4:
  case 6:
  case 21:
  case 262:
  case 269: {
    if (number == 6)
      throw Error("E_PROCESS_FILESYSTEM",
                  "lstat symlink observations are not implemented", 1);
    std::string name;
    int error = 0;
    auto dir = (number == 262 || number == 269) ? a[0] : std::uint64_t(-100);
    auto address = (number == 262 || number == 269) ? a[1] : a[0];
    if (number == 262 && (a[3] & ~std::uint64_t(0x1100)))
      throw Error("E_PROCESS_FILESYSTEM", "Unmodeled fstatat flags", 1);
    if (number == 262 && (a[3] & 0x1000)) {
      std::string value;
      if (!p.path(address, value))
        return failure(EFAULT);
      if (value.empty())
        return p.stat_fd(a[0], a[2]);
    }
    if (!p.resolve(dir, address, name, error))
      return failure(error);
    auto node = p.node(name, error);
    if (!node)
      return failure(error);
    if (number == 21 || number == 269) {
      auto mode = number == 21 ? a[1] : a[2];
      if (mode & ~std::uint64_t(7))
        return failure(EINVAL);
      if ((mode & 4) && !(node->stat.mode & 0444))
        return failure(EACCES);
      if ((mode & 2) && !(node->stat.mode & 0222))
        return failure(EACCES);
      if ((mode & 1) && !(node->stat.mode & 0111))
        return failure(EACCES);
      return 0;
    }
    return p.write(number == 262 ? a[2] : a[1], &node->stat, sizeof(GuestStat))
               ? 0
               : failure(EFAULT);
  }
  case 5:
    return p.stat_fd(a[0], a[1]);
  case 137: { // statfs
    std::string name;
    int error = 0;
    if (!p.resolve(std::uint64_t(-100), a[0], name, error))
      return failure(error);
    if (!p.node(name, error))
      return failure(error);
    const GuestStatFS statistics;
    return p.write(a[1], &statistics, sizeof(statistics)) ? 0
                                                          : failure(EFAULT);
  }
  case 138: { // fstatfs
    if (a[0] > INT32_MAX || !p.descriptors.contains(int(a[0])))
      return failure(EBADF);
    const GuestStatFS statistics;
    return p.write(a[1], &statistics, sizeof(statistics)) ? 0
                                                          : failure(EFAULT);
  }
  case 8: {
    if (a[0] > INT32_MAX || !p.descriptors.contains(int(a[0])))
      return failure(EBADF);
    auto &d = *p.descriptors.at(int(a[0])).description;
    if (!d.node)
      return failure(ESPIPE);
    std::int64_t base = a[2] == 0   ? 0
                        : a[2] == 1 ? d.offset
                        : a[2] == 2 ? d.node->bytes.size()
                                    : -1;
    if (base < 0)
      return failure(EINVAL);
    auto offset = std::int64_t(a[1]);
    std::int64_t position = 0;
    if (__builtin_add_overflow(base, offset, &position))
      return failure(EINVAL);
    if (position < 0)
      return failure(EINVAL);
    d.offset = position;
    return d.offset;
  }
  case 16:
    // Virtual descriptors are not terminals. Returning ENOTTY lets isatty and
    // window-size probes take their documented non-terminal fallback.
    return failure(ENOTTY);
  case 17:
  case 18:
    return p.transfer(a[0], a[1], a[2], number == 18, a[3]);
  case 19:
  case 20: {
    if (a[2] > 1024)
      return failure(EINVAL);
    std::uint64_t total = 0;
    for (std::uint64_t i = 0; i < a[2]; i++) {
      std::uint64_t vector[2];
      if (a[1] > UINT64_MAX - i * 16 || !p.read(a[1] + i * 16, vector, 16))
        return total ? total : failure(EFAULT);
      auto result = p.transfer(
          a[0], vector[0], std::min<std::uint64_t>(vector[1], io_limit - total),
          number == 20);
      if (std::int64_t(result) < 0)
        return total ? total : result;
      total += result;
      if (result < vector[1])
        break;
      if (total >= io_limit)
        break;
    }
    return total;
  }
  case 32:
  case 33:
  case 292: {
    if (a[0] > INT32_MAX || !p.descriptors.contains(int(a[0])))
      return failure(EBADF);
    auto descriptor = p.descriptors.at(int(a[0]));
    descriptor.close_exec = false;
    if (number == 32) {
      int fd = p.allocate(descriptor);
      return fd < 0 ? failure(EMFILE) : std::uint64_t(fd);
    }
    if (a[1] >= 1024)
      return failure(EBADF);
    if (number == 33 && a[0] == a[1])
      return a[0];
    if (number == 292 && a[0] == a[1])
      return failure(EINVAL);
    if (number == 292 && (a[2] & ~std::uint64_t(O_CLOEXEC)))
      return failure(EINVAL);
    descriptor.close_exec = number == 292 && (a[2] & O_CLOEXEC);
    p.descriptors[int(a[1])] = descriptor;
    return a[1];
  }
  case 72: {
    if (a[0] > INT32_MAX || !p.descriptors.contains(int(a[0])))
      return failure(EBADF);
    auto &d = p.descriptors.at(int(a[0]));
    if (a[1] == F_GETFD)
      return d.close_exec ? FD_CLOEXEC : 0;
    if (a[1] == F_SETFD) {
      d.close_exec = (a[2] & FD_CLOEXEC) != 0;
      return 0;
    }
    if (a[1] == F_GETFL)
      return d.description->flags;
    if (a[1] == F_SETFL) {
      if (a[2] &
          ~std::uint64_t(O_ACCMODE | O_APPEND | O_NONBLOCK | O_LARGEFILE))
        throw Error("E_PROCESS_FILESYSTEM", "Unmodeled F_SETFL flags", 1);
      d.description->flags = (d.description->flags & ~(O_APPEND | O_NONBLOCK)) |
                             (a[2] & (O_APPEND | O_NONBLOCK));
      return 0;
    }
    if (a[1] == F_DUPFD || a[1] == F_DUPFD_CLOEXEC) {
      if (a[2] >= 1024)
        return failure(EINVAL);
      auto copy = d;
      copy.close_exec = a[1] == F_DUPFD_CLOEXEC;
      int fd = p.allocate(copy, int(a[2]));
      return fd < 0 ? failure(EMFILE) : std::uint64_t(fd);
    }
    throw Error("E_PROCESS_FILESYSTEM", "Unmodeled fcntl operation", 1);
  }
  case 74:
  case 75:
    return p.sync_fd(a[0]);
  case 76:
    return p.truncate_path(std::uint64_t(-100), a[0], a[1]);
  case 77:
    return p.truncate_fd(a[0], a[1]);
  case 82:
    return p.rename_entry(std::uint64_t(-100), a[0], std::uint64_t(-100),
                          a[1], 0);
  case 83:
    return p.mkdir_at(std::uint64_t(-100), a[0], a[1]);
  case 84:
    return p.remove_entry(std::uint64_t(-100), a[0], 0x200);
  case 87:
    return p.remove_entry(std::uint64_t(-100), a[0], 0);
  case 90:
    return p.set_mode_path(std::uint64_t(-100), a[0], a[1]);
  case 91:
    return p.set_mode(a[0], a[1]);
  case 258:
    return p.mkdir_at(a[0], a[1], a[2]);
  case 263:
    return p.remove_entry(a[0], a[1], a[2]);
  case 264:
    return p.rename_entry(a[0], a[1], a[2], a[3], 0);
  case 268:
    if (a[3])
      return failure(EINVAL);
    return p.set_mode_path(a[0], a[1], a[2]);
  case 285: {
    if (a[1] != 0)
      return failure(EOPNOTSUPP);
    if (a[0] > INT32_MAX || !p.descriptors.contains(int(a[0])))
      return failure(EBADF);
    auto &description = *p.descriptors.at(int(a[0])).description;
    if ((description.flags & O_ACCMODE) == O_RDONLY)
      return failure(EBADF);
    if (a[2] > UINT64_MAX - a[3])
      return failure(EFBIG);
    return p.resize_node(description.node, a[2] + a[3]);
  }
  case 316:
    return p.rename_entry(a[0], a[1], a[2], a[3], a[4]);
  case 79:
    if (a[1] < p.cwd.size() + 1)
      return failure(ERANGE);
    return p.write(a[0], p.cwd.c_str(), p.cwd.size() + 1) ? p.cwd.size() + 1
                                                          : failure(EFAULT);
  case 89:
  case 267: {
    std::string name;
    int error = 0;
    if (!p.resolve(number == 89 ? std::uint64_t(-100) : a[0],
                   number == 89 ? a[0] : a[1], name, error))
      return failure(error);
    auto buffer = number == 89 ? a[1] : a[2], size = number == 89 ? a[2] : a[3];
    if (!size)
      return failure(EINVAL);
    std::string target;
    if (name == "/proc/self/exe")
      target = p.executable;
    else {
      if (p.root.empty())
        return failure(ENOENT);
      std::error_code ec;
      auto host = p.root / name.substr(1);
      auto link = std::filesystem::read_symlink(host, ec);
      if (ec)
        return failure(ec.value() == ENOENT ? ENOENT : EINVAL);
      target = link.string();
    }
    auto n = std::min<std::uint64_t>(size, target.size());
    return p.write(buffer, target.data(), n) ? n : failure(EFAULT);
  }
  case 257:
    return p.open(a[0], a[1], a[2], a[3]);
  case 217:
    return p.getdents(a[0], a[1], a[2]);
  case 332: { // statx
    if (a[2] & ~std::uint64_t(0x980))
      return failure(EINVAL);
    std::string name;
    int error = 0;
    if (!p.resolve(a[0], a[1], name, error))
      return failure(error);
    auto node = p.node(name, error);
    if (!node)
      return failure(error);
    GuestStatX result;
    result.mode = node->stat.mode;
    result.links = node->stat.nlink;
    result.uid = node->stat.uid;
    result.gid = node->stat.gid;
    result.inode = node->stat.ino;
    result.size = node->stat.size;
    result.blocks = node->stat.blocks;
    result.block_size = node->stat.blksize;
    result.atime = {node->stat.atime, (std::uint32_t)node->stat.atime_ns, 0};
    result.ctime = {node->stat.ctime, (std::uint32_t)node->stat.ctime_ns, 0};
    result.mtime = {node->stat.mtime, (std::uint32_t)node->stat.mtime_ns, 0};
    result.btime = result.ctime;
    return p.write(a[4], &result, sizeof(result)) ? 0 : failure(EFAULT);
  }
  default:
    return {};
  }
}
llvm::json::Object ProcessFiles::report() const {
  llvm::json::Array changed;
  for (const auto &[path, n] : impl->nodes)
    if (n->changed) {
      std::string encoded;
      for (auto b : n->bytes) {
        encoded += "0123456789abcdef"[b >> 4];
        encoded += "0123456789abcdef"[b & 15];
      }
      changed.push_back(llvm::json::Object{{"path", path},
                                           {"size", n->bytes.size()},
                                           {"hex", std::move(encoded)}});
    }
  return llvm::json::Object{{"sysroot", impl->root.string()},
                            {"host_writes", false},
                            {"changed_files", std::move(changed)}};
}
} // namespace zvril
