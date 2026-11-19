#include "zvril/verify.h"
#include <cerrno>
#include <fcntl.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/landlock.h>
#include <linux/seccomp.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>
#include <vector>

namespace zvril {
bool sandbox_available() {
  return syscall(SYS_landlock_create_ruleset, nullptr, 0,
                 LANDLOCK_CREATE_RULESET_VERSION) >= 3;
}
bool ptrace_available() {
  pid_t pid = fork();
  if (pid < 0)
    return false;
  if (!pid)
    _exit(ptrace(PTRACE_TRACEME, 0, nullptr, nullptr) == 0 ? 0 : 1);
  int status = 0;
  while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {
  }
  return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}
void restrict_worker(const std::filesystem::path &original,
                     std::uint64_t timeout_ms) {
  if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0))
    throw Error("E_SANDBOX", "Cannot set no_new_privs", 1);
  int abi = static_cast<int>(syscall(SYS_landlock_create_ruleset, nullptr, 0,
                                     LANDLOCK_CREATE_RULESET_VERSION));
  if (abi < 3)
    throw Error("E_SANDBOX", "Landlock ABI 3+ is required for native execution",
                1);
  landlock_ruleset_attr rules{};
  rules.handled_access_fs =
      LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_WRITE_FILE |
      LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR |
      LANDLOCK_ACCESS_FS_REMOVE_DIR | LANDLOCK_ACCESS_FS_REMOVE_FILE |
      LANDLOCK_ACCESS_FS_MAKE_CHAR | LANDLOCK_ACCESS_FS_MAKE_DIR |
      LANDLOCK_ACCESS_FS_MAKE_REG | LANDLOCK_ACCESS_FS_MAKE_SOCK |
      LANDLOCK_ACCESS_FS_MAKE_FIFO | LANDLOCK_ACCESS_FS_MAKE_BLOCK |
      LANDLOCK_ACCESS_FS_MAKE_SYM | LANDLOCK_ACCESS_FS_REFER |
      LANDLOCK_ACCESS_FS_TRUNCATE;
  int fd = static_cast<int>(
      syscall(SYS_landlock_create_ruleset, &rules, sizeof(rules), 0));
  if (fd < 0)
    throw Error("E_SANDBOX", "Cannot create filesystem ruleset", 1);
  const auto allow = [&](const std::filesystem::path &path) {
    int handle = open(path.c_str(), O_PATH | O_CLOEXEC);
    if (handle < 0)
      return;
    struct stat stat{};
    fstat(handle, &stat);
    landlock_path_beneath_attr rule{};
    rule.parent_fd = handle;
    rule.allowed_access = LANDLOCK_ACCESS_FS_READ_FILE;
    if (S_ISDIR(stat.st_mode))
      rule.allowed_access |= LANDLOCK_ACCESS_FS_READ_DIR;
    const auto result = syscall(SYS_landlock_add_rule, fd,
                                LANDLOCK_RULE_PATH_BENEATH, &rule, 0);
    close(handle);
    if (result < 0) {
      close(fd);
      throw Error("E_SANDBOX", "Cannot install filesystem rule", 1);
    }
  };
  allow(original);
  for (const char *path :
       {"/usr/lib", "/usr/lib64", "/lib", "/lib64", "/etc/ld.so.cache"})
    allow(path);
  if (syscall(SYS_landlock_restrict_self, fd, 0)) {
    close(fd);
    throw Error("E_SANDBOX", "Cannot restrict filesystem", 1);
  }
  close(fd);
  std::vector<sock_filter> code{
      BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(seccomp_data, arch)),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
      BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(seccomp_data, nr)),
      BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, 0x40000000, 0, 1),
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM)};
  const int denied[] = {SYS_socket,
                        SYS_connect,
                        SYS_bind,
                        SYS_listen,
                        SYS_accept,
                        SYS_accept4,
                        SYS_sendto,
                        SYS_sendmsg,
                        SYS_recvfrom,
                        SYS_recvmsg,
                        SYS_socketpair,
                        SYS_execve,
                        SYS_execveat,
                        SYS_fork,
                        SYS_vfork,
                        SYS_clone,
                        SYS_clone3,
                        SYS_ptrace,
                        SYS_process_vm_readv,
                        SYS_process_vm_writev,
                        SYS_mount,
                        SYS_umount2,
                        SYS_unshare,
                        SYS_setns,
                        SYS_bpf,
                        SYS_perf_event_open,
                        SYS_io_uring_setup,
                        SYS_userfaultfd,
                        SYS_keyctl,
                        SYS_add_key,
                        SYS_request_key,
                        SYS_open_by_handle_at,
                        SYS_kill,
                        SYS_tkill,
                        SYS_tgkill,
                        SYS_openat2,
                        SYS_truncate,
                        SYS_ftruncate,
                        SYS_chmod,
                        SYS_fchmod,
                        SYS_fchmodat,
                        SYS_chown,
                        SYS_fchown,
                        SYS_lchown,
                        SYS_fchownat,
                        SYS_link,
                        SYS_linkat,
                        SYS_unlink,
                        SYS_unlinkat,
                        SYS_rename,
                        SYS_renameat,
                        SYS_renameat2,
                        SYS_mkdir,
                        SYS_mkdirat,
                        SYS_rmdir,
                        SYS_symlink,
                        SYS_symlinkat,
                        SYS_mknod,
                        SYS_mknodat,
                        SYS_setxattr,
                        SYS_lsetxattr,
                        SYS_fsetxattr,
                        SYS_removexattr,
                        SYS_lremovexattr,
                        SYS_fremovexattr};
  for (int number : denied) {
    code.push_back(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
                            static_cast<unsigned>(number), 0, 1));
    code.push_back(BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM));
  }
  for (const auto [number, arg] :
       {std::pair{SYS_open, 1}, std::pair{SYS_openat, 2}}) {
    code.push_back(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
                            static_cast<unsigned>(number), 0, 4));
    code.push_back(BPF_STMT(
        BPF_LD | BPF_W | BPF_ABS,
        static_cast<unsigned>(offsetof(seccomp_data, args) + 8 * arg)));
    code.push_back(
        BPF_JUMP(BPF_JMP | BPF_JSET | BPF_K,
                 O_ACCMODE | O_CREAT | O_TRUNC | O_APPEND | __O_TMPFILE, 0, 1));
    code.push_back(BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM));
    code.push_back(BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));
  }
  code.push_back(BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));
  sock_fprog program{static_cast<unsigned short>(code.size()), code.data()};
  if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &program))
    throw Error("E_SANDBOX", "Cannot install syscall filter", 1);
  const rlimit cpu{(timeout_ms + 999) / 1000 + 1,
                   (timeout_ms + 999) / 1000 + 1},
      as{2ULL * 1024 * 1024 * 1024, 2ULL * 1024 * 1024 * 1024}, files{0, 0},
      core{0, 0};
  if (setrlimit(RLIMIT_CPU, &cpu) || setrlimit(RLIMIT_AS, &as) ||
      setrlimit(RLIMIT_FSIZE, &files) || setrlimit(RLIMIT_CORE, &core))
    throw Error("E_SANDBOX", "Cannot install worker resource limits", 1);
}
} // namespace zvril
