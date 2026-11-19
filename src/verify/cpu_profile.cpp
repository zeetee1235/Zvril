#include "zvril/verify.h"
#include <cerrno>
#include <chrono>
#include <csetjmp>
#include <csignal>
#include <cstdint>
#include <cstring>
#include <poll.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <ucontext.h>
#include <unistd.h>

namespace zvril {
namespace {
sigjmp_buf resume_probe;
volatile sig_atomic_t fault_flags = 0;
volatile std::uint64_t initial_flags = 0;
void fault(int, siginfo_t *, void *opaque) {
  auto *context = static_cast<ucontext_t *>(opaque);
  fault_flags = context->uc_mcontext.gregs[REG_EFL] & 0xcd5;
  siglongjmp(resume_probe, 1);
}
int measure(bool repne, bool expected_fault, std::uint8_t *page) {
  std::memset(page, 0x31, 4096);
  if (repne)
    std::memset(page + 512, 0x32, 64);
  auto *source = page + 4093, *destination = page + 512;
  std::uint64_t count = expected_fault ? 8 : 3, completed = 0;
  fault_flags = -1;
  if (!sigsetjmp(resume_probe, 1)) {
    if (repne) {
      asm volatile("cld; mov $16,%%eax; cmp $1,%%eax; pushfq; popq %0; repne "
                   "cmpsb; pushfq; popq %1"
                   : "=m"(initial_flags), "=m"(completed), "+S"(source),
                     "+D"(destination), "+c"(count)::"rax", "cc", "memory");
    } else {
      asm volatile("cld; mov $16,%%eax; cmp $1,%%eax; pushfq; popq %0; repe "
                   "cmpsb; pushfq; popq %1"
                   : "=m"(initial_flags), "=m"(completed), "+S"(source),
                     "+D"(destination), "+c"(count)::"rax", "cc", "memory");
    }
  }
  if (expected_fault)
    return fault_flags;
  return completed & 0xcd5;
}
} // namespace
unsigned native_rep_fault_profile() {
  // Native execution is performed only by verify's explicit execution path.
  // An isolated, fixed calibration fixture avoids guessing from vendor names.
  int descriptors[2];
  if (pipe(descriptors))
    throw Error("E_CPU_PROFILE", "Cannot create CPU probe pipe", 1);
  auto child = fork();
  if (child < 0) {
    close(descriptors[0]);
    close(descriptors[1]);
    throw Error("E_CPU_PROFILE", "Cannot start CPU probe", 1);
  }
  if (!child) {
    close(descriptors[0]);
    std::uint8_t profile = 0xff;
    rlimit cpu{1, 1}, core{0, 0};
    setrlimit(RLIMIT_CPU, &cpu);
    setrlimit(RLIMIT_CORE, &core);
    auto *mapping =
        static_cast<std::uint8_t *>(mmap(nullptr, 8192, PROT_READ | PROT_WRITE,
                                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
    if (mapping != MAP_FAILED && !mprotect(mapping + 4096, 4096, PROT_NONE)) {
      struct sigaction action{};
      action.sa_sigaction = fault;
      action.sa_flags = SA_SIGINFO;
      sigemptyset(&action.sa_mask);
      if (!sigaction(SIGSEGV, &action, nullptr)) {
        profile = 0;
        for (unsigned variant = 0; variant < 2; variant++) {
          auto completed = measure(variant, false, mapping);
          auto observed = measure(variant, true, mapping);
          auto initial = initial_flags & 0xcd5;
          if (observed < 0 || completed == int(initial) ||
              (observed != int(initial) && observed != completed)) {
            profile = 0xff;
            break;
          }
          if (observed == int(initial))
            profile |= 1u << variant;
        }
      }
    }
    (void)write(descriptors[1], &profile, 1);
    _exit(0);
  }
  close(descriptors[1]);
  pollfd descriptor{descriptors[0], POLLIN, 0};
  std::uint8_t profile = 0xff;
  int status = 0;
  if (poll(&descriptor, 1, 2000) > 0)
    (void)read(descriptors[0], &profile, 1);
  else
    kill(child, SIGKILL);
  close(descriptors[0]);
  while (waitpid(child, &status, 0) < 0 && errno == EINTR) {
  }
  if (profile > 3 || !WIFEXITED(status) || WEXITSTATUS(status))
    throw Error("E_CPU_PROFILE",
                "Native REP fault behavior could not be calibrated", 1);
  return profile;
}
} // namespace zvril
