#define _GNU_SOURCE
#include <stdint.h>
#include <signal.h>
#include <setjmp.h>
#include <ucontext.h>

/* Trusted sequential test oracle. Does not use ptrace or change product
 * sandbox policy. The assembly fixture records normal completion itself. */
static sigjmp_buf resume;
static uint64_t *observation;
static uintptr_t entry;
static int dividing;
static void fault(int signal, siginfo_t *info, void *opaque) {
  (void)info;
  ucontext_t *context = (ucontext_t *)opaque;
  observation[0] = context->uc_mcontext.gregs[dividing ? REG_RDX : REG_RCX];
  observation[1] = context->uc_mcontext.gregs[REG_RDI];
  observation[2] = context->uc_mcontext.gregs[REG_RSI];
  observation[3] = context->uc_mcontext.gregs[REG_RAX];
  observation[4] = context->uc_mcontext.gregs[REG_EFL];
  observation[6] = (unsigned)signal;
  observation[7] = context->uc_mcontext.gregs[REG_RIP] - entry;
  siglongjmp(resume, 1);
}
static int capture(int division, void *function, void *dst, void *src, uint64_t count,
                    uint64_t accumulator, uint64_t direction, uint64_t *output) {
  typedef void (*Target)(void *, void *, uint64_t, uint64_t, uint64_t, uint64_t *);
  struct sigaction previous, action = {0};
  action.sa_sigaction = fault;
  action.sa_flags = SA_SIGINFO;
  sigemptyset(&action.sa_mask);
  observation = output;
  entry = (uintptr_t)function;
  dividing = division;
  int expected_signal = division ? SIGFPE : SIGSEGV;
  if (sigaction(expected_signal, &action, &previous)) return -1;
  if (!sigsetjmp(resume, 1))
    ((Target)function)(dst, src, count, accumulator, direction, output);
  sigaction(expected_signal, &previous, 0);
  return (int)output[6];
}
int string_oracle(void *function, void *dst, void *src, uint64_t count,
                  uint64_t accumulator, uint64_t direction, uint64_t *output) {
  return capture(0, function, dst, src, count, accumulator, direction, output);
}
int division_oracle(void *function, void *low, void *high, uint64_t divisor,
                    uint64_t unused1, uint64_t unused2, uint64_t *output) {
  return capture(1, function, low, high, divisor, unused1, unused2, output);
}
