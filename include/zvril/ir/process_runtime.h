#pragma once
#include "zvril/runtime.h"
extern "C" {
int zvril_rt_begin(ZvrilRuntime *, void *, uint64_t, uint64_t, uint64_t);
int zvril_rt_end(ZvrilRuntime *, void *, uint64_t);
void zvril_rt_fault(ZvrilRuntime *, uint64_t, uint64_t, uint64_t);
void zvril_rt_consume_flags(ZvrilRuntime *, uint64_t);
int zvril_rt_tracing(ZvrilRuntime *);
void zvril_rt_record(ZvrilRuntime *, const uint64_t *, uint64_t);
}
// Exact imports of a dynamic step, implemented by the process dispatcher.
#define ZVRIL_PROCESS_RUNTIME(X)                                               \
  X(zvril_runtime_read)                                                        \
  X(zvril_runtime_write)                                                       \
  X(zvril_runtime_bias) X(zvril_runtime_fsbase) X(zvril_runtime_flags_valid)   \
      X(zvril_runtime_set_flags_valid) X(zvril_runtime_rep_fault_flags)        \
          X(zvril_rt_begin) X(zvril_rt_end) X(zvril_rt_fault)                  \
              X(zvril_rt_consume_flags) X(zvril_rt_tracing) X(zvril_rt_record)
