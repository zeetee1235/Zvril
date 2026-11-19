#include "zvril/runtime.h"
#include <assert.h>
#include <stdint.h>
#include <string.h>

extern int zvril_rt_begin(ZvrilRuntime *, void *, uint64_t, uint64_t, uint64_t);
extern int zvril_rt_end(ZvrilRuntime *, void *, uint64_t);
extern void zvril_rt_fault(ZvrilRuntime *, uint64_t, uint64_t, uint64_t);
int main(void) {
  ZvrilRuntime *r = zvril_runtime_create(128 * 1024, 100);
  assert(r);
  assert(zvril_runtime_rep_fault_flags(r) == 3);
  assert(zvril_runtime_set_rep_fault_flags(r, 0));
  assert(zvril_runtime_rep_fault_flags(r) == 0);
  assert(!zvril_runtime_set_rep_fault_flags(r, 4));
  assert(zvril_runtime_set_rep_fault_flags(r, 3));
  assert(zvril_runtime_map(r, 0x80000, 16, 7, 0, 0, 1));
  unsigned char instruction = 0x90;
  assert(!zvril_runtime_write(r, 0x80000, &instruction, 1));
  assert(zvril_runtime_status(r)->fault == ZVRIL_FAULT_EXTERNAL);
  zvril_runtime_clear_fault(r);
  unsigned char data[8192] = {1, 2, 3}, out[32] = {0};
  assert(zvril_runtime_map(r, 0x1001, sizeof(data), 3, data, sizeof(data), 0));
  assert(!zvril_runtime_map(r, 0x1002, 10, 3, 0, 0, 1));
  assert(!zvril_runtime_map(r, UINT64_MAX, 2, 3, 0, 0, 1));
  assert(zvril_runtime_write(r, 0x1ff8, data, 32));
  assert(zvril_runtime_read(r, 0x1ff8, out, 32) && !memcmp(data, out, 32));
  assert(zvril_runtime_protect(r, 0x2000, 16, 1));
  assert(!zvril_runtime_write(r, 0x1ff8, data, 32));
  assert(zvril_runtime_status(r)->fault == ZVRIL_FAULT_WRITE);
  zvril_runtime_clear_fault(r);
  assert(zvril_runtime_read(r, 0x1ff8, out, 32) && !memcmp(data, out, 32));
  // A failed protect across a hole must leave earlier pages writable.
  assert(!zvril_runtime_protect(r, 0x1001, 0x9000, 1));
  assert(zvril_runtime_write(r, 0x1001, data, 1));
  assert(zvril_runtime_map(r, 0x10000, 128, 3, 0, 0, 0));
  assert(!zvril_runtime_read(r, 0x10000, out, 1));
  assert(zvril_runtime_status(r)->fault == ZVRIL_FAULT_UNINITIALIZED);
  zvril_runtime_clear_fault(r);
  assert(zvril_runtime_write(r, 0x10000, data, 1));
  uint64_t state[4] = {1, 2, 3, 4};
  assert(zvril_rt_begin(r, state, sizeof(state), 0x1234, 0));
  state[0] = 99;
  out[0] = 88;
  assert(zvril_runtime_write(r, 0x10000, out, 1));
  assert(zvril_runtime_write(r, 0x10001, out, 1));
  zvril_rt_fault(r, 9, 0, 0);
  assert(!zvril_rt_end(r, state, sizeof(state)) && state[0] == 1);
  assert(zvril_runtime_status(r)->fault_pc == 0x1234);
  zvril_runtime_clear_fault(r);
  assert(zvril_runtime_read(r, 0x10000, out, 1) && out[0] == 1);
  assert(!zvril_runtime_read(r, 0x10001, out, 1));
  zvril_runtime_clear_fault(r);
  uint64_t p = zvril_runtime_bridge(r, "calloc", 4, 8, 0);
  assert(p);
  assert(zvril_runtime_read(r, p, out, 32));
  for (unsigned i = 0; i < 32; i++)
    assert(out[i] == 0);
  assert(zvril_runtime_bridge(r, "memset", p, 0x41, 8) == p);
  assert(zvril_runtime_bridge(r, "memcmp", p, 0x1001, 0) == 0);
  uint64_t q = zvril_runtime_bridge(r, "realloc", p, 8192, 0);
  assert(q);
  assert(zvril_runtime_read(r, q, out, 8));
  for (unsigned i = 0; i < 8; i++)
    assert(out[i] == 0x41);
  assert(!zvril_runtime_read(r, p, out, 1));
  zvril_runtime_clear_fault(r);
  zvril_runtime_bridge(r, "free", q, 0, 0);
  assert(!zvril_runtime_read(r, q, out, 1));
  zvril_runtime_clear_fault(r);
  assert(!zvril_runtime_bridge(r, "calloc", UINT64_MAX, 2, 0));
  zvril_runtime_bridge(r, "unmodeled", 0, 0, 0);
  assert(zvril_runtime_status(r)->fault == ZVRIL_FAULT_EXTERNAL);
  zvril_runtime_destroy(r);
  r = zvril_runtime_create(8, 10);
  assert(r);
  assert(!zvril_runtime_bridge(r, "malloc", 9, 0, 0));
  assert(zvril_runtime_status(r)->fault == ZVRIL_FAULT_RESOURCE);
  zvril_runtime_destroy(r);
  r = zvril_runtime_create(16384, 100);
  assert(r);
  assert(zvril_runtime_map(r, 0x1000, 12288, 7, 0, 0, 1));
  assert(!zvril_runtime_write(r, 0x1000, &instruction, 1));
  zvril_runtime_clear_fault(r);
  zvril_runtime_dynamic_code(r, 1);
  assert(zvril_runtime_write(r, 0x1000, &instruction, 1));
  assert(zvril_runtime_fetch(r, 0x1000, out, 1) && out[0] == 0x90);
  assert(zvril_runtime_protect(r, 0x1000, 4096, 4));
  assert(zvril_runtime_probe(r, 0x1000, 4096, ZVRIL_X));
  assert(!zvril_runtime_probe(r, 0x1000, 1, ZVRIL_W));
  assert(zvril_runtime_status(r)->fault == 0);
  assert(zvril_runtime_fetch(r, 0x1000, out, 1));
  assert(!zvril_runtime_read(r, 0x1000, out, 1));
  zvril_runtime_clear_fault(r);
  assert(zvril_runtime_unmap(r, 0x1800, 4096));
  assert(zvril_runtime_fetch(r, 0x1000, out, 1));
  assert(!zvril_runtime_fetch(r, 0x1800, out, 1));
  assert(zvril_runtime_fetch(r, 0x2800, out, 1));
  assert(zvril_runtime_unmap(r, 0x1000, 12288));
  assert(zvril_runtime_map(r, 0x1000, 12288, 3, 0, 0, 1));
  assert(!zvril_runtime_fetch(r, 0x1000, out, 1));
  assert(zvril_runtime_unmap(r, 0x8000, 4096)); /* unmapped holes are legal */
  zvril_runtime_set_fsbase(r, 0x12345678);
  assert(zvril_runtime_fsbase(r) == 0x12345678);
  zvril_runtime_destroy(r);
  return 0;
}
