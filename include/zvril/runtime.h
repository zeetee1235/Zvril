#pragma once
#include <stdint.h>

/* Runtime ABI v1 for generated modules. Host pointers belong only in data.
 * Guest addresses, including RSP and register pointers, remain uint64_t.
 * All mapped bytes are RW; the caller supplies a valid host allocation.
 * No ELF segments, imports or process state are mapped automatically.
 */
typedef struct ZvrilMemory {
  uint8_t *data;
  uint64_t base;
  uint64_t size;
  uint64_t fault; /* 0=OK, 1=read, 2=write, 3=step limit, 4=bad return */
  uint64_t fault_pc;
  uint64_t fault_address;
  uint64_t fault_width;
  uint64_t steps_left;
  uint64_t return_pc; /* Caller-chosen sentinel on the root guest stack. */
} ZvrilMemory;

/* Symbols exported by each generated module. State is Remill's real State.
 * Register IDs: RAX RCX RDX RBX RSP RBP RSI RDI R8..R15 RIP AF CF DF OF PF SF
 * ZF. State storage must be zero-initialized and at least zvril_state_size()
 * bytes. State, data and Memory allocations must be disjoint and valid for the
 * run. Read fault before trusting outputs; register state on a fault is
 * unspecified.
 */
#ifdef __cplusplus
extern "C" {
#endif
uint64_t zvril_state_size(void);
uint64_t zvril_state_get(void *state, uint32_t reg);
void zvril_state_set(void *state, uint32_t reg, uint64_t value);
ZvrilMemory *zvril_lifted(void *state, uint64_t entry_pc, ZvrilMemory *memory);

/* Runtime ABI v2. Memory is split at 4 KiB boundaries; access permissions and
 * initialization are checked for every byte, including cross-page accesses.
 * API v1 remains supported through a conversion wrapper in generated modules.
 */
enum { ZVRIL_R = 1, ZVRIL_W = 2, ZVRIL_X = 4 };
enum {
  ZVRIL_FAULT_READ = 1,
  ZVRIL_FAULT_WRITE = 2,
  ZVRIL_FAULT_STEPS = 3,
  ZVRIL_FAULT_RETURN = 4,
  ZVRIL_FAULT_DIVIDE = 5,
  ZVRIL_FAULT_UNINITIALIZED = 6,
  ZVRIL_FAULT_RESOURCE = 7,
  ZVRIL_FAULT_EXTERNAL = 8,
  ZVRIL_FAULT_TRAP = 9
};
typedef struct ZvrilRuntime ZvrilRuntime;
typedef struct ZvrilTraceRecord {
  uint64_t pc;
  uint64_t gpr[17];
  uint64_t flags;
  uint64_t flags_valid;
} ZvrilTraceRecord;
ZvrilRuntime *zvril_runtime_create(uint64_t byte_limit, uint64_t step_limit);
void zvril_runtime_destroy(ZvrilRuntime *runtime);
int zvril_runtime_map(ZvrilRuntime *, uint64_t address, uint64_t size,
                      unsigned permissions, const void *initial,
                      uint64_t initial_size, int zero_initialize);
int zvril_runtime_read(ZvrilRuntime *, uint64_t address, void *bytes,
                       uint64_t size);
int zvril_runtime_write(ZvrilRuntime *, uint64_t address, const void *bytes,
                        uint64_t size);
int zvril_runtime_protect(ZvrilRuntime *, uint64_t address, uint64_t size,
                          unsigned permissions);
/* Process mode fetches and rechecks the instruction bytes before every step.
 * Static function modules retain the immutable executable-memory contract. */
void zvril_runtime_dynamic_code(ZvrilRuntime *, int enabled);
int zvril_runtime_fetch(ZvrilRuntime *, uint64_t address, void *,
                        uint64_t size);
int zvril_runtime_probe(ZvrilRuntime *, uint64_t address, uint64_t size,
                        unsigned permissions);
int zvril_runtime_unmap(ZvrilRuntime *, uint64_t address, uint64_t size);
void zvril_runtime_set_fsbase(ZvrilRuntime *, uint64_t);
ZvrilMemory *zvril_runtime_status(ZvrilRuntime *);
void zvril_runtime_set_return(ZvrilRuntime *, uint64_t sentinel);
void zvril_runtime_clear_fault(ZvrilRuntime *);
void zvril_runtime_trace(ZvrilRuntime *, ZvrilTraceRecord *, uint64_t capacity);
uint64_t zvril_runtime_trace_count(ZvrilRuntime *);
uint64_t zvril_runtime_flags_valid(ZvrilRuntime *);
void zvril_runtime_set_flags_valid(ZvrilRuntime *, uint64_t mask);
uint64_t zvril_runtime_unknown_flags(ZvrilRuntime *);
/* Fault FLAGS CPU policy: bit 0 restores REPE, bit 1 restores REPNE.
 * Unset bits retain completed comparison progress. Default is 3. */
int zvril_runtime_set_rep_fault_flags(ZvrilRuntime *, unsigned restore_mask);
uint64_t zvril_runtime_rep_fault_flags(ZvrilRuntime *);
uint64_t zvril_runtime_bias(ZvrilRuntime *);
void zvril_runtime_set_bias(ZvrilRuntime *, uint64_t);
int zvril_runtime_tls(ZvrilRuntime *, uint64_t size, uint64_t alignment,
                      const void *initial, uint64_t initial_size);
uint64_t zvril_runtime_fsbase(ZvrilRuntime *);
uint64_t zvril_runtime_stack(ZvrilRuntime *);
uint64_t zvril_runtime_return_area(ZvrilRuntime *);
int zvril_runtime_success(ZvrilRuntime *);
/* Generated with an aggregate --abi contract: scalar slots contain raw bits,
 * aggregate slots contain valid host pointers to layout-sized packets.
 * Pointer fields inside packets contain guest addresses. Result must have at
 * least the declared return size. Returns 1 only with no runtime fault or
 * unknown consumed flags; otherwise result is not valid. */
int zvril_invoke_packet(ZvrilRuntime *, const uint64_t *slots, void *result);
uint64_t zvril_runtime_bridge(ZvrilRuntime *, const char *name, uint64_t,
                              uint64_t, uint64_t);
int zvril_init_image(ZvrilRuntime *, uint64_t load_bias);
ZvrilRuntime *zvril_lifted_v2(void *state, uint64_t entry_pc, ZvrilRuntime *);
#ifdef __cplusplus
}
#endif
