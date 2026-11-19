/* Explicit SysV u64(u64,u64) fixture runner; never loads the original ELF. */
#include "zvril/runtime.h"
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static uint64_t parse(const char* text) {
  char* end = NULL;
  errno = 0;
  uint64_t value = strtoull(text, &end, 0);
  if (errno || end == text || *end) { fputs("Invalid integer\n", stderr); exit(3); }
  return value;
}

int main(int argc, char** argv) {
  if (argc != 4) { fputs("Usage: recompiled ENTRY_PC ARG0 ARG1\n", stderr); return 3; }
  void* state = calloc(1, (size_t)zvril_state_size());
  const uint64_t size = 65536, base = 0x10000000, sentinel = UINT64_C(0xfffffffffffffff0);
  uint8_t* data = calloc(1, (size_t)size);
  if (!state || !data) { free(state); free(data); return 2; }
  memcpy(data + size - 8, &sentinel, 8);
  ZvrilMemory memory = {data, base, size, 0, 0, 0, 0, 100000, sentinel};
  zvril_state_set(state, 7, parse(argv[2])); /* RDI */
  zvril_state_set(state, 6, parse(argv[3])); /* RSI */
  zvril_state_set(state, 4, base + size - 8); /* RSP */
  zvril_lifted(state, parse(argv[1]), &memory);
  if (memory.fault)
    fprintf(stderr, "Runtime fault=%" PRIu64 " pc=0x%" PRIx64 "\n", memory.fault, memory.fault_pc);
  else
    printf("%" PRIu64 "\n", zvril_state_get(state, 0)); /* RAX */
  const int result = memory.fault ? 1 : 0;
  free(state); free(data);
  return result;
}
