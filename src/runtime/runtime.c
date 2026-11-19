#include "zvril/runtime.h"
#include <limits.h>
#include <stdlib.h>
#include <string.h>

typedef struct Page {
  uint64_t base, size;
  uint8_t *data, *initialized;
  unsigned permissions;
} Page;
typedef struct Allocation {
  uint64_t base, size;
  uint8_t *data;
  uint8_t *initialized;
  int owned, freed;
} Allocation;
typedef struct Undo {
  uint64_t address;
  uint8_t value, initialized;
} Undo;
struct ZvrilRuntime {
  ZvrilMemory status; /* Prefix is deliberately identical to ABI v1. */
  Page *pages;
  uint64_t page_count, page_capacity;
  Allocation *allocations;
  uint64_t allocation_count, allocation_capacity, byte_limit, bytes_mapped;
  uint64_t bias, heap_next, tls_base, fs_base;
  uint64_t stack_base;
  uint64_t return_area;
  uint64_t ctype_base;
  Undo *undo;
  uint64_t undo_count, undo_capacity;
  uint8_t *snapshot;
  uint64_t snapshot_size;
  int transaction;
  ZvrilTraceRecord *trace;
  uint64_t trace_capacity, trace_count;
  uint64_t flags_valid;
  uint64_t unknown_flags;
  int dynamic_code;
  unsigned rep_fault_restore;
};
static int span(uint64_t base, uint64_t size) {
  return size && size - 1 <= UINT64_MAX - base;
}
static void fault(ZvrilRuntime *r, uint64_t kind, uint64_t address,
                  uint64_t width) {
  if (!r->status.fault) {
    r->status.fault = kind;
    r->status.fault_address = address;
    r->status.fault_width = width;
  }
}
static Page *page(ZvrilRuntime *r, uint64_t address) {
  uint64_t lo = 0, hi = r->page_count;
  while (lo < hi) {
    uint64_t m = lo + (hi - lo) / 2;
    if (r->pages[m].base <= address)
      lo = m + 1;
    else
      hi = m;
  }
  if (!lo)
    return NULL;
  Page *p = &r->pages[lo - 1];
  return address - p->base < p->size ? p : NULL;
}
static int reserve(void **data, uint64_t *capacity, uint64_t needed,
                   uint64_t width) {
  if (needed <= *capacity)
    return 1;
  uint64_t next = *capacity ? *capacity : 16;
  while (next < needed) {
    if (next > UINT64_MAX / 2)
      return 0;
    next *= 2;
  }
  if (next > SIZE_MAX / width)
    return 0;
  void *p = realloc(*data, (size_t)(next * width));
  if (!p)
    return 0;
  *data = p;
  *capacity = next;
  return 1;
}
ZvrilRuntime *zvril_runtime_create(uint64_t bytes, uint64_t steps) {
  if (!bytes || bytes > SIZE_MAX)
    return NULL;
  ZvrilRuntime *r = (ZvrilRuntime *)calloc(1, sizeof(*r));
  if (r) {
    r->byte_limit = bytes;
    r->status.steps_left = steps;
    r->heap_next = UINT64_C(0x700000000000);
    r->flags_valid = UINT64_C(0xcd5);
    r->rep_fault_restore = 3;
  }
  return r;
}
void zvril_runtime_destroy(ZvrilRuntime *r) {
  if (!r)
    return;
  for (uint64_t i = 0; i < r->allocation_count; i++)
    if (r->allocations[i].owned) {
      free(r->allocations[i].data);
      free(r->allocations[i].initialized);
    }
  free(r->pages);
  free(r->allocations);
  free(r->snapshot);
  free(r->undo);
  free(r);
}
static int map_data(ZvrilRuntime *r, uint64_t base, uint64_t size,
                    unsigned permissions, uint8_t *data, uint8_t *init,
                    int owned) {
  if (!span(base, size) || size > r->byte_limit - r->bytes_mapped ||
      (permissions & ~7u))
    return 0;
  for (uint64_t i = 0; i < r->page_count; i++) {
    Page *p = &r->pages[i];
    if (base <= p->base ? p->base - base < size : base - p->base < p->size)
      return 0;
  }
  uint64_t count = 1 + (size - 1 + (base & 4095)) / 4096;
  if (count > 65536 || r->page_count > 65536 - count ||
      !reserve((void **)&r->pages, &r->page_capacity, r->page_count + count,
               sizeof(Page)) ||
      !reserve((void **)&r->allocations, &r->allocation_capacity,
               r->allocation_count + 1, sizeof(Allocation)))
    return 0;
  uint64_t offset = 0;
  while (offset < size) {
    uint64_t at = base + offset, n = 4096 - (at & 4095);
    if (n > size - offset)
      n = size - offset;
    uint64_t pos = r->page_count;
    while (pos && r->pages[pos - 1].base > at) {
      r->pages[pos] = r->pages[pos - 1];
      pos--;
    }
    r->pages[pos] =
        (Page){at, n, data + offset, init ? init + offset : NULL, permissions};
    r->page_count++;
    offset += n;
  }
  r->allocations[r->allocation_count++] =
      (Allocation){base, size, data, init, owned, 0};
  r->bytes_mapped += size;
  return 1;
}
int zvril_runtime_map(ZvrilRuntime *r, uint64_t base, uint64_t size,
                      unsigned permissions, const void *initial, uint64_t n,
                      int zero) {
  if (!r || !span(base, size) || n > size || (n && !initial) ||
      size > r->byte_limit - r->bytes_mapped || size > SIZE_MAX)
    return 0;
  uint8_t *bytes = (uint8_t *)calloc(1, (size_t)size);
  uint8_t *init = (uint8_t *)calloc(1, (size_t)size);
  if (!bytes || !init) {
    free(bytes);
    free(init);
    return 0;
  }
  if (zero)
    memset(init, 1, (size_t)size);
  if (n) {
    memcpy(bytes, initial, (size_t)n);
    memset(init, 1, (size_t)n);
  }
  if (!map_data(r, base, size, permissions, bytes, init, 1)) {
    free(bytes);
    free(init);
    return 0;
  }
  return 1;
}
static int check(ZvrilRuntime *r, uint64_t at, uint64_t n, int write,
                 int initialized) {
  if (r->status.fault)
    return 0;
  if (!n)
    return 1;
  if (!span(at, n) || n > r->byte_limit) {
    fault(r, write ? 2 : 1, at, n);
    return 0;
  }
  uint64_t offset = 0;
  while (offset < n) {
    Page *p = page(r, at + offset);
    if (!p || !(p->permissions & (write ? ZVRIL_W : ZVRIL_R))) {
      fault(r, write ? 2 : 1, at, n);
      return 0;
    }
    if (write && (p->permissions & ZVRIL_X) && !r->dynamic_code) {
      // The static instruction graph is immutable. Never continue execution
      // using stale semantics after a guest executable-memory write.
      fault(r, ZVRIL_FAULT_EXTERNAL, at, n);
      return 0;
    }
    uint64_t within = at + offset - p->base, take = p->size - within;
    if (take > n - offset)
      take = n - offset;
    if (initialized && p->initialized)
      for (uint64_t j = 0; j < take; j++)
        if (!p->initialized[within + j]) {
          fault(r, 6, at + offset + j, n);
          return 0;
        }
    offset += take;
  }
  return 1;
}
int zvril_runtime_read(ZvrilRuntime *r, uint64_t at, void *output, uint64_t n) {
  if (!r || (n && !output) || !check(r, at, n, 0, 1))
    return 0;
  uint64_t offset = 0;
  while (offset < n) {
    Page *p = page(r, at + offset);
    uint64_t pos = at + offset - p->base, take = p->size - pos;
    if (take > n - offset)
      take = n - offset;
    memcpy((uint8_t *)output + offset, p->data + pos, (size_t)take);
    offset += take;
  }
  return 1;
}
int zvril_runtime_write(ZvrilRuntime *r, uint64_t at, const void *input,
                        uint64_t n) {
  if (!r || (n && !input) || !check(r, at, n, 1, 0))
    return 0;
  if (r->transaction && (n > r->byte_limit - r->undo_count ||
                         !reserve((void **)&r->undo, &r->undo_capacity,
                                  r->undo_count + n, sizeof(Undo)))) {
    fault(r, 7, at, n);
    return 0;
  }
  for (uint64_t i = 0; i < n; i++) {
    Page *p = page(r, at + i);
    uint64_t pos = at + i - p->base;
    if (r->transaction)
      r->undo[r->undo_count++] = (Undo){
          at + i, p->data[pos], p->initialized ? p->initialized[pos] : 1};
    p->data[pos] = ((const uint8_t *)input)[i];
    if (p->initialized)
      p->initialized[pos] = 1;
  }
  return 1;
}
ZvrilMemory *zvril_runtime_status(ZvrilRuntime *r) {
  return r ? &r->status : NULL;
}
void zvril_runtime_set_return(ZvrilRuntime *r, uint64_t v) {
  r->status.return_pc = v;
}
void zvril_runtime_clear_fault(ZvrilRuntime *r) {
  r->status.fault = 0;
  r->status.fault_address = 0;
  r->status.fault_width = 0;
}
void zvril_runtime_trace(ZvrilRuntime *r, ZvrilTraceRecord *p, uint64_t n) {
  r->trace = p;
  r->trace_capacity = n;
  r->trace_count = 0;
}
uint64_t zvril_runtime_trace_count(ZvrilRuntime *r) { return r->trace_count; }
uint64_t zvril_runtime_flags_valid(ZvrilRuntime *r) { return r->flags_valid; }
void zvril_runtime_set_flags_valid(ZvrilRuntime *r, uint64_t mask) {
  r->flags_valid = mask;
}
uint64_t zvril_runtime_unknown_flags(ZvrilRuntime *r) {
  return r->unknown_flags;
}
int zvril_runtime_set_rep_fault_flags(ZvrilRuntime *r, unsigned mask) {
  if (!r || mask > 3)
    return 0;
  r->rep_fault_restore = mask;
  return 1;
}
uint64_t zvril_runtime_rep_fault_flags(ZvrilRuntime *r) {
  return r->rep_fault_restore;
}
void zvril_rt_consume_flags(ZvrilRuntime *r, uint64_t mask) {
  if (mask & ~r->flags_valid)
    r->unknown_flags |= mask & ~r->flags_valid;
}
int zvril_rt_tracing(ZvrilRuntime *r) { return r->trace != NULL; }
uint64_t zvril_runtime_bias(ZvrilRuntime *r) { return r->bias; }
void zvril_runtime_set_bias(ZvrilRuntime *r, uint64_t v) { r->bias = v; }
uint64_t zvril_runtime_stack(ZvrilRuntime *r) {
  if (r->stack_base)
    return r->stack_base;
  uint64_t base = UINT64_C(0x7fff00000000);
  if (!zvril_runtime_map(r, base, 65536, 3, 0, 0, 1)) {
    fault(r, 7, base, 65536);
    return 0;
  }
  r->stack_base = base;
  return base;
}
uint64_t zvril_runtime_return_area(ZvrilRuntime *r) {
  if (r->return_area)
    return r->return_area;
  uint64_t base = UINT64_C(0x58000000);
  if (!zvril_runtime_map(r, base, 4096, 3, 0, 0, 1)) {
    fault(r, 7, base, 4096);
    return 0;
  }
  r->return_area = base;
  return base;
}
int zvril_runtime_success(ZvrilRuntime *r) {
  return r && !r->status.fault && !r->unknown_flags;
}
uint64_t zvril_runtime_fsbase(ZvrilRuntime *r) { return r->fs_base; }
void zvril_runtime_set_fsbase(ZvrilRuntime *r, uint64_t value) {
  r->fs_base = value;
}
void zvril_runtime_dynamic_code(ZvrilRuntime *r, int enabled) {
  r->dynamic_code = enabled != 0;
}
int zvril_runtime_probe(ZvrilRuntime *r, uint64_t address, uint64_t n,
                        unsigned permissions) {
  if (!r || (permissions & ~7u) || (n && !span(address, n)))
    return 0;
  uint64_t offset = 0;
  while (offset < n) {
    Page *p = page(r, address + offset);
    if (!p || (p->permissions & permissions) != permissions)
      return 0;
    uint64_t take = p->size - (address + offset - p->base);
    if (take > n - offset)
      take = n - offset;
    offset += take;
  }
  return 1;
}
int zvril_runtime_fetch(ZvrilRuntime *r, uint64_t address, void *out,
                        uint64_t n) {
  if (!r || !span(address, n) || !out || r->status.fault)
    return 0;
  for (uint64_t i = 0; i < n; i++) {
    Page *p = page(r, address + i);
    if (!p || !(p->permissions & ZVRIL_X) ||
        (p->initialized && !p->initialized[address + i - p->base]))
      return 0;
  }
  for (uint64_t i = 0; i < n; i++) {
    Page *p = page(r, address + i);
    ((uint8_t *)out)[i] = p->data[address + i - p->base];
  }
  return 1;
}
int zvril_runtime_tls(ZvrilRuntime *r, uint64_t size, uint64_t alignment,
                      const void *initial, uint64_t n) {
  if (!r || r->fs_base || !alignment || (alignment & (alignment - 1)) ||
      alignment > 4096 || n > size || size > UINT64_MAX - alignment)
    return 0;
  uint64_t extent = (size + alignment - 1) & ~(alignment - 1);
  if (extent > UINT64_MAX - 8191)
    return 0;
  uint64_t tp = UINT64_C(0x600000000000) + ((extent + 4095) & ~UINT64_C(4095));
  if (tp < extent)
    return 0;
  uint64_t base = tp - extent;
  if (extent > UINT64_MAX - 4096 ||
      !zvril_runtime_map(r, base, extent + 4096, 3, initial, n, 1))
    return 0;
  r->tls_base = base;
  r->fs_base = base + extent;
  // Single-threaded SysV TLS variant II, with a self pointer in the TCB.
  return zvril_runtime_write(r, r->fs_base, &r->fs_base, 8);
}

/* Only generated code calls these transaction/compatibility helpers. */
int zvril_rt_begin(ZvrilRuntime *r, void *state, uint64_t size, uint64_t pc,
                   uint64_t valid) {
  r->status.fault_pc = pc;
  (void)valid;
  if (r->status.fault)
    return 0;
  if (!r->status.steps_left) {
    fault(r, 3, pc, 0);
    return 0;
  }
  r->status.steps_left--;
  if (size > r->snapshot_size) {
    void *p = realloc(r->snapshot, (size_t)size);
    if (!p) {
      fault(r, 7, pc, 0);
      return 0;
    }
    r->snapshot = p;
    r->snapshot_size = size;
  }
  memcpy(r->snapshot, state, (size_t)size);
  r->undo_count = 0;
  r->transaction = 1;
  return 1;
}
int zvril_rt_end(ZvrilRuntime *r, void *state, uint64_t size) {
  r->transaction = 0;
  if (!r->status.fault) {
    r->undo_count = 0;
    return 1;
  }
  memcpy(state, r->snapshot, (size_t)size);
  while (r->undo_count) {
    Undo *u = &r->undo[--r->undo_count];
    Page *p = page(r, u->address);
    uint64_t pos = u->address - p->base;
    p->data[pos] = u->value;
    if (p->initialized)
      p->initialized[pos] = u->initialized;
  }
  return 0;
}
void zvril_rt_fault(ZvrilRuntime *r, uint64_t code, uint64_t address,
                    uint64_t width) {
  fault(r, code, address, width);
}
ZvrilRuntime *zvril_rt_legacy_begin(ZvrilMemory *m) {
  uint64_t n = m->size ? m->size : 1;
  ZvrilRuntime *r = zvril_runtime_create(n, m->steps_left);
  if (!r)
    return NULL;
  r->status = *m;
  if (m->size && m->data && span(m->base, m->size) &&
      !map_data(r, m->base, m->size, ZVRIL_R | ZVRIL_W, m->data, NULL, 0))
    fault(r, 7, m->base, m->size);
  return r;
}
void zvril_rt_legacy_end(ZvrilRuntime *r, ZvrilMemory *m) {
  if (r) {
    *m = r->status;
    zvril_runtime_destroy(r);
  } else
    m->fault = 7;
}
void zvril_rt_record(ZvrilRuntime *r, const uint64_t *gpr, uint64_t flags) {
  if (!r->trace)
    return;
  if (r->trace_count < r->trace_capacity) {
    ZvrilTraceRecord *t = &r->trace[r->trace_count];
    t->pc = r->status.fault_pc;
    memcpy(t->gpr, gpr, 17 * 8);
    t->flags = flags;
    t->flags_valid = r->flags_valid;
  }
  r->trace_count++;
}
static uint64_t allocate(ZvrilRuntime *r, uint64_t n, int zero) {
  if (!n)
    n = 1;
  if (n > UINT64_MAX - 4095)
    return 0;
  uint64_t size = (n + 4095) & ~UINT64_C(4095), at = r->heap_next;
  if (!span(at, size) ||
      !zvril_runtime_map(r, at, n, ZVRIL_R | ZVRIL_W, NULL, 0, zero)) {
    fault(r, ZVRIL_FAULT_RESOURCE, at, n);
    return 0;
  }
  r->heap_next += size;
  return at;
}
static Allocation *allocation(ZvrilRuntime *r, uint64_t p) {
  for (uint64_t i = 0; i < r->allocation_count; i++)
    if (r->allocations[i].base == p && p >= UINT64_C(0x700000000000) &&
        !r->allocations[i].freed)
      return &r->allocations[i];
  return NULL;
}
static int release(ZvrilRuntime *r, uint64_t p) {
  if (!p)
    return 1;
  Allocation *a = allocation(r, p);
  if (!a) {
    fault(r, 8, p, 0);
    return 0;
  }
  for (uint64_t i = 0; i < r->page_count; i++)
    if (r->pages[i].base >= a->base && r->pages[i].base - a->base < a->size)
      r->pages[i].permissions = 0;
  a->freed = 1;
  return 1;
}
static int same(const char *a, const char *b) { return strcmp(a, b) == 0; }
uint64_t zvril_runtime_bridge(ZvrilRuntime *r, const char *name, uint64_t a,
                              uint64_t b, uint64_t n) {
  if (r->status.fault)
    return 0;
  if (same(name, "__ctype_b_loc")) {
    // glibc's unsigned-short table contract, explicitly C/POSIX locale only.
    if (!r->ctype_base) {
      uint16_t table[384] = {0};
      for (unsigned ch = 0; ch < 128; ch++) {
        unsigned upper = ch >= 'A' && ch <= 'Z', lower = ch >= 'a' && ch <= 'z',
                 digit = ch >= '0' && ch <= '9';
        unsigned alpha = upper || lower, alnum = alpha || digit,
                 space = ch == ' ' || (ch >= 9 && ch <= 13),
                 print = ch >= 32 && ch <= 126, graph = ch >= 33 && ch <= 126;
        table[ch + 128] =
            (uint16_t)((upper ? 0x100 : 0) | (lower ? 0x200 : 0) |
                       (alpha ? 0x400 : 0) | (digit ? 0x800 : 0) |
                       ((digit || (ch >= 'A' && ch <= 'F') ||
                         (ch >= 'a' && ch <= 'f'))
                            ? 0x1000
                            : 0) |
                       (space ? 0x2000 : 0) | (print ? 0x4000 : 0) |
                       (graph ? 0x8000 : 0) |
                       ((ch == ' ' || ch == '\t') ? 1 : 0) |
                       ((ch < 32 || ch == 127) ? 2 : 0) |
                       ((graph && !alnum) ? 4 : 0) | (alnum ? 8 : 0));
      }
      uint64_t base = UINT64_C(0x610000000000), pointer = base + 256;
      if (!zvril_runtime_map(r, base, 4096, 3, table, sizeof(table), 1) ||
          !zvril_runtime_write(r, base + 768, &pointer, 8) ||
          !zvril_runtime_protect(r, base, 4096, 1)) {
        fault(r, 7, base, 4096);
        return 0;
      }
      r->ctype_base = base + 768;
    }
    return r->ctype_base;
  }
  if (same(name, "__tls_get_addr")) {
    uint64_t descriptor[2];
    if (!r->fs_base || !zvril_runtime_read(r, a, descriptor, 16))
      return 0;
    if (descriptor[0] != 1 || descriptor[1] >= r->fs_base - r->tls_base) {
      fault(r, 8, a, 16);
      return 0;
    }
    return r->tls_base + descriptor[1];
  }
  if (same(name, "__zvril_tlsdesc")) {
    uint64_t descriptor[2];
    if (!r->fs_base || !zvril_runtime_read(r, a, descriptor, 16))
      return 0;
    uint64_t address = r->fs_base + descriptor[1];
    if (descriptor[0] != UINT64_C(0xffff80000000fd00) ||
        address < r->tls_base || address >= r->fs_base) {
      fault(r, 8, a, 16);
      return 0;
    }
    return descriptor[1];
  }
  if (same(name, "malloc"))
    return allocate(r, a, 0);
  if (same(name, "calloc")) {
    if (a && b > UINT64_MAX / a)
      return 0;
    return allocate(r, a * b, 1);
  }
  if (same(name, "free")) {
    release(r, a);
    return 0;
  }
  if (same(name, "realloc")) {
    if (!a)
      return allocate(r, b, 0);
    if (!b) {
      release(r, a);
      return 0;
    }
    Allocation *old = allocation(r, a);
    if (!old) {
      fault(r, 8, a, 0);
      return 0;
    }
    uint64_t old_size = old->size;
    uint8_t *old_data = old->data;
    uint8_t *old_init = old->initialized;
    uint64_t p = allocate(r, b, 0);
    if (!p)
      return 0;
    Allocation *dest = allocation(r, p);
    uint64_t count = old_size < b ? old_size : b;
    memcpy(dest->data, old_data, (size_t)count);
    memcpy(dest->initialized, old_init, (size_t)count);
    release(r, a);
    return p;
  }
  if (same(name, "memcpy") || same(name, "memmove") || same(name, "memset")) {
    if (n > r->byte_limit) {
      fault(r, 7, a, n);
      return 0;
    }
    if (!check(r, a, n, 1, 0))
      return 0;
    if (same(name, "memset")) {
      uint8_t byte = (uint8_t)b;
      for (uint64_t i = 0; i < n; i++)
        if (!zvril_runtime_write(r, a + i, &byte, 1))
          return 0;
      return a;
    }
    if (!check(r, b, n, 0, 1))
      return 0;
    if (same(name, "memcpy") && n && (a < b ? b - a < n : a - b < n)) {
      fault(r, 8, a, n);
      return 0;
    }
    if (a > b && a - b < n)
      for (uint64_t i = n; i; i--) {
        uint8_t x;
        zvril_runtime_read(r, b + i - 1, &x, 1);
        zvril_runtime_write(r, a + i - 1, &x, 1);
      }
    else
      for (uint64_t i = 0; i < n; i++) {
        uint8_t x;
        zvril_runtime_read(r, b + i, &x, 1);
        zvril_runtime_write(r, a + i, &x, 1);
      }
    return a;
  }
  int strlen_mode = same(name, "strlen"),
      string_mode = same(name, "strcmp") || same(name, "strncmp");
  int compare = same(name, "memcmp");
  if (strlen_mode || string_mode || compare) {
    uint64_t limit = (same(name, "strncmp") || compare) ? n : r->byte_limit;
    if (limit > r->byte_limit) {
      fault(r, 7, a, limit);
      return 0;
    }
    for (uint64_t i = 0; i < limit; i++) {
      if (i > UINT64_MAX - a || (!strlen_mode && i > UINT64_MAX - b)) {
        fault(r, 1, a, 1);
        return 0;
      }
      uint8_t x = 0, y = 0;
      if (!zvril_runtime_read(r, a + i, &x, 1))
        return 0;
      if (strlen_mode) {
        if (!x)
          return i;
        continue;
      }
      if (!zvril_runtime_read(r, b + i, &y, 1))
        return 0;
      if (x != y)
        return (uint64_t)(int64_t)((int)x - (int)y);
      if (string_mode && !x)
        return 0;
    }
    if (strlen_mode || (string_mode && !same(name, "strncmp")))
      fault(r, 7, a, limit);
    return 0;
  }
  fault(r, 8, 0, 0);
  return 0;
}
int zvril_runtime_protect(ZvrilRuntime *r, uint64_t address, uint64_t size,
                          unsigned permissions) {
  if (!r || !span(address, size) || (permissions & ~7u))
    return 0;
  // Validate the complete range before changing permissions or splitting pages.
  uint64_t checked = 0;
  while (checked < size) {
    Page *p = page(r, address + checked);
    if (!p)
      return 0;
    uint64_t take = p->size - (address + checked - p->base);
    if (take > size - checked)
      take = size - checked;
    checked += take;
  }
  if (r->page_count > 65534 || !reserve((void **)&r->pages, &r->page_capacity,
                                        r->page_count + 2, sizeof(Page)))
    return 0;
  /* Split page fragments at the protected range's endpoints. */
  for (unsigned endpoint = 0; endpoint < 2; endpoint++) {
    uint64_t at = endpoint ? address + size - 1 : address;
    if (endpoint) {
      if (at == UINT64_MAX)
        continue;
      at++;
    }
    Page *p = page(r, at);
    if (!p || p->base == at)
      continue;
    uint64_t index = (uint64_t)(p - r->pages), delta = at - p->base;
    if (!reserve((void **)&r->pages, &r->page_capacity, r->page_count + 1,
                 sizeof(Page)))
      return 0;
    p = &r->pages[index];
    Page second = *p;
    second.base = at;
    second.size -= delta;
    second.data += delta;
    if (second.initialized)
      second.initialized += delta;
    p->size = delta;
    memmove(r->pages + index + 2, r->pages + index + 1,
            (size_t)((r->page_count - index - 1) * sizeof(Page)));
    r->pages[index + 1] = second;
    r->page_count++;
  }
  uint64_t covered = 0;
  for (uint64_t i = 0; i < r->page_count; i++) {
    Page *p = &r->pages[i];
    if (p->base >= address && p->base - address < size) {
      p->permissions = permissions;
      covered += p->size;
    }
  }
  return covered == size;
}

int zvril_runtime_unmap(ZvrilRuntime *r, uint64_t address, uint64_t size) {
  if (!r || r->transaction || !span(address, size) || r->page_count > 65534 ||
      !reserve((void **)&r->pages, &r->page_capacity, r->page_count + 2,
               sizeof(Page)))
    return 0;
  /* Holes are legal, and partial unmaps preserve both surviving fragments. */
  for (unsigned end = 0; end < 2; end++) {
    if (end && address + size - 1 == UINT64_MAX)
      continue;
    uint64_t at = end ? address + size : address;
    Page *p = page(r, at);
    if (!p || p->base == at)
      continue;
    uint64_t index = (uint64_t)(p - r->pages), delta = at - p->base;
    Page second = *p;
    second.base = at;
    second.size -= delta;
    second.data += delta;
    if (second.initialized)
      second.initialized += delta;
    p->size = delta;
    memmove(r->pages + index + 2, r->pages + index + 1,
            (size_t)((r->page_count - index - 1) * sizeof(Page)));
    r->pages[index + 1] = second;
    r->page_count++;
  }
  uint64_t kept = 0;
  for (uint64_t i = 0; i < r->page_count; i++)
    if (r->pages[i].base < address || r->pages[i].base - address >= size)
      r->pages[kept++] = r->pages[i];
  r->page_count = kept;
  /* Retain partially mapped backing allocations until the final fragment is
   * gone. Account retained storage against the memory budget. */
  for (uint64_t i = 0; i < r->allocation_count; i++) {
    Allocation *a = &r->allocations[i];
    if (!a->owned)
      continue;
    int used = 0;
    for (uint64_t j = 0; j < r->page_count; j++) {
      uintptr_t p = (uintptr_t)r->pages[j].data, base = (uintptr_t)a->data;
      if (p >= base && p - base < a->size) {
        used = 1;
        break;
      }
    }
    if (!used) {
      free(a->data);
      free(a->initialized);
      a->data = a->initialized = NULL;
      a->owned = 0;
      a->freed = 1;
      r->bytes_mapped -= a->size;
    }
  }
  return 1;
}
