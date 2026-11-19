#include <stdarg.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
static volatile uint64_t data_value = 17;
static volatile uint64_t *volatile data_pointer = &data_value;
static volatile uint64_t zero_value;
uint64_t program_data(uint64_t x) {
  zero_value = x;
  return *data_pointer + zero_value;
}
uint64_t program_address(void) { return (uint64_t)&data_value; }
uint64_t program_store(uint64_t *p, uint64_t x) {
  *p = x;
  return x;
}
uint64_t program_load(const uint64_t *p) { return *p; }
uint64_t program_varint(unsigned n, ...) {
  va_list ap;
  va_start(ap, n);
  uint64_t s = 0;
  for (unsigned i = 0; i < n; i++)
    s += va_arg(ap, uint64_t);
  va_end(ap);
  return s;
}
double program_varfloat(unsigned n, ...) {
  va_list ap;
  va_start(ap, n);
  double s = 0;
  for (unsigned i = 0; i < n; i++)
    s += va_arg(ap, double);
  va_end(ap);
  return s;
}
uint64_t program_strlen(const char *s) { return strlen(s); }
void *program_copy(void *a, const void *b, uint64_t n) {
  return memcpy(a, b, n);
}
int program_compare(const char *a, const char *b) { return strcmp(a, b); }
uint64_t program_heap(uint64_t x) {
  uint64_t *p = calloc(2, sizeof(uint64_t));
  if (!p)
    return 0;
  p[0] = x;
  uint64_t y = p[0] + p[1];
  free(p);
  return y;
}
uint64_t program_stack(uint64_t a, uint64_t b, uint64_t c, uint64_t d,
                       uint64_t e, uint64_t f, uint64_t g, uint64_t h) {
  return a + b + c + d + e + f + g + h;
}
double program_float(double a, double b, double c) { return a * b + c; }
int64_t program_div(int64_t a, int64_t b) { return a / b; }
void program_trap(void) { __asm__ volatile("ud2"); }
static __thread uint64_t tls_value __attribute__((tls_model("initial-exec"))) =
    31;
uint64_t program_tls(uint64_t x) {
  tls_value += x;
  return tls_value;
}
