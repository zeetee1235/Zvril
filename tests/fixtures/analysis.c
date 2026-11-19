/* Newly written analysis fixture. The CLI tests never execute this ELF. */
#include <stddef.h>
#include <stdio.h>

unsigned char zvril_bss[8192];
volatile int zvril_bias = 7;

__attribute__((noinline, used)) static int local_helper(int value) {
  return value + zvril_bias;
}

int target(int value) {
  zvril_bss[0] = (unsigned char)value;
  return local_helper(value);
}

int target_alias(int) __attribute__((alias("target")));

int external_call(const char* text) {
  return puts(text);
}

int main(void) {
  return target(3);
}
