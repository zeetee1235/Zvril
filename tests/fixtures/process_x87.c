#include <stdio.h>

int main(void) {
  volatile long double value = 2.0L;
  value *= 3.0L;
  printf("x87:%.1Lf\n", value);
  return value == 6.0L ? 0 : 9;
}
