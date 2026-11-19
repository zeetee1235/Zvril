#include <dlfcn.h>
#include <stdio.h>

int main(void) {
  void *library = dlopen("libm.so.6", RTLD_NOW);
  if (!library) {
    puts(dlerror());
    return 91;
  }
  double (*square_root)(double) =
      (double (*)(double))dlsym(library, "sqrt");
  if (!square_root)
    return 92;
  double value = square_root(81.0);
  printf("dlopen:%.0f\n", value);
  return value == 9.0 ? 0 : 93;
}
