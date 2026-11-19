// Freestanding C++ virtual dispatch. Exception/unwinder support is a separate
// gate.
extern "C" int process_main(unsigned long *stack);
extern "C" void process_relocate();
asm(".text\n.global _start\n.type _start,@function\n_start:\n"
    "xor %ebp,%ebp\nmov %rsp,%r12\nand $-16,%rsp\ncall process_relocate\n"
    "mov %r12,%rdi\ncall process_main\n"
    "mov %eax,%edi\nmov $231,%eax\nsyscall\nud2\n"
    ".size _start,.-_start\n");
// Minimal fixture CRT: the Linux kernel leaves static PIE self-relocation to
// user startup. The same code runs in the native and translated executions.
extern "C" void process_relocate() {
#ifdef __PIE__
  extern unsigned char __ehdr_start[] __attribute__((visibility("hidden")));
  extern unsigned long _DYNAMIC[] __attribute__((visibility("hidden")));
  const auto bias = reinterpret_cast<unsigned long>(__ehdr_start);
  unsigned long records = 0, size = 0;
  for (auto *entry = _DYNAMIC; entry[0]; entry += 2) {
    if (entry[0] == 7)
      records = entry[1];
    if (entry[0] == 8)
      size = entry[1];
  }
  for (unsigned long offset = 0; offset < size; offset += 24) {
    auto *record =
        reinterpret_cast<const unsigned long *>(bias + records + offset);
    if (record[1] == 8)
      *reinterpret_cast<unsigned long *>(bias + record[0]) = bias + record[2];
  }
#endif
}
class Operation {
public:
  virtual unsigned long apply(const unsigned char *, unsigned long) = 0;
};
class Sum final : public Operation {
public:
  unsigned long apply(const unsigned char *data, unsigned long count) override {
    unsigned long result = 9;
    for (unsigned long i = 0; i < count; i++)
      result += data[i];
    return result;
  }
};
class Xor final : public Operation {
public:
  unsigned long apply(const unsigned char *data, unsigned long count) override {
    unsigned long result = 17;
    for (unsigned long i = 0; i < count; i++)
      result ^= data[i];
    return result;
  }
};
__attribute__((noinline)) static unsigned long
execute(Operation *operation, const unsigned char *data, unsigned long count) {
  return operation->apply(data, count);
}
extern "C" int process_main(unsigned long *stack) {
  if (stack[0] != 2)
    return 99;
  auto *argument = reinterpret_cast<const unsigned char *>(stack[2]);
  unsigned long length = 0;
  while (argument[length])
    ++length;
  Sum sum;
  Xor xored;
  auto result =
      execute(&sum, argument, length) + execute(&xored, argument, length);
  const char text[] = "cpp\n";
  long output;
  asm volatile("syscall"
               : "=a"(output)
               : "a"(1L), "D"(1L), "S"(text), "d"(4L)
               : "rcx", "r11", "memory");
  if (output != 4)
    return 98;
  return result & 255;
}
