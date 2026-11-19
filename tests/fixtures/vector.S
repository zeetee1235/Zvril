.text
.globl program_avx2
.type program_avx2,@function
program_avx2:
  vmovdqu (%rsi), %ymm0
  vpaddd (%rdx), %ymm0, %ymm0
  vmovdqu %ymm0, (%rdi)
  vzeroupper
  ret
.size program_avx2, .-program_avx2
.globl program_constant
.type program_constant,@function
program_constant:
  sub $8,%rsp
  lea program_constant_helper(%rip),%rax
  call *%rax
  add $8,%rsp
  ret
.size program_constant,.-program_constant
.hidden program_constant_helper
.globl program_constant_helper
.type program_constant_helper,@function
program_constant_helper:
  lea (%rdi,%rsi),%rax
  ret
.size program_constant_helper,.-program_constant_helper
.section .note.GNU-stack,"",@progbits
