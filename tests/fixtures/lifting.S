.intel_syntax noprefix
.text
.macro function name
.global \name
.type \name,@function
\name:
.endm
.macro endfunction name
.size \name,.-\name
.endm

function lift_add
  mov rax,rdi
  add rax,rsi
  ret
endfunction lift_add

function lift_partial
  mov rax,-1
  mov ax,di
  mov rcx,rsi
  mov ah,cl
  ret
endfunction lift_partial

function lift_shift
  mov rax,rdi
  mov rcx,rsi
  shl rax,cl
  ret
endfunction lift_shift

function lift_sum
  xor eax,eax
  xor ecx,ecx
.Lsum_loop:
  cmp rcx,rsi
  jae .Lsum_done
  movzx edx,byte ptr[rdi+rcx]
  add rax,rdx
  inc rcx
  jmp .Lsum_loop
.Lsum_done:
  ret
endfunction lift_sum

function lift_store
  movzx eax,byte ptr[rdi]
  add al,1
  mov byte ptr[rdi+1],al
  ret
endfunction lift_store

function lift_unaligned
  mov rax,qword ptr[rdi+1]
  ret
endfunction lift_unaligned

function lift_stack
  push rbp
  mov rbp,rsp
  sub rsp,32
  mov qword ptr[rsp],rdi
  mov rax,qword ptr[rsp]
  leave
  ret
endfunction lift_stack

.hidden lift_helper
function lift_helper
  lea rax,[rdi+rsi]
  ret
endfunction lift_helper

function lift_call
  sub rsp,8
  call lift_helper
  add rax,5
  add rsp,8
  ret
endfunction lift_call

function lift_tail
  jmp lift_helper
endfunction lift_tail

.protected lift_factorial
function lift_factorial
  cmp rdi,1
  jbe .Lfactorial_one
  push rdi
  dec rdi
  call lift_factorial
  pop rdi
  imul rax,rdi
  ret
.Lfactorial_one:
  mov eax,1
  ret
endfunction lift_factorial

function lift_sse
  movdqu xmm0,xmmword ptr[rdi]
  pxor xmm0,xmmword ptr[rdi+16]
  movdqu xmmword ptr[rdi+32],xmm0
  movq rax,xmm0
  ret
endfunction lift_sse

function lift_float
  movq xmm0,rdi
  movq xmm1,rsi
  addsd xmm0,xmm1
  movq rax,xmm0
  ret
endfunction lift_float

function lift_infinite
.Lforever:
  jmp .Lforever
endfunction lift_infinite

function lift_indirect
  call rax
  ret
endfunction lift_indirect

function lift_syscall
  syscall
  ret
endfunction lift_syscall

function lift_cpuid
  cpuid
  ret
endfunction lift_cpuid

function lift_rep
  addr32 rep movsb
  ret
endfunction lift_rep

function lift_external
  call puts@PLT
  ret
endfunction lift_external

function lift_truncated
  .byte 0x0f
endfunction lift_truncated

function lift_overlap
  .byte 0xeb,0xff
endfunction lift_overlap

function native_add_flags
  mov rax,rdi
  add rax,rsi
  mov qword ptr[rdx],rax
  pushfq
  pop rcx
  mov qword ptr[rdx+8],rcx
  ret
endfunction native_add_flags

.section .note.GNU-stack,"",@progbits
