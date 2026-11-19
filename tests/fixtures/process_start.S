/* Freestanding Linux process contract, no libc or function symbols required. */
.global _start
.text
_start:
 mov (%rsp),%r12
 cmp $3,%r12
 jne fail
 test $15,%rsp
 jnz fail
 mov 16(%rsp),%rsi
 cmpb $'a',(%rsi)
 jne fail
 mov 24(%rsp),%rsi
 cmpb $'b',(%rsi)
 jne fail
 cmpq $0,32(%rsp)
 jne fail
 mov 40(%rsp),%rsi
 cmpb $'T',(%rsi)
 jne fail
 cmpq $0,48(%rsp)
 jne fail
 lea 56(%rsp),%rbx
aux:
 mov (%rbx),%rax
 test %rax,%rax
 jz fail
 cmp $6,%rax
 je pagesize
 add $16,%rbx
 jmp aux
pagesize:
 cmpq $4096,8(%rbx)
 jne fail
 xor %eax,%eax
 xor %edi,%edi
 lea buffer(%rip),%rsi
 mov $32,%edx
 syscall
 mov %rax,%rdx
 mov $1,%eax
 mov $1,%edi
 syscall
 mov $1,%eax
 mov $2,%edi
 lea binary(%rip),%rsi
 mov $4,%edx
 syscall
 /* Bad buffers report -EFAULT and do not trap or poison later syscalls. */
 mov $1,%eax
 mov $1,%edi
 mov $1,%esi
 mov $8,%edx
 syscall
 cmp $-14,%rax
 jne fail
 mov $3,%eax
 mov $1,%edi
 syscall
 mov $1,%eax
 mov $1,%edi
 lea binary(%rip),%rsi
 mov $4,%edx
 syscall
 cmp $-9,%rax
 jne fail
 mov $231,%eax
 mov $23,%edi
 syscall
fail:
 mov $231,%eax
 mov $99,%edi
 syscall
.section .rodata
binary: .byte 0x00,0xff,0x41,0x0a
.bss
.balign 16
buffer: .skip 32
.section .note.GNU-stack,"",@progbits
