.global _start
.text
_start:
 /* Per-task FS and GS are guest state, never host arch_prctl. */
 mov $158,%eax
 mov $0x1002,%edi
 lea parent_tls(%rip),%rsi
 syscall
 mov $158,%eax
 mov $0x1001,%edi
 lea parent_tls(%rip),%rsi
 syscall
 /* Shared VM/FS/files/sighand/thread, SETTLS, TID stores and clear_child_tid. */
 mov $56,%eax
 mov $0x13d0f00,%edi
 lea child_stack_end(%rip),%rsi
 lea parent_tid(%rip),%rdx
 lea child_tid(%rip),%r10
 lea child_tls(%rip),%r8
 syscall
 test %rax,%rax
 jz child
 cmp %eax,parent_tid(%rip)
 jne fail
parent_wait:
 mov child_tid(%rip),%edx
 test %edx,%edx
 jz joined
 mov $202,%eax
 lea child_tid(%rip),%rdi
 /* clear_child_tid uses the shared futex wake operation. */
 xor %esi,%esi
 xor %r10d,%r10d
 xor %r8d,%r8d
 xor %r9d,%r9d
 syscall
 jmp parent_wait
joined:
 cmpl $43,counter(%rip)
 jne fail
 cmpl $11,%fs:0
 jne fail
 cmpl $11,%gs:0
 jne fail
 mov $231,%eax
 mov $41,%edi
 syscall
child:
 cmpl $22,%fs:0
 jne fail
 cmpl $11,%gs:0
 jne fail
 mov $186,%eax
 syscall
 cmp %eax,child_tid(%rip)
 jne fail
 mov $42,%eax
 lock xadd %eax,counter(%rip)
 jz fail
 test %eax,%eax
 jnz fail
 mov $42,%eax
 mov $43,%edx
 lock cmpxchg %edx,counter(%rip)
 jne fail
 xor %eax,%eax
 mov $99,%edx
 lock cmpxchg %edx,counter(%rip)
 je fail
 cmp $43,%eax
 jne fail
 mov $7,%eax
 mov $9,%edx
 mov $11,%ebx
 mov $13,%ecx
 lock cmpxchg8b pair8(%rip)
 jne fail
 xor %eax,%eax
 xor %edx,%edx
 lock cmpxchg8b pair8(%rip)
 je fail
 cmp $11,%eax
 jne fail
 cmp $13,%edx
 jne fail
 mov $17,%eax
 mov $19,%edx
 mov $23,%ebx
 mov $29,%ecx
 lock cmpxchg16b pair16(%rip)
 jne fail
 xor %eax,%eax
 xor %edx,%edx
 lock cmpxchg16b pair16(%rip)
 je fail
 cmp $23,%rax
 jne fail
 cmp $29,%rdx
 jne fail
 /* Give the parent time to enter its futex wait. */
 mov $40,%ecx
spin: dec %ecx
 jnz spin
 mov $60,%eax
 xor %edi,%edi
 syscall
fail:
 mov $231,%eax
 mov $99,%edi
 syscall
.data
.balign 8
parent_tls: .quad 11
child_tls: .quad 22
counter: .long 0
parent_tid: .long 0
child_tid: .long 1
.balign 16
pair8: .long 7,9
.balign 16
pair16: .quad 17,19
.bss
.balign 16
child_stack: .skip 16384
child_stack_end:
.section .note.GNU-stack,"",@progbits
