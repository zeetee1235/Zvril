.global _start
.text
_start:
 mov $9,%eax
 xor %edi,%edi
 mov $4096,%esi
 mov $3,%edx
 mov $0x22,%r10d
 mov $-1,%r8
 xor %r9d,%r9d
 syscall
 test %rax,%rax
 js fail
 mov %rax,%r12
 /* mov eax,17; ret */
 movb $0xb8,(%r12)
 movl $17,1(%r12)
 movb $0xc3,5(%r12)
 mov $10,%eax
 mov %r12,%rdi
 mov $4096,%esi
 mov $5,%edx
 syscall
 test %rax,%rax
 jnz fail
 call *%r12
 cmp $17,%eax
 jne fail
 mov $10,%eax
 mov %r12,%rdi
 mov $4096,%esi
 mov $7,%edx
 syscall
 test %rax,%rax
 jnz fail
 /* Change already executed instruction bytes while page is executable. */
 movl $29,1(%r12)
 call *%r12
 cmp $29,%eax
 jne fail
 /* Revert and enter the original compiled version again. */
 movl $17,1(%r12)
 call *%r12
 cmp $17,%eax
 jne fail
 mov $11,%eax
 mov %r12,%rdi
 mov $4096,%esi
 syscall
 test %rax,%rax
 jnz fail
 mov $231,%eax
 mov $37,%edi
 syscall
fail:
 mov $231,%eax
 mov $99,%edi
 syscall
.section .note.GNU-stack,"",@progbits
