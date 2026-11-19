.text
.globl table_tail
.type table_tail,@function
table_tail:
 cmp $2,%edi
 ja 1f
 mov %edi,%eax
 mov %rsi,%rdi
 lea dispatch_table(%rip),%rdx
 jmp *(%rdx,%rax,8)
1: xor %eax,%eax
 ret
.size table_tail,.-table_tail

.globl table_call
.type table_call,@function
table_call:
 cmp $2,%edi
 ja 1f
 mov %edi,%eax
 mov %rsi,%rdi
 lea dispatch_table(%rip),%rdx
 sub $8,%rsp
 call *(%rdx,%rax,8)
 add $8,%rsp
 add $17,%rax
 ret
1: xor %eax,%eax
 ret
.size table_call,.-table_call

.hidden table_one
.type table_one,@function
table_one:
 lea 1(%rdi),%rax
 ret
.size table_one,.-table_one
.hidden table_two
.type table_two,@function
table_two:
 lea (%rdi,%rdi,2),%rax
 ret
.size table_two,.-table_two
.hidden table_three
.type table_three,@function
table_three:
 mov %rdi,%rax
 xor $0x1234,%rax
 ret
.size table_three,.-table_three

#ifdef MUTABLE_TABLE
.data
#else
.section .data.rel.ro,"aw",@progbits
#endif
.align 8
.hidden dispatch_table
dispatch_table:
.quad table_one,table_two,table_three
.section .note.GNU-stack,"",@progbits
