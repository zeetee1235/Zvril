#define _GNU_SOURCE
#include <signal.h>
#include <stdint.h>
#include <ucontext.h>
static long call(long n,long a,long b,long c,long d,long e,long f) {
 register long r10 asm("r10")=d;register long r8 asm("r8")=e;register long r9 asm("r9")=f;
 long result;asm volatile("syscall":"=a"(result):"a"(n),"D"(a),"S"(b),"d"(c),"r"(r10),"r"(r8),"r"(r9):"rcx","r11","memory");return result;
}
#define S(n,a,b,c) call(n,(long)(a),(long)(b),(long)(c),0,0,0)
struct Action {void (*handler)(int,siginfo_t*,void*);unsigned long flags;void (*restorer)(void);unsigned long mask;};
extern void restorer(void);
asm(".text\nrestorer:\nmov $15,%eax\nsyscall\nud2\n");
static unsigned char alternate[32768] __attribute__((aligned(16)));
static volatile int seen,handled_fpe,handled_ill,handled_segv;
static void die(void){S(231,99,0,0);for(;;){}}
static void handler(int signal,siginfo_t *info,void *opaque) {
 ucontext_t *context=(ucontext_t*)opaque;
 unsigned long sp;asm volatile("mov %%rsp,%0":"=r"(sp));
 if(sp<(unsigned long)alternate||sp>=(unsigned long)(alternate+sizeof(alternate)))die();
 stack_t active;if(S(131,0,&active,0)||!(active.ss_flags&SS_ONSTACK))die();
 if(info->si_signo!=signal)die();
 if(signal==SIGUSR1) {
   if(info->si_code!=SI_TKILL||info->si_pid!=S(39,0,0,0))die();
   ++seen;
   asm volatile("pxor %%xmm0,%%xmm0":::"xmm0");
 } else if(signal==SIGFPE) {
   if(info->si_code!=FPE_INTDIV||context->uc_mcontext.gregs[REG_TRAPNO]!=0)die();
   context->uc_mcontext.gregs[REG_RIP]+=2;context->uc_mcontext.gregs[REG_RAX]=123;++handled_fpe;
 } else if(signal==SIGILL) {
   if(context->uc_mcontext.gregs[REG_TRAPNO]!=6)die();
   context->uc_mcontext.gregs[REG_RIP]+=2;++handled_ill;
 } else if(signal==SIGSEGV) {
   if(info->si_addr||info->si_code!=SEGV_MAPERR||context->uc_mcontext.gregs[REG_TRAPNO]!=14)die();
   context->uc_mcontext.gregs[REG_RIP]+=6;++handled_segv;
 } else die();
}
static int install(int signal) {
 struct Action action={handler,SA_SIGINFO|SA_ONSTACK|0x04000000,restorer,0};
 return call(13,signal,(long)&action,0,8,0,0);
}
int process_main(void) {
 stack_t stack={alternate,0,sizeof(alternate)};if(S(131,&stack,0,0))return 1;
 if(install(SIGUSR1)||install(SIGFPE)||install(SIGILL)||install(SIGSEGV))return 2;
 unsigned long bit=1UL<<(SIGUSR1-1),pending=0,old=0;
 if(call(14,SIG_BLOCK,(long)&bit,(long)&old,8,0,0)||old)return 3;
 long pid=S(39,0,0,0),tid=S(186,0,0,0);
 if(S(234,pid,tid,SIGUSR1)||seen)return 4;
 if(S(127,&pending,8,0)||!(pending&bit))return 5;
 unsigned char pattern[16]={1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16},observed[16];
 asm volatile("movdqu %0,%%xmm0"::"m"(pattern):"xmm0");
 if(call(14,SIG_UNBLOCK,(long)&bit,0,8,0,0))return 6;
 asm volatile("movdqu %%xmm0,%0":"=m"(observed));
 if(seen!=1)return 7;
 for(int i=0;i<16;i++)if(observed[i]!=pattern[i])return 8;
 unsigned eax=7,edx=0;
 asm volatile("div %%ecx":"+a"(eax),"+d"(edx):"c"(0):"cc");
 if(eax!=123||handled_fpe!=1)return 9;
 asm volatile("ud2":::"memory");if(handled_ill!=1)return 10;
 asm volatile("movl $1,(%%rax)"::"a"(0):"memory");if(handled_segv!=1)return 11;
 pending=~0UL;if(S(127,&pending,8,0)||pending)return 12;
 stack.ss_flags=SS_DISABLE;if(S(131,&stack,0,0))return 13;
 if(S(1,1,"signals\n",8)!=8)return 14;
 return 67;
}
asm(".text\n.global _start\n_start:\nxor %ebp,%ebp\nand $-16,%rsp\ncall process_main\nmov %eax,%edi\nmov $231,%eax\nsyscall\nud2\n");
