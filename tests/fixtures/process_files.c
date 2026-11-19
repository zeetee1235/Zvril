typedef unsigned long U;
static long call(long n,long a,long b,long c,long d,long e,long f) {
 register long r10 asm("r10")=d;register long r8 asm("r8")=e;register long r9 asm("r9")=f;
 long result;asm volatile("syscall":"=a"(result):"a"(n),"D"(a),"S"(b),"d"(c),"r"(r10),"r"(r8),"r"(r9):"rcx","r11","memory");return result;
}
#define S(n,a,b,c) call(n,(long)(a),(long)(b),(long)(c),0,0,0)
struct Vec {void *data;U size;};
int process_main(void) {
 char data[16]={0};U st[18];
 long fd=call(257,-100,(long)"input.bin",0,0,0,0);if(fd<0)return 1;
 if(S(5,fd,st,0)||st[6]!=6)return 2;
 if(S(0,fd,data,2)!=2||data[0]!='A'||data[1]!='B')return 3;
 long alias=S(32,fd,0,0);if(alias<0)return 4;
 if(S(0,alias,data+2,2)!=2||data[2]!='C'||data[3]!='D')return 5;
 if(call(17,fd,(long)(data+4),1,5,0,0)!=1||data[4]!='F')return 6;
 if(S(8,fd,0,0))return 7;
 struct Vec vectors[2]={{data,2},{data+2,4}};
 if(S(19,fd,vectors,2)!=6)return 8;
 for(int i=0;i<6;i++)if(data[i]!='A'+i)return 9;
 if(S(3,alias,0,0)||S(3,fd,0,0))return 10;
 long output=call(257,-100,(long)"output.bin",0x242,0644,0,0);if(output<0)return 11;
 vectors[0].data=data;vectors[0].size=2;vectors[1].data=data+4;vectors[1].size=2;
 if(S(20,output,vectors,2)!=4)return 12;
 if(call(18,output,(long)(data+2),1,2,0,0)!=1)return 13;
 if(S(8,output,0,0)||S(0,output,data+8,4)!=4)return 14;
 if(data[8]!='A'||data[9]!='B'||data[10]!='C'||data[11]!='F')return 15;
 long mapping=call(9,0,4096,3,2,output,0);if(mapping<0)return 16;
 volatile char *mapped=(volatile char*)mapping;
 if(mapped[0]!='A'||mapped[2]!='C')return 17;
 mapped[0]='Z';
 if(call(17,output,(long)data,1,0,0,0)!=1||data[0]!='A')return 18;
 if(S(11,mapping,4096,0)||S(3,output,0,0))return 19;
 if(S(1,1,data+8,4)!=4)return 20;
 return 59;
}
asm(".text\n.global _start\n_start:\nxor %ebp,%ebp\nand $-16,%rsp\ncall process_main\nmov %eax,%edi\nmov $231,%eax\nsyscall\nud2\n");
