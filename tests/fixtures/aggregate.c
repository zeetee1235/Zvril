#include <stdint.h>
#include <stdarg.h>
typedef struct {uint64_t a,b;} UPair;
typedef struct {double a,b;} DPair;
typedef struct {uint64_t a;double b;} Mixed;
typedef struct {uint64_t a,b,c;} Big;
typedef struct {const unsigned char* p;uint64_t n;} PointerPair;
typedef struct {uint32_t a;uint64_t b;} Padded;
uint64_t aggregate_sum(UPair x,uint64_t y){return x.a+x.b+y;}
Mixed aggregate_mixed(Mixed x,double y){x.a+=3;x.b+=y;return x;}
DPair aggregate_double(DPair x){x.a+=1.5;x.b*=2;return x;}
Big aggregate_big(Big x,uint64_t y){x.a+=y;x.b^=y;x.c*=3;return x;}
uint64_t aggregate_rollback(uint64_t a,uint64_t b,uint64_t c,uint64_t d,uint64_t e,UPair x,uint64_t last){return a+b+c+d+e+x.a+x.b+last;}
double aggregate_sse_rollback(double a,double b,double c,double d,double e,double f,double g,DPair x,double last){return a+b+c+d+e+f+g+x.a+x.b+last;}
PointerPair aggregate_pointer(PointerPair x){if(x.n){x.p++;x.n--;}return x;}
Padded aggregate_padding(Padded x){x.a+=1;x.b+=2;return x;}
UPair aggregate_variadic(unsigned count,...){
 va_list args;va_start(args,count);UPair result={0,0};
 for(unsigned i=0;i<count;i++){UPair next=va_arg(args,UPair);result.a+=next.a;result.b+=next.b;}
 va_end(args);return result;
}
typedef struct {uint8_t a;uint16_t b;uint32_t c;} Small;
typedef struct __attribute__((aligned(16))) {uint64_t a;} Aligned;
typedef struct __attribute__((packed)) {uint8_t a;uint64_t b;} Packed;
typedef struct {Padded p;double scale;} Nested;
typedef struct {float a,b;} Floats;
typedef struct {float a;uint32_t b;double c;} IntegerWins;
Small aggregate_auto_small(Small x){x.a++;x.b*=3;x.c^=0x12345678;return x;}
Aligned aggregate_auto_aligned(Aligned x){x.a+=7;return x;}
Packed aggregate_auto_packed(Packed x){x.a++;x.b+=x.a;return x;}
Nested aggregate_auto_nested(Nested x){x.p.a+=2;x.p.b+=3;x.scale*=2;return x;}
Floats aggregate_auto_floats(Floats x){x.a+=0.5f;x.b*=2;return x;}
IntegerWins aggregate_auto_merge(IntegerWins x){x.a+=0.25f;x.b+=5;x.c*=3;return x;}
PointerPair aggregate_auto_pointer(PointerPair x){if(x.n){x.n+=*x.p;x.p++;}return x;}
uint64_t aggregate_auto_aligned_stack(uint64_t a,uint64_t b,uint64_t c,uint64_t d,uint64_t e,uint64_t f,uint64_t g,Aligned x,uint64_t last){return a+b+c+d+e+f+g+x.a+last;}
int16_t aggregate_narrow(UPair x,int8_t a,int16_t b){return (int16_t)(x.a+x.b+a+b);}
