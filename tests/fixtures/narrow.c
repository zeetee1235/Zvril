#include <stdarg.h>
#include <stdint.h>
uint8_t narrow_u8(uint8_t x){return x^0x5a;}
int8_t narrow_i8(int64_t x){return (int8_t)x;}
uint16_t narrow_u16(uint16_t x){return x^0x5aa5;}
int16_t narrow_i16(int64_t x){return (int16_t)x;}
int64_t narrow_args(int8_t a,int16_t b,uint8_t c,uint16_t d){return (int64_t)a*1000000+(int64_t)b*1000+c*100+d;}
int64_t narrow_stack(int8_t a,int16_t b,uint8_t c,uint16_t d,int8_t e,int16_t f,int8_t g,int16_t h,uint16_t i){return (int64_t)a+b+c+d+e+f+g+h+i;}
int64_t narrow_variadic(uint8_t n,...){va_list args;va_start(args,n);int64_t sum=0;for(unsigned i=0;i<n;i++)sum+=va_arg(args,int);va_end(args);return sum;}
