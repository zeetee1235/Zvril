#include <stdint.h>
uint64_t demo_add(uint64_t a,uint64_t b){return a+b;}
uint64_t demo_sum(const unsigned char* p,uint64_t n){uint64_t sum=0;for(uint64_t i=0;i<n;i++)sum+=p[i];return sum;}
double demo_float(double a,double b){return a+b;}
