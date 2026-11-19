#include <stdint.h>
#define HELPER(n) __attribute__((noinline,visibility("hidden"))) uint64_t switch_helper_##n(uint64_t x){return (x+n)*((n)*2+3);}
HELPER(0) HELPER(1) HELPER(2) HELPER(3) HELPER(4) HELPER(5) HELPER(6) HELPER(7)
uint64_t program_switch(unsigned index,uint64_t value){
  switch(index){
  case 0:return switch_helper_0(value);case 1:return switch_helper_1(value);
  case 2:return switch_helper_2(value);case 3:return switch_helper_3(value);
  case 4:return switch_helper_4(value);case 5:return switch_helper_5(value);
  case 6:return switch_helper_6(value);case 7:return switch_helper_7(value);
  default:return 999;
  }
}
