#include <cstdio>
#include <cstring>
#include <stdexcept>
static int cleanup=0;
struct Guard {~Guard(){cleanup+=7;}};
__attribute__((noinline)) static void fail() {Guard g;throw std::runtime_error("zvril-exception");}
int main() {
 int result=0;
 try {fail();return 91;}
 catch(const std::exception &e) {if(std::strcmp(e.what(),"zvril-exception"))return 92;result+=cleanup;}
 try {try {throw 17;} catch(...) {throw;}}
 catch(int value) {result+=value;}
 std::printf("exceptions:%d\n",result);
 return result==24?0:93;
}
