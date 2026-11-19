#include "zvril/elf/image.h"
#include <cstddef>
#include <cstdint>
#include <vector>
extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data,std::size_t size){
  if(size>4*1024*1024)return 0;
  zvril::Limits limits;limits.max_bytes=4*1024*1024;limits.max_entries=10000;limits.max_string_bytes=1024*1024;
  try{(void)zvril::parse(std::vector<std::uint8_t>(data,data+size),limits);}catch(const zvril::Error&){}
  return 0;
}
