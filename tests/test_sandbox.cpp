#include "zvril/verify.h"
#include <cassert>
#include <cerrno>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

int main(int argc,char** argv){
  if(!zvril::sandbox_available())return 77;
  assert(argc==2);
  zvril::restrict_worker(argv[1],2000);
  int own=open(argv[1],O_RDONLY);assert(own>=0);close(own);
  assert(open("/etc/passwd",O_RDONLY)<0);
  assert(open("/tmp/zvril-sandbox-must-not-create",O_WRONLY|O_CREAT,0600)<0);
  assert(socket(AF_INET,SOCK_STREAM,0)<0&&errno==EPERM);
  assert(syscall(SYS_fork)<0&&errno==EPERM);
  assert(syscall(SYS_execve,"/bin/true",nullptr,nullptr)<0&&errno==EPERM);
  return 0;
}
