#include <pthread.h>
#include <stdio.h>

static long value;

static void *worker(void *argument) {
  value += (long)argument;
  return (void *)((long)argument * 2);
}

int main(void) {
  pthread_t thread;
  void *result = 0;
  if (pthread_create(&thread, 0, worker, (void *)21))
    return 91;
  if (pthread_join(thread, &result))
    return 92;
  printf("pthread:%ld:%ld\n", value, (long)result);
  return value == 21 && (long)result == 42 ? 0 : 93;
}
