#include <stdio.h>
#include <string.h>
#include <unistd.h>

int false__stack_chk_fail(int a) { return a; }

int main(int argc, char** argv) {
  char buf[16];
  int (*op)(int) = false__stack_chk_fail;

  if (argc>1)
    strcpy(buf,argv[1]);
  else
    strcpy(buf,"test");

  printf("%s,%d\n", buf, op(42));

  sleep(2);
  return 0;
}
