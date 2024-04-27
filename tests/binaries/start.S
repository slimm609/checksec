.globl _start
_start:call main
       movl $1, %eax
       xorl %ebx, %ebx
       int $0x80
