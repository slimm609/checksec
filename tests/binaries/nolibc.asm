section .data
        msg db 'Hello, World!', 0ah ;note the newline (Line Feed-LF) at the end (hex:0ah; decimal:10)
        len equ $ - msg             ;calculate the length of the message
        delay dq 2, 100000000       ;define delay with Timespec structure members tv_sec, tv_nsec (qwords, 64-bit integer values)

section .text
        global _start               ;must be declared for linker (ld)

_start:                             ;tells linker entry point
        mov rax, 1                  ;system call for write (sys_write 1)
        mov rdi, 1                  ;file descriptor (1 is stdout)
        mov rsi, msg                ;address of string to output
        mov rdx, len                ;message length
        syscall                     ;invoke operating system to do the write

        mov rax, 35                 ;system call for nanosleep (sys_nanosleep 35)
        mov rdi, delay              ;load the pointer to our delay
        mov rsi, 0                  ;exit code 0
        syscall                     ;invoke operating system to do the delay

        mov rax, 60                 ;system call for exit (sys_exit 60)
        xor rdi, rdi                ;exit code 0
        syscall                     ;invoke operating system to exit
