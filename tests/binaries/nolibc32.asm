section .data
        msg db "Hello, world!", 0xa ;note the newline (Line Feed-LF) at the end (hex:0ah; decimal:10)
        len equ $ - msg             ;calculate the length of the message
        delay dd 2, 100000000       ;define delay with Timespec structure members tv_sec, tv_nsec (dwords, 32-bit integer values)

section .text
        global _start               ;must be declared for linker (ld)

_start:                             ;tells linker entry point
        mov eax,4                   ;system call for write (sys_write 4)
        mov ebx,1                   ;file descriptor (1 is stdout)
        mov ecx,msg                 ;address of string to output
        mov edx,len                 ;message length
        int 0x80                    ;invoke operating system to do the write

        mov eax, 162                ;system call for nanosleep (sys_nanosleep 162)
        mov ebx, delay              ;load the pointer to our delay
        mov ecx, 0                  ;exit code 0
        int 0x80                    ;invoke operating system to do the delay

        mov eax,1                   ;system call for exit (sys_exit 1)
        xor ebx, ebx                ;exit code 0
        int 0x80                    ;invoke operating system to exit
