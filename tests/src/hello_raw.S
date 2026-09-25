/* No libc at all: exercises the loader, stack and raw syscall trap. */
    .globl _start
    .text
_start:
    mov $1, %eax            /* write */
    mov $1, %edi
    lea msg(%rip), %rsi
    mov $len, %edx
    syscall
    mov $60, %eax           /* exit(argc) */
    mov (%rsp), %rdi
    syscall
    .section .rodata
msg: .ascii "hello from raw syscalls\n"
    .set len, . - msg
