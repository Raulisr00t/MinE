.CODE
 
MineJump PROC
    mov  rsp, rdx       
    xor  rbp, rbp       ; RBP = 0  (Linux ABI requirement at _start)
    xor  rbx, rbx
    xor  r12, r12
    xor  r13, r13
    xor  r14, r14
    xor  r15, r15
    xor  rsi, rsi
    xor  rdi, rdi
    xor  rdx, rdx
    xor  rax, rax
    jmp  rcx            ; jump to entry — no CALL, no return address pushed
MineJump ENDP
 
END
 
