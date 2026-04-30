OPTION DOTNAME

.CODE

PUBLIC MineLinuxToWin
PUBLIC MineLinuxToWinFS
PUBLIC MineWinToLinux
PUBLIC MineJump

; MineLinuxToWinFS
; Entry: RAX=win_fn, RDI=a1, RSI=a2, RDX=a3, RCX=a4, R8=a5, R9=a6
; Saves guest FS via rdfsbase, maps Linux->Win ABI, calls fn, restores FS.
; Stack at entry: [RSP] = return address (8 bytes from caller's call instruction)
; Pushes: rbp rbx r12 r13 r14 r15 = 6x8 = 48 bytes. Total RSP shift = 56.
; sub 40h = 64 bytes more. Grand total = 120 bytes.
; Entry RSP%16 = 8 (Linux caller had 16-aligned RSP before call).
; After 6 pushes: (8 - 48)%16 = 8. After sub 40h: (8 - 64)%16 = 8. Correct.
MineLinuxToWinFS PROC
    push    rbp
    mov     rbp, rsp
    push    rbx
    push    r12
    push    r13
    push    r14
    push    r15
    mov     r12, rax
    mov     r13, r8
    mov     r14, r9
    rdfsbase rbx
    sub     rsp, 40h
    mov     QWORD PTR [rsp+20h], r13
    mov     QWORD PTR [rsp+28h], r14
    mov     r8,  rdx
    mov     r9,  rcx
    mov     rcx, rdi
    mov     rdx, rsi
    call    r12
    wrfsbase rbx
    add     rsp, 40h
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbx
    pop     rbp
    ret
MineLinuxToWinFS ENDP

; MineLinuxToWin - legacy, no FS save
MineLinuxToWin PROC
    push    rbp
    mov     rbp, rsp
    push    r12
    push    r13
    push    r14
    push    r15
    mov     r12, rax
    mov     r13, r8
    mov     r14, r9
    sub     rsp, 40h
    mov     QWORD PTR [rsp+20h], r13
    mov     QWORD PTR [rsp+28h], r14
    mov     r8,  rdx
    mov     r9,  rcx
    mov     rcx, rdi
    mov     rdx, rsi
    call    r12
    add     rsp, 40h
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbp
    ret
MineLinuxToWin ENDP

; MineWinToLinux
; Windows: RCX=fn, RDX=a1, R8=a2, R9=a3
; Linux:   RAX=fn, RDI=a1, RSI=a2, RDX=a3
MineWinToLinux PROC
    mov     rax, rcx
    mov     rdi, rdx
    mov     rsi, r8
    mov     rdx, r9
    xor     rcx, rcx
    xor     r8,  r8
    xor     r9,  r9
    jmp     rax
MineWinToLinux ENDP

; MineJump
; RCX = guest entry VA
; RDX = guest RSP
; R8  = guest FS base (read by caller with _readfsbase_u64() AFTER all setup)
;
; Restores FS from R8 before jumping to guest entry.
; This is the authoritative FS restore - happens as the very last thing
; before guest code runs, so no Windows code can clobber it afterward.
MineJump PROC
    DB 0F3h, 041h, 00Fh, 0AEh, 0F0h
    mov     r11, rcx        ; entry point
    mov     rsp, rdx        ; guest RSP
    ; Restore guest FS - R8 holds the value read just before this call
    test    r8, r8
    jz      skip_fs
    wrfsbase r8
skip_fs:
    xor     rax, rax
    xor     rbx, rbx
    xor     rcx, rcx
    xor     rdx, rdx
    xor     rsi, rsi
    xor     rdi, rdi
    xor     rbp, rbp
    xor     r8,  r8
    xor     r9,  r9
    xor     r10, r10
    xor     r12, r12
    xor     r13, r13
    xor     r14, r14
    xor     r15, r15
    jmp     r11
MineJump ENDP

END