; mine_abi.asm — Linux x86-64 to Windows x64 ABI adapter
;
; Linux call ABI:   arg1=RDI  arg2=RSI  arg3=RDX  arg4=RCX  arg5=R8  arg6=R9
; Windows call ABI: arg1=RCX  arg2=RDX  arg3=R8   arg4=R9   (shadow space on stack)
;
; Usage: set RAX = Windows function pointer, then CALL MineLinuxToWin
; It will reorder registers and call the Windows function.

.CODE

; MineLinuxToWin: RAX=win_fn, RDI/RSI/RDX/RCX/R8/R9 = Linux args
MineLinuxToWin PROC
    ; Step 1: save Linux args that will be overwritten during shuffle
    ;   Linux arg3 = RDX  (will be overwritten when we set Windows arg2=RDX)
    ;   Linux arg4 = RCX  (will be overwritten when we set Windows arg1=RCX)
    mov     r10, rdx        ; r10 = Linux arg3 (RDX)
    mov     r11, rcx        ; r11 = Linux arg4 (RCX) -- note: r11 is caller-saved

    ; Step 2: build Windows args (RAX still holds target fn)
    mov     rcx, rdi        ; Windows arg1 = Linux arg1
    mov     rdx, rsi        ; Windows arg2 = Linux arg2
    mov     r8,  r10        ; Windows arg3 = Linux arg3 (saved)
    mov     r9,  r11        ; Windows arg4 = Linux arg4 (saved)
    ; Linux arg5 (R8) and arg6 (R9) go on stack -- most stubs don't need them

    ; Step 3: shadow space + call
    sub     rsp, 20h
    call    rax
    add     rsp, 20h
    ret
MineLinuxToWin ENDP

END