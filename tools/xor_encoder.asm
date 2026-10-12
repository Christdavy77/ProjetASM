BITS 64
global _start

section .data
    input_file  db "payload/reverse_shell_core.bin", 0
    output_file db "payload/reverse_shell_core_xor.bin", 0

section .bss
    buffer resb 4096        ; tampon de lecture/écriture

section .text
_start:
    ; === Ouvrir le fichier source en lecture (O_RDONLY = 0) ===
    mov     rax, 2              ; syscall open
    lea     rdi, [input_file]
    xor     rsi, rsi            ; O_RDONLY = 0
    xor     rdx, rdx
    syscall
    mov     r12, rax            ; r12 = fd_in

    ; === Créer le fichier de sortie (O_WRONLY|O_CREAT|O_TRUNC = 0x241) ===
    mov     rax, 2              ; syscall open
    lea     rdi, [output_file]
    mov     rsi, 0x241          ; O_WRONLY | O_CREAT | O_TRUNC
    mov     rdx, 420            ; permissions 0644 en decimal
    syscall
    mov     r13, rax            ; r13 = fd_out

boucle_lecture:
    ; === Lire un bloc de 4096 bytes ===
    mov     rax, 0              ; syscall read
    mov     rdi, r12            ; fd_in
    lea     rsi, [buffer]
    mov     rdx, 4096
    syscall

    test    rax, rax
    jle     fermer              ; 0 = fin de fichier

    mov     r14, rax            ; r14 = nombre de bytes lus

    ; === XOR chaque byte avec 0x41 ===
    lea     rsi, [buffer]
    mov     rcx, r14
boucle_xor:
    xor     byte [rsi], 0x41
    inc     rsi
    loop    boucle_xor

    ; === Écrire le bloc XOR-encodé ===
    mov     rax, 1              ; syscall write
    mov     rdi, r13            ; fd_out
    lea     rsi, [buffer]
    mov     rdx, r14
    syscall

    jmp     boucle_lecture

fermer:
    ; === Fermer les fichiers ===
    mov     rax, 3              ; syscall close
    mov     rdi, r12
    syscall

    mov     rax, 3
    mov     rdi, r13
    syscall

    ; === exit(0) ===
    xor     rdi, rdi
    mov     rax, 60
    syscall