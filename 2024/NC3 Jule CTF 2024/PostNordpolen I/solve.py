from pwn import *

r = remote('10.10.106.188', 1337)
r.readuntil(b"> ")
r.sendline(b"1")

r.readuntil(b'\nDu har 1 brev klar til udlevering: ')
ENC_FLAG = bytes.fromhex(r.readuntil(b'\n')[:-1].decode())
r.readuntil(b"> ")

for _ in range(500):
    r.sendline(b"2")
    r.readuntil(b"Besked: ")
    r.sendline(b"A"*128)
    r.readuntil(b"Adresse: ")
    r.sendline(b"")
    r.readuntil(b"\nAfsendt til : ")
    ENC = bytes.fromhex(r.readline()[:-1].decode())
    r.readuntil(b"> ")

    pt = xor(xor(b'A'*128, ENC), ENC_FLAG)
    if b'NC3' in pt:
        print(pt)
        break
