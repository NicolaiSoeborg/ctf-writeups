from pwn import *

def xor(a, b):
    return bytes([x ^ y for x, y in zip(a, b)])

r = remote('10.10.164.170', 1337)
r.readuntil(b"> ")

letter = 1
while letter <= 1000:
    if letter % 64 == 0: print(f"{letter=}")
    r.sendline(b"1")
    r.readuntil(b'\nDu har 1 brev klar til udlevering: ')
    ENC_FLAG = bytes.fromhex(r.readuntil(b'\n')[:-1].decode())
    r.readuntil(b"> ")
    letter += 1

print(f"{letter=}")

ct0 = ENC_FLAG[0:16]
ct1 = ENC_FLAG[16:32]
ct2 = ENC_FLAG[32:48]
ct3 = ENC_FLAG[48:64]
ct4 = ENC_FLAG[64:80]

def ENC(msg: bytes) -> bytes:
    """ returns result of ENC(key, msg) """
    global letter
    r.sendline(b"2")
    r.readuntil(b"Besked: ")
    r.sendline(b'AAAA')
    r.readuntil(b"Adresse: ")
    r.sendline(b"")
    r.readuntil(b"IV: ")

    assert len(msg) == 16, msg
    r.sendline(msg.hex().encode())

    r.readuntil(b"afsendt til : ")
    CRIB = f"[BREV {letter}] AAAA".encode()
    result = xor(CRIB, bytes.fromhex(r.readuntil(b'\n')[:-1].decode()))

    r.readuntil(b"> ")
    letter += 1
    return result


ks0 = xor(ct0, b'[BREV 1000] NC3{')

ks1 = ENC(ks0)
pt1 = xor(ct1, ks1)

ks2 = ENC(ks1)
pt2 = xor(ct2, ks2)

ks3 = ENC(ks2)
pt3 = xor(ct3, ks3)

ks4 = ENC(ks3)
pt4 = xor(ct4, ks4)

print(b'NC3{' + pt1 + pt2 + pt3 + pt4)
