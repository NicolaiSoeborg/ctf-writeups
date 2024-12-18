#!/usr/bin/env python3

from Crypto.Cipher import AES

# Delt nøgle og kodebog, der aldrig løber tør!
from secret import FLAG, KEY, CODEBOOK


def encrypt(pt, key, iv=None):
    cipher = AES.new(key, mode=AES.MODE_OFB, iv=iv)
    return cipher.encrypt(pt)


def input_hex(prompt, length=16):
    try:
        hx = bytes.fromhex(input(prompt))
        if len(hx) != length:
            raise ValueError(f"Input skal være {length} bytes")
    except ValueError as e:
        print(e)
        return

    return hx


def main():
    print("********************************")
    print("*  PostNordpolens Postcentral  *")
    print("*            Uge 48            *")
    print("********************************")

    letter = 1

    while True:
        print()
        print("1. Afhent breve til udlevering")
        print("2. Krypter og afsend besked")
        print("3. Afslut arbejdsdag")
        choice = input("> ")
        print()

        if choice == "1":
            iv = CODEBOOK.next()
            ct = encrypt(f"[BREV {letter}] {FLAG}".encode(), KEY, iv)
            print(f"Du har 1 brev klar til udlevering: {ct.hex()}")

        elif choice == "2":
            msg = input("Besked: ")
            addr = input("Adresse: ")

            if (iv := input_hex("IV: ")) is None:
                continue

            ct = encrypt(f"[BREV {letter}] {msg}".encode(), KEY, iv)
            print(f"\nBREV {letter} afsendt til {addr}: {ct.hex()}")

        elif choice == "3":
            print("Tak for i dag, husk at registrere dine timer!")
            break

        else:
            print("Ugyldigt valg :(")
            continue

        letter += 1


if __name__ == "__main__":
    main()
