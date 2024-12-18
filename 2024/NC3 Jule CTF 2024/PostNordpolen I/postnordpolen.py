#!/usr/bin/env python3

from Crypto.Cipher import AES

# Ugens delte nøgle og kodebog med engangskoder
from secret import FLAG, KEY, CODEBOOK


def encrypt(pt, key):
    nonce = CODEBOOK.next()
    cipher = AES.new(key, mode=AES.MODE_CTR, nonce=nonce)
    return nonce + cipher.encrypt(pt)


def main():
    print("********************************")
    print("*  PostNordpolens Postcentral  *")
    print("*            Uge 47            *")
    print("********************************")

    enc_flag = encrypt(FLAG, KEY)

    while True:
        print()
        print("1. Afhent breve til udlevering")
        print("2. Krypter og afsend besked")
        print("3. Afslut arbejdsdag")
        choice = input("> ")
        print()

        if choice == "1":
            print(f"Du har 1 brev klar til udlevering: {enc_flag.hex()}")

        elif choice == "2":
            msg = input("Besked: ")
            addr = input("Adresse: ")
            ct = encrypt(msg.encode(), KEY)
            print(f"\nAfsendt til {addr}: {ct.hex()}")

        elif choice == "3":
            print("Tak for i dag, husk at registrere dine timer!")
            break

        else:
            print("Ugyldigt valg :(")


if __name__ == "__main__":
    main()
