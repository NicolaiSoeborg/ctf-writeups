from pwn import *

import string
import hashlib
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import hmac
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


with open('server-ecdhcert.pem', 'rb') as f:
    their_cert = x509.load_pem_x509_certificate(f.read())
with open('admin-ecdhcert.pem', 'rb') as f:
    admin_cert = x509.load_pem_x509_certificate(f.read())
with open('guest-ecdhcert.pem', 'rb') as f:
    my_cert = f.read()
with open('guest-ecdhkey.pem', 'rb') as f:
    my_key = serialization.load_pem_private_key(f.read(), None, default_backend())

def write_encrypted(message, iv, key):
    cipher = Cipher(algorithms.AES(key), modes.CBC(binascii.unhexlify(iv)))
    encryptor = cipher.encryptor()
    payload = encryptor.update(message + b'\x00' * (16 - len(message) % 16)) + encryptor.finalize()
    return binascii.hexlify(payload)

def read_encrypted(message, iv, key):
    cipher = Cipher(algorithms.AES(key), modes.CBC(binascii.unhexlify(iv)))
    decryptor = cipher.decryptor()
    return decryptor.update(message).strip(b'\x00')

def connect(client_cert, client_key):
    r = remote('mytls.2023.ctfcompetition.com', 1337)

    r.readline()  # == proof-of-work: disabled ==\

    r.recvuntil(b'Please provide the client certificate in PEM format:\n')
    r.sendline(client_cert)

    r.recvuntil(b'Please provide the ephemeral client random:\n')
    client_ephemeral_random = b'A'*32
    r.sendline(client_ephemeral_random)

    r.recvuntil(b'Please provide the ephemeral client key:\n')
    client_ephemeral_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    client_ephemeral_public_bytes = client_ephemeral_key.public_key().public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
    r.sendline(client_ephemeral_public_bytes)

    r.recvuntil(b'Server ephemeral random:\n')
    server_ephemeral_random = r.recvline().strip()  # b'4f8d86d98ec619c243cdd08b0a64daeb\n#

    r.recvuntil(b'Server ephemeral key:\n')
    server_ephemeral_pubkey = r.recvline()  # b'-----BEGIN PUBLIC KEY-----\n'
    server_ephemeral_pubkey += r.recvline() # b'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEh7hddajKzMGljHhOc+0xWt9zMCe4\n'
    server_ephemeral_pubkey += r.recvline() # b'ieI9ihLH9lBn5KtICmSQ4fbhJaaRyqYK/qGQICedtB1uxKnJXPlvyAnFqg==\n'
    server_ephemeral_pubkey += r.recvline() # b'-----END PUBLIC KEY-----\n'
    server_ephemeral_pubkey = serialization.load_pem_public_key(server_ephemeral_pubkey)
    r.recvline()  # newline

    ephemeral_secret = client_ephemeral_key.exchange(ec.ECDH(), server_ephemeral_pubkey)
    client_secret = client_key.exchange(ec.ECDH(), their_cert.public_key())

    derived_key = HKDF(algorithm=hashes.SHA256(),
                       length=32,
                       salt=b'SaltyMcSaltFace',
                       info=b'mytls').derive(ephemeral_secret +
                                             client_secret +
                                             client_ephemeral_random +
                                             server_ephemeral_random)

    r.recvuntil(b'Please provide the client HMAC:\n')
    client_hmac = hmac.HMAC(derived_key, hashes.SHA256())
    client_hmac.update(b'client myTLS successful!')
    r.sendline(client_hmac.finalize().hex().encode())

    r.recvuntil(b'Server HMAC:\n')
    server_hmac = r.readline().strip()

    # b'Hello guest!'
    message = binascii.unhexlify(r.readline().strip())
    message = read_encrypted(message, server_ephemeral_random, derived_key)

    def oracle(storage_slot: bytes, secret_to_write: bytes):
        # b'Welcome to our write-only file storage!\n\nSelect the storage slot [0-9]:'
        message = binascii.unhexlify(r.readline().strip())
        read_encrypted(message, server_ephemeral_random, derived_key)

        r.sendline(write_encrypted(storage_slot, server_ephemeral_random, derived_key))

        # b'Gimme your secrets:'
        message = binascii.unhexlify(r.readline().strip())
        read_encrypted(message, server_ephemeral_random, derived_key)

        r.sendline(write_encrypted(secret_to_write, server_ephemeral_random, derived_key))

        # b'Saved! Previous secret reference: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
        message = binascii.unhexlify(r.readline().strip())
        recieved = read_encrypted(message, server_ephemeral_random, derived_key)
        return bytes.fromhex(recieved[-64:].decode())

    return oracle



def win(server_private):
    r = remote('mytls.2023.ctfcompetition.com', 1337)
    r.readline()  # == proof-of-work: disabled ==

    r.recvuntil(b'Please provide the client certificate in PEM format:\n')
    r.sendline(admin_cert.public_bytes(encoding=serialization.Encoding.PEM))

    r.recvuntil(b'Please provide the ephemeral client random:\n')
    client_ephemeral_random = b'A'*32
    r.sendline(client_ephemeral_random)

    r.recvuntil(b'Please provide the ephemeral client key:\n')
    client_ephemeral_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    client_ephemeral_public_bytes = client_ephemeral_key.public_key().public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
    r.sendline(client_ephemeral_public_bytes)

    r.recvuntil(b'Server ephemeral random:\n')
    server_ephemeral_random = r.recvline().strip()  # b'4f8d86d98ec619c243cdd08b0a64daeb\n#

    r.recvuntil(b'Server ephemeral key:\n')
    server_ephemeral_pubkey = r.recvline()  # b'-----BEGIN PUBLIC KEY-----\n'
    server_ephemeral_pubkey += r.recvline() # b'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEh7hddajKzMGljHhOc+0xWt9zMCe4\n'
    server_ephemeral_pubkey += r.recvline() # b'ieI9ihLH9lBn5KtICmSQ4fbhJaaRyqYK/qGQICedtB1uxKnJXPlvyAnFqg==\n'
    server_ephemeral_pubkey += r.recvline() # b'-----END PUBLIC KEY-----\n'
    server_ephemeral_pubkey = serialization.load_pem_public_key(server_ephemeral_pubkey)
    r.recvline()  # newline

    ephemeral_secret = client_ephemeral_key.exchange(ec.ECDH(), server_ephemeral_pubkey)
    client_secret = server_private.exchange(ec.ECDH(), admin_cert.public_key()) # hax!

    derived_key = HKDF(algorithm=hashes.SHA256(),
                       length=32,
                       salt=b'SaltyMcSaltFace',
                       info=b'mytls').derive(ephemeral_secret +
                                             client_secret +
                                             client_ephemeral_random +
                                             server_ephemeral_random)

    r.recvuntil(b'Please provide the client HMAC:\n')
    client_hmac = hmac.HMAC(derived_key, hashes.SHA256())
    client_hmac.update(b'client myTLS successful!')
    r.sendline(client_hmac.finalize().hex().encode())

    r.recvuntil(b'Server HMAC:\n')
    server_hmac = r.readline().strip()

    # b'Hello guest! Flag: ...'
    message = binascii.unhexlify(r.readline().strip())
    message = read_encrypted(message, server_ephemeral_random, derived_key)
    print(message)



def hash(msg):
    h = hashlib.new('sha256')
    h.update(msg)
    return h.digest()

def brute_byte(prefix, recovered, goal):
    for c in string.printable:
        guess = hash(prefix + c.encode() + recovered)
        if guess == goal:
            return c.encode()
    return prefix + recovered


oracle = connect(my_cert, my_key)

length = 241
# while True:
#     oracle(b'../../app/server-ecdhkey.pem', b"A"*length)
#     remote_hash = oracle(b'../../app/server-ecdhkey.pem', b"")
#     local_hash = hash(b"A"*length)
#     if local_hash == remote_hash:
#         break
#     length += 1

# recovered = b""
# for _ in range(length):
#     oracle = connect(my_cert, my_key)
#     prefix = b"A" * (length - 1 - len(recovered))
#     oracle(b'../../app/server-ecdhkey.pem', prefix)
#     goal = oracle(b'../../app/server-ecdhkey.pem', b"")
# 
#     recovered = brute_byte(prefix, recovered, goal) + recovered
#     print(recovered)
recovered = b'-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgodXSjxjUm89w/y6m\nhRc9c7aOOYIgy5m4K++AXeErUKahRANCAARNWVuTXe/JBFanevD4MMlIDyZ8xXKz\nnyUf63kGe9RBfFPek03cHJhEM5Fhe/1hHS2Jz2+R9zZWHd5gVYWFf2uC\n-----END PRIVATE KEY-----\n'


server_private = serialization.load_pem_private_key(recovered, None, default_backend())


print("Winning")
win(server_private)
# Hello admin! CTF{KeyC0mpromiseAll0w51mpersonation}\n
