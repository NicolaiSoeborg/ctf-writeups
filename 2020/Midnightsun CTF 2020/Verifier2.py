import hashlib
import binascii
from ecdsa import SigningKey, NIST192p
from ecdsa.numbertheory import inverse_mod
from telnetlib import Telnet

"""
    #r1 = int('b59af637923b31002a8b6b59df1c6ffcf3fa7fff0313a979', 16)
    #s1 = int('d93e8707910d21d098a261c5d188d3185db3144454a83f9a', 16)
    #m1 = 'h'
    #z1 = int(HASH(m1), 16)

    #r2 = int('b59af637923b31002a8b6b59df1c6ffcf3fa7fff0313a979', 16)
    #s2 = int('010ba2ab74b17ade095e2c7aa98438aea812c1e0419e8399', 16)
    #m2 = 'i'
    #z2 = int(HASH(m2), 16)

    #k = (((z1 - z2) % n) * inverse_mod(s1 - s2, n)) % n
    #print(f"k: {k}")

    #dA = ((((s1 * k) % n) - z1) * inverse_mod(r1, n)) % n
    #print(f"dA: {dA}")

    #priv = SigningKey.from_secret_exponent(dA, curve=curve)
    #sig = priv.sign(b'it works', k=1234)

    #print(binascii.hexlify(sig))
"""

def HASH(content):
    h = hashlib.sha1()
    h.update(content.encode())
    return h.hexdigest()


curve = NIST192p
n = curve.order


PROMPT = b'> '
with Telnet('verifier2-01.play.midnightsunctf.se', 31337) as tn:
    tn.read_until(PROMPT)
    
    tn.write(b'1\n')
    tn.read_until(b'message> ')
    tn.write(b'A\n')
    tn.read_until(b'Signature: ')
    sig1 = tn.read_until(b'\n')[:-1].decode()
    
    tn.read_until(PROMPT)

    tn.write(b'1\n')
    tn.read_until(b'message> ')
    tn.write(b'B\n')
    tn.read_until(b'Signature: ')
    sig2 = tn.read_until(b'\n')[:-1].decode()

    r1 = int(sig1[:48], 16)
    r2 = int(sig2[:48], 16)
    if r1 != r2:
        print("r isnt reused. Try again.")
        exit(1)

    s1 = int(sig1[48:], 16)
    s2 = int(sig2[48:], 16)
    z1 = int(HASH('A'), 16)
    z2 = int(HASH('B'), 16)

    k = (((z1 - z2) % n) * inverse_mod(s1 - s2, n)) % n
    print(f"k: {k}")

    dA = ((((s1 * k) % n) - z1) * inverse_mod(r1, n)) % n
    print(f"dA: {dA}")

    priv = SigningKey.from_secret_exponent(dA, curve=curve)
    sig = priv.sign(b'please_give_me_the_flag', k=1337)

    tn.read_until(PROMPT)

    tn.write(b'3\n')
    tn.read_until(b'signature> ')
    tn.write(binascii.hexlify(sig) + b'\n')
    tn.interact()

    # midnight{number_used_once_or_twice_or_more_e8595d72819c03bf07e534a9adf71e8a}
