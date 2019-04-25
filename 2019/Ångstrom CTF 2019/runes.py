n = 99157116611790833573985267443453374677300242114595736901854871276546481648883
g = 99157116611790833573985267443453374677300242114595736901854871276546481648884
c = 2433283484328067719826123652791700922735828879195114568755579061061723786565164234075183183699826399799223318790711772573290060335232568738641793425546869

# We can factor n (or look it up on factordb.com)
# http://factordb.com/index.php?query=99157116611790833573985267443453374677300242114595736901854871276546481648883
p = 310013024566643256138761337388255591613
q = 319848228152346890121384041219876391791
assert n == p * q

# https://github.com/mikeivanov/paillier/blob/master/paillier/paillier.py
from gmpy2 import invert
class PrivateKey(object):
    def __init__(self, p, q, n):
        self.l = (p-1) * (q-1)
        self.m = invert(self.l, n)

class PublicKey(object):
    def __init__(self, n):
        self.n = n
        self.n_sq = n * n
        self.g = n + 1

def decrypt(priv, pub, cipher):
    x = pow(cipher, priv.l, pub.n_sq) - 1
    plain = ((x // pub.n) * priv.m) % pub.n
    return plain

pub = PublicKey(n)
priv = PrivateKey(p, q, n)
print(bytes.fromhex(hex(decrypt(priv, pub, c))[2:]))
