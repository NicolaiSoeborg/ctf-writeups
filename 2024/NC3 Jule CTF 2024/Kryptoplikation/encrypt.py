from random import randint

# 512-bit prime
P = 13187894026947502600331395231459335882158393410614133036296342117478704820555154018132946245287063906492618556075499328589037764675831105264487871422591331

def encrypt(pt, key):
    ct = []
    for c in pt:
        ct.append((c * key) % P)
    return ct

with open("flag.txt", "rb") as f:
    flag = f.read().strip()

key = randint(2**510, 2**511)
ct = encrypt(flag, key)
print(ct)
