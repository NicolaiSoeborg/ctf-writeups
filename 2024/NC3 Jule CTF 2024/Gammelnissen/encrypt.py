# pip install pycryptodome
from Crypto.Util.number import bytes_to_long, getPrime

with open("flag.txt", "rb") as f:
    m = bytes_to_long(f.read().strip())

p = getPrime(512)
q = p
n = p * q
e = 0x10001
ct = pow(m, e, n)

print(f"{n = }")
print(f"{ct = }")
