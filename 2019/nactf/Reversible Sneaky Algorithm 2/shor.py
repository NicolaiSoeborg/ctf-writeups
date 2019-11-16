from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_OAEP
key = RSA.generate(1024)
public_key = key.publickey().export_key()
file_out = open("oligarchy.pem", "wb")
file_out.write(public_key)
flag = #REDACTED
cipher = PKCS1_OAEP.new(key)
ciphertext = cipher.encrypt(flag)
c = int(ciphertext.hex(), 16)
print ("c:", c)
