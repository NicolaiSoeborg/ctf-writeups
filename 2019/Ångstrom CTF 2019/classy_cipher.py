# from secret import flag, shift

def encrypt(d, s):
	e = ''
	for c in d:
		e += chr((ord(c)+s) % 0xff)
	return e

assert encrypt(flag, shift) == ':<M?TLH8<A:KFBG@V'

# for s in range(255):
# 	if encrypt("ACTF{???????????}", s).startswith(":<M?"):
# 		print(s)
# 248

def decrypt(e, s = 248):
	d = ''
	for c in e:
		d += chr((ord(c)-s) % 0xFF)
	return d

print(decrypt(':<M?TLH8<A:KFBG@V'))  # actf{so_charming}
