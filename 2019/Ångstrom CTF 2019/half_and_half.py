def xor(x, y):
	o = ''
	for a, b in zip(x, y):
		o += chr(ord(a) ^ ord(b))
	return o

# assert len(flag) % 2 == 0

# half = len(flag)//2
# milk = flag[:half]
# cream = flag[half:]
# assert xor(milk, cream) == '\x15\x02\x07\x12\x1e\x100\x01\t\n\x01"'


ct = '\x15\x02\x07\x12\x1e\x100\x01\t\n\x01"'

# words = []
# with open('.../wordlists/english-words.txt', 'r') as f:
# 	for line in f.readlines():
# 		if len(line[:-1]) == 6:
# 			words.append(line[:-1])

# This challenge has many solutions, so "guess" the correct:
for word in ['coffee']:
	cream = xor('actf{' + word + '_', ct)  # O
	milk = xor(cream, ct)
	flag = ''.join([milk, cream])
	print(flag)
