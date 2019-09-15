import binascii
from string import printable
from itertools import permutations
from Crypto.Cipher import DES

IV = '13371337'

keys = ["0101010101010101", "FEFEFEFEFEFEFEFE",
"E0E0E0E0F1F1F1F1", "1F1F1F1F0E0E0E0E",
"0000000000000000", "FFFFFFFFFFFFFFFF",
"E1E1E1E1F0F0F0F0", "1E1E1E1E0F0F0F0F"] + [
"011F011F010E010E", "1F011F010E010E01",
"01E001E001F101F1", "E001E001F101F101",
"01FE01FE01FE01FE", "FE01FE01FE01FE01",
"1FE01FE00EF10EF1", "E01FE01FF10EF10E",
"1FFE1FFE0EFE0EFE", "FE1FFE1FFE0EFE0E",
"E0FEE0FEF1FEF1FE", "FEE0FEE0FEF1FEF1"] + [
"01011F1F01010E0E", "1F1F01010E0E0101", "E0E01F1FF1F10E0E",
"0101E0E00101F1F1", "1F1FE0E00E0EF1F1", "E0E0FEFEF1F1FEFE", "0101FEFE0101FEFE", "1F1FFEFE0E0EFEFE",
"E0FE011FF1FE010E", "011F1F01010E0E01", "1FE001FE0EF101FE", "E0FE1F01F1FE0E01", "011FE0FE010EF1FE",
"1FE0E01F0EF1F10E", "E0FEFEE0F1FEFEF1", "011FFEE0010EFEF1", "1FE0FE010EF1FE01", "FE0101FEFE0101FE",
"01E01FFE01F10EFE", "1FFE01E00EFE01F1", "FE011FE0FE010EF1", "FE01E01FFE01F10E", "1FFEE0010EFEF101",
"FE1F01E0FE0E01F1", "01E0E00101F1F101", "1FFEFE1F0EFEFE0E", "FE1FE001FE0EF101", "01E0FE1F01F1FE0E",
"E00101E0F10101F1", "FE1F1FFEFE0E0EFE", "01FE1FE001FE0EF1", "E0011FFEF1010EFE", "FEE0011FFEF1010E",
"01FEE01F01FEF10E", "E001FE1FF101FE0E", "FEE01F01FEF10E01", "01FEFE0101FEFE01", "E01F01FEF10E01FE",
"FEE0E0FEFEF1F1FE", "1F01011F0E01010E", "E01F1FE0F10E0EF1", "FEFE0101FEFE0101", "1F01E0FE0E01F1FE",
"E01FFE01F10EFE01", "FEFE1F1FFEFE0E0E", "1F01FEE00E01FEF1", "E0E00101F1F10101", "FEFEE0E0FEFEF1F1"]


def unduck(aChr):
    assert aChr != 10, 'duck returns [0..9, 11..16]'
    if aChr > 10:
        return aChr - 1
    return aChr

def unpadInput(input):
    while input[-1] == '_':
        input = input[:-1]
    return input

def decodeText(encodedText, offset = 9133337):
    assert type(encodedText) == str
    assert len(encodedText) % 8 == 0
    nibbleLen = 8  # getNibbleLength(offset)
    output = ""
    for i in range(0, len(encodedText), nibbleLen):
        encodedByte = encodedText[i : i + nibbleLen]  # 8-byte-long
        c = hex(unduck(int(encodedByte) - offset))[2:]
        assert len(c) == 1
        output += c
    return output

def desDecrypt(input, key):
    cipher = DES.new(key, DES.MODE_OFB, IV)
    msg = cipher.decrypt(input)
    return msg

with open('FLAG.enc', 'r') as f:
    flag_encrypted = f.read()
    flag_encrypted = decodeText(flag_encrypted, 9133337)
    flag_encrypted = bytes.fromhex(flag_encrypted)
    # flag_encrypted should now be the "raw" double DES encrypted flag
    # but looking at the output, it doesn't look like raw DES output... ???

    # decode the bytes to "ascii-hex" and then the ascii-hex to raw bytes:
    flag_encrypted = binascii.unhexlify(flag_encrypted.decode())
    # now the flag looks like "raw DES output"

for k1, k2 in permutations(keys, 2):
    key1 = binascii.unhexlify(k1)
    key2 = binascii.unhexlify(k2)

    a = desDecrypt(flag_encrypted, key2)
    b = desDecrypt(a, key1)
    if b'flag' in b:
        print(b)

# flag{~tak3_0n3_N!bbI3_@t_@_t!m3~}
