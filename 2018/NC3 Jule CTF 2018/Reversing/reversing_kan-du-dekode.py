#!/usr/bin/env python3
from base64 import b64decode

krypteret_indhold = b64decode('Vg0TGwVSbVkQAQEQUG5WBxVIYysIAQZODgUPFg8RRnxVDhVbeCgJCAkBHkUCBFNMKSZBFQEMBQsOCw4YDjMGAy0FCg0LAA86Fx4ZMwUcBgsWFFIGGFttSgseWW9ODBdXZ25WSgUZDRVZb05BDR0DCFRv')

# Lets guess it will decrypt to something beginning with '<html>':
password = ''.join(chr(krypteret_indhold[i] ^ ord(c)) for i, c in enumerate('<html>'))
print(f'Does this look like the beginning of the password: {password} ?')  # "jegvil" <-- seems right

# Guess password length (i.e. when will the current password repeat):
print('\nPassword len | Decrypted block')
for pass_len in range(len(password)-1, 40):
    # We cound decode multiple blocks, but a single should be fine to find repeats:
    decrypted_block = ''.join(chr(krypteret_indhold[pass_len+i] ^ ord(password[i])) for i in range(len(password)))
    print(pass_len, decrypted_block)

# Both 14 and 28 match, so take the shortest len:
REAL_PASS_LEN = 14

# Pad password so we can try decrypting:
NULL = '\x00'
password += NULL * (REAL_PASS_LEN - len(password))

# This (crappy) code allows you to guess the password one char at a time:
while password[-1] == '\x00':
    print(f'\nYou need to guess the remaining {password.count(NULL)} chars of the password.')
    guess = input(f'Password (type guess + [enter]): {password}')

    new_password = password[:password.index(NULL)] + guess
    new_password += NULL * (REAL_PASS_LEN - len(new_password))
    print(''.join(chr(c ^ ord(new_password[i % len(new_password)])) for i, c in enumerate(krypteret_indhold)))
    if input('Looks good? (y/n): ').lower() in ['y', 'yes']:
        password = new_password
    print('-' * 120)

# Flag: NC3{dekodning_af_kodede_php_bytes}
