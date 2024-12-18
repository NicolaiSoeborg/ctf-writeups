# Kryptoplikation

Vi får et krypto-system hvor hver byte i flaget er krypteret via `(bogstav * key) % P`

Så vi vil finde en løsning til `bogstav[0] * key  ==  ct[0]  (mod P)`

Det gør vi ved at omskrive til: `key = ct[0] * bogstav[0]^-1  (mod P)`

Når vi kender _key_ kan vi endnu engang finde den modular inverse mod P og gange med cipherteksten:

Så er løsningen: `bogstav[0] = ct[0] * key^-1  (mod P)`

## Solve

```python
ct = eval(open("krypteret.txt", "rt").read())
P = 13187894026947502600331395231459335882158393410614133036296342117478704820555154018132946245287063906492618556075499328589037764675831105264487871422591331

mod_inv = pow(ord('N'), -1, P)  # = N^-1 mod P
key = (ct[0] * mod_inv) % P
print(f'{key=}')
# key=4056284460887128042279888677032084765613378016096367436329224866578906500140582049600556365818223401072149740398210458751202059533973667401449003523637208

d = pow(key, -1, P)  # key^-1  (mod P)

for bogstav in ct:
    print(chr((bogstav * d) % P), end='')
print('')
```

## Flag

Flag: `NC3{https://www.cryptoisnotcryptocurrency.com/}`
