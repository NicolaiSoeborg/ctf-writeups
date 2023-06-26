# Google CTF 2023

URL: https://capturetheflag.withgoogle.com/

Team: Kalmarunionen

Place: 4 (of 676)

## Crypto: myTLS

> I implemented my own mTLS. It supports forward secrecy and it should be faster than yours!

Idea:
 * We connect using guest credentials
 * Then we do dir traversal to `../../app/server-ecdhkey.pem`
 * We fill the hmac buffer with known bytes (besides 1 byte) and bruteforce the hash recurrently
 * Using this we steal the server private key
 * The mTLS logic checks that the CA has signed client-cert (true)
 * Ephemeral keys are exchanged
 * A shared secret is generated using ECDH between `server_key` (which we stole) and `client_cert` (which we are impersonating)
 * A shared key is derived using above shared secret and ephemeral values which we know

Challenge files: <mytls.zip>

Solve script: <solve-mtls.py>

Thanks to Polly and the rest of the Kalmarunionen team for working together and solving this and a ton of challenges in Google CTF!

## Misc: Totally Not Brute Force

....
