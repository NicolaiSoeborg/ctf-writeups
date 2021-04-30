# Personal Proxy

Challenge description:

> To access the internet I setup a personal socks proxy using open-source software, and a tunnel with strong password is used to make it secure.
> Here is my proxy config file and a network traffic captured when uploading my secret file to personal storage center. I do not believe anyone could read those encrypted bytes.
> Proxy server hosted at 13.52.88.46:50000

Looking at [the challenge](./challenge.zip) we get two files;

 * `capture.pcap`
 * `server-docker.tar.gz`

## Server setup

Lets start by looking at the server configuration, it contains a `danted.conf` that setup a [dante](https://www.inet.no/dante/) SOCKS proxy on port 61080.
Note that dante has no authentication, but the port is not exposed by docker, so we can't reach it from the outside.

What is exposed is [shadowtunnel v1.7](https://github.com/snail007/shadowtunnel/releases/download/v1.7) running on port 50000 with parameters:
`./shadowtunnel -e -f 127.0.0.1:61080 -l :50000 -p $PASSWORD` and a *unknown strong password*.

The parameters:
 * `-e`: inbound connection is encrypted
 * `-f 127.0.0.1:61080`: forward address
 * `-l :50000`: local listen address
 * `-p $PASSWORD`: password for encrypt/decrypt (default "shadowtunnel")

## Network dump

The capture starts with a standard TCP handshake between the client (port 33734) and the server (port 50000):

```
127.0.0.1:33734 -> SYN     -> 127.0.0.1:50000
127.0.0.1:50000 -> SYN-ACK -> 127.0.0.1:33734
127.0.0.1:33734 -> ACK     -> 127.0.0.1:50000
```

Then the client sends 4 bytes, receives 2 bytes, sends 10 bytes and receives 10 bytes, finally the client sends a lot of bytes.

```diff
+78 05 cb a2                                x...
-78 07                                      x.
+09 2b 82 ce eb 89 06 0a  e0 6c             .+...... .l
-ce a3 0c 2b 2e da 2b 23  9c f1             ...+..+# ..
+[many bytes]
```

## The attack

We now understand the setup:

[mermaid diagram]

I.e. shadowtunnel decrypts incoming traffic and forwards it to danted, which parses the SOCKS traffic and forwards the decrypted traffic.
We have a network dump for a successful 

### Idea 1: Crack the password

Maybe the password is not really strong, or the default password, or in the RockYou wordlist, or ...

To try a simple bruteforce attack, we first need to figure out how shadowtunnel works.
The code is fairly readable, but it has been changed a bit since v1.7 (which however is the newest release) - and the git history is a mess!

We find something like the following:

```go
encryptconn.NewCipher(method, password).NewConn(c, method, password)
```

If no encryption method is specified it will default to aes-192-cfb. That is AES in [cipher feedback mode](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#CFB).

![CFB mode diagram](https://upload.wikimedia.org/wikipedia/commons/9/9d/CFB_encryption.svg)

But what about the IV? And how is `$PASSWORD` turned into the AES key?
Prepare for some wonky crypto:

```go
func md5sum(d []byte) []byte {
	h := md5.New()
	h.Write(d)
	return h.Sum(nil)
}

func evpBytesToKey(password string, keyLen int) (key []byte) {
	const md5Len = 16
	cnt := (keyLen-1)/md5Len + 1
	m := make([]byte, cnt*md5Len)
	copy(m, md5sum([]byte(password)))

	// Repeatedly call md5 until bytes generated is enough.
	// Each call to md5 uses data: prev md5 sum + password.
	d := make([]byte, md5Len+len(password))
	start := 0
	for i := 1; i < cnt; i++ {
		start += md5Len
		copy(d, m[start-md5Len:start])
		copy(d[md5Len:], password)
		copy(m[start:], md5sum(d))
	}
	return m[:keyLen]
}
```

aes-192-cfb has `keyLen = 24` and `ivLen = 16`, so the above is essential:

```python
from hashlib import md5, sha256

def md5sum(x): return md5(x).digest()

def evpBytesToKey(password):
    step1 = md5sum(password)
    step2 = md5sum(step1 + password)
    return (step1 + step2)[:24]

key = evpBytesToKey("$PASSWORD")
iv = sha256(key)[:16]
```

That is clearly not a good way to derive a key, TODO MERE HER
But how do we attack it? -> we need to know the pt data

### Predict plaintext data

We know dante is a SOCKS proxy, so lets do a quick local test:

```bash
ncat -l -p 50001 | xxd &
curl -s --socks5 127.0.0.1:50001 http://example.com/ >/dev/null
^C
00000000: 0502 0001                                ....
```

Looking at [RFC 1928: SOCKS Protocol Version 5](https://tools.ietf.org/html/rfc1928) (which is super short and really to the point) we can see that this packet corresponds to:

```
+----+----------+----------+
|VER | NMETHODS | METHODS  |
+----+----------+----------+
|\x05|   \x02   | \x00\x01 |
+----+----------+----------+
```

With `\x00` being "no auth required" and `\x01` is GSSAPI.

The server should choose method `\x00` and respond with version plus the choosen method, i.e. `\x05\x00`.

This fits with our assumptions. TODO MERE HER

MERE


**Idea 2: Make dante connect to us and replay traffic**

Lets first try to run dante locally and see if we can make it connect to itself:

61080

```python
import socket
TARGET, PORT = '127.0.0.1', 61080

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((TARGET, PORT))

    s.sendall(b'\x05\x02\x00\x01')  # client hello
    assert s.recv(2) == b'\x05\x00'  # auth none

    s.sendall(b'\x05\x01\x00\x01')  # Connect to following IPv4 and port:
    s.sendall(b'\x7f\x00\x00\x01')  # IP: 127.0.0.1
    s.sendall(b'\xee\x98')  # Port: 61080
    assert s.recv(1) == b'\x05'
    print("Connected status:", s.recv(1))
    assert s.recv(2) == b'\x00\x01'
    print('Connected as IP:', s.recv(1024))

    s.sendall(b'\x05\x02\x00\x01')
    print('It works?', s.recv(1024))

"""
Connected status: b'\x00'
Connected as IP: b't\xcb\xf4\x9a\xc6\x84'
It works? b'\x05\x00'  # <-- it works!
"""
```



192.168.31.239:8000
