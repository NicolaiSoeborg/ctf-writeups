from math import sqrt
from telnetlib import Telnet
#from collections import defaultdict
#from string import ascii_lowercase

PROMPT = b"Press enter when you are ready.\n"

def sieve_of_eratosthenes(n):
    prime = [True for i in range(n + 1)]
    p = 2
    while (p * p <= n):
        if prime[p]:
            for i in range(p * 2, n + 1, p):
                prime[i] = False
        p += 1
    prime[0] = False
    prime[1] = False
    return prime

primes = [p for p, b in enumerate(sieve_of_eratosthenes(10_000_000)) if b]
print(f"Primes: {len(primes)}")

with Telnet('challenges.tamuctf.com', 8573) as tn:
    tn.read_until(PROMPT)
    tn.write(b"\n")
    chal = int(tn.read_until(b"\n").decode()[:-1])
    print(f"CHALLENGE: {chal}")
    for p in primes:
        guess = str(chal / p)
        if guess[-2:] == '.0':
            p = int(guess[:-2])
            q = int(chal / p)
            print(f"FOUND: p={p}, q={q}")
            tn.write(f"{p} {q}\n".encode())
            break
    else:
        print("Didn't solve it ... :/")
        exit(1)
    print(tn.read_all().decode())

# gigem{g00d_job_yOu_h4aaxx0rrR}
