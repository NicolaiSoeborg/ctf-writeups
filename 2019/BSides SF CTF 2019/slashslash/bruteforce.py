# SevenPinLock0123456
from subprocess import run, DEVNULL
from os import system

for key in range(10000000):
    k = str(key).zfill(7)
    p = run(['/usr/bin/openssl', 'aes-128-cbc', '-d', '-in', 'flag.aes128cbc', '-out', f'/tmp/bruteforce/{key}.bin', '-k', k], stderr=DEVNULL)
    if p.returncode == 0:
        print('FOUND:', k)
        system(f'cp /tmp/bruteforce/{key}.bin ./found/{key}.bin')
    else:
        system(f'rm /tmp/bruteforce/{key}.bin')
    
    if key % 100000 == 0:
        print(key)
