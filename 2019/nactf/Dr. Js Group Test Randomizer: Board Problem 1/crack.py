from telnetlib import Telnet

def get_rnd(tn):
    tn.write(b"r\n")
    rnd = tn.read_until(b"\n> ")[:-3]
    return int(rnd.decode())

with Telnet('shell.2019.nactf.com', 31258) as tn:
    print(tn.read_until(b"> "))
    print("Let it loop for about 4000 random values, then it should output just zeros or 39")
    i = 0
    try:
        while True:
            i += 1
            print(i, get_rnd(tn), flush=True)
    except KeyboardInterrupt:
        pass
    tn.interact()
