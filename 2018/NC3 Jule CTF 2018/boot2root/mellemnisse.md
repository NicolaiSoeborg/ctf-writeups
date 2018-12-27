$ megadl https://mega.nz/#!VcVxEIRI!dUoeo93xYvaBBB2s8wj6WdlvEKIjOHi8voZghLD4SYQ
$ tar -x < nc3ctf2018_boot2root.tar
$ cd nc3ctf2018_boot2root/
$ guestmount --ro -i -a nc3ctf2018_boot2root-cl1.vmdk mp/
> Enter key or passphrase ("/dev/sda5"): nc3nisse2018
$ cd mp/

$ file home/lillenisse/sambashare_til_mine_gaver/nissevaerksted_shell_crypted.exe
> nissevaerksted_shell_crypted.exe: PE32 executable (console) Intel 80386, for MS Windows, UPX compressed

Lets unpack it:

$ upx -d nissevaerksted_shell_crypted.exe
>                        Ultimate Packer for eXecutables
>                           Copyright (C) 1996 - 2017
> UPX 3.94        Markus Oberhumer, Laszlo Molnar & John Reiser   May 12th 2017
> 
>         File size         Ratio      Format      Name
>    --------------------   ------   -----------   -----------
>      76800 <-     38912   50.67%    win32/pe     nissevaerksted_shell_crypted.exe
> 
> Unpacked 1 file.

$ strings nissevaerksted_shell_crypted.exe
> [...]
> HEJ VEN ...
> K0dEORD, tak:
> Velkommen
> cmd.exe
> FORKERT!
> sfotezsfsnjulpef1se

Rotate that by '-1' and get: 'rensdyrermitkode0rd'

$ cat home/mellemnisse/.fl@g.txt
> Det her flag er lidt specielt. Erstat de mange X'er nedenfor med det kodeord som du brugte til at få shell:
> NC3{mellemnisse_fundet_via__XXXXXXXXXXXXXXXXXXX}

Flag: NC3{mellemnisse_fundet_via__rensdyrermitkode0rd}

(this flag should probably have been found by scanning port 9000 and reversing nissevaerksted_shell_crypted.exe)
