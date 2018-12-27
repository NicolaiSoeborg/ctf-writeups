$ megadl https://mega.nz/#!VcVxEIRI!dUoeo93xYvaBBB2s8wj6WdlvEKIjOHi8voZghLD4SYQ
$ tar -x < nc3ctf2018_boot2root.tar
$ cd nc3ctf2018_boot2root/
$ guestmount --ro -i -a nc3ctf2018_boot2root-cl1.vmdk mp/
> Enter key or passphrase ("/dev/sda5"): nc3nisse2018
$ cd mp/

$ cat home/mellemnisse# cat note_fra_storenisse.txt
> rudolfersej

$ ecryptfs-unwrap-passphrase home/.ecryptfs/storenisse/.ecryptfs/wrapped-passphrase
> Passphrase: rudolfersej
> 65380fa32a30972fbf8ad16838a4d2b3

$ ecryptfs-recover-private home/.ecryptfs/storenisse/.Private
> INFO: Found [home/.ecryptfs/storenisse/.Private].
> Try to recover this directory? [Y/n]: y
> INFO: Found your wrapped-passphrase
> Do you know your LOGIN passphrase? [Y/n] rudolfersej
> INFO: To recover this directory, you MUST have your original MOUNT passphrase.
> INFO: When you first setup your encrypted private directory, you were told to record
> INFO: your MOUNT passphrase.
> INFO: It should be 32 characters long, consisting of [0-9] and [a-f].
> 
> Enter your MOUNT passphrase: 
> INFO: Success!  Private data mounted at [/tmp/ecryptfs.gUaZ22FM].

$ cd /tmp/ecryptfs.gUaZ22FM
$ cat flag.txt
> NC3{godt_fundet_mester__tag_nu_den_store}
$ cat rootflag.txt
> NC3{r00t_dansemus}
