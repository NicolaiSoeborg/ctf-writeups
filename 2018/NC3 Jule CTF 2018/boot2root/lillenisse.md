$ megadl https://mega.nz/#!VcVxEIRI!dUoeo93xYvaBBB2s8wj6WdlvEKIjOHi8voZghLD4SYQ
$ tar -x < nc3ctf2018_boot2root.tar
$ cd nc3ctf2018_boot2root/
$ guestmount --ro -i -a nc3ctf2018_boot2root-cl1.vmdk mp/
> Enter key or passphrase ("/dev/sda5"): nc3nisse2018
$ cd mp/

$ strings var/lib/mysql/ib_* | grep NC3
lillenissed3c23faeb8f7aa2bec55465283ca121cNC3{web_er_ikke_noget_problem_for_en_nisse}
+NC3{web_er_ikke_noget_problem_for_en_nisse}*

But this is not the flag!

$ strings var/lib/mysql/hemmelig/users.ibd
> [two hex strings]

The first hex string gives the flag from before, but the second decodes to:
> TkMze3dlYl9lcl9pa2tlX25vZ2V0X3Byb2JsZW1fZm9yX2VuX25pc3NlX19lal9oZWxsZXJfc3FsaX0=
$ echo 'TkMze3dlYl9lcl9pa2tlX25vZ2V0X3Byb2JsZW1fZm9yX2VuX25pc3NlX19lal9oZWxsZXJfc3FsaX0=' | base64 -d
> NC3{web_er_ikke_noget_problem_for_en_nisse__ej_heller_sqli}

Flag: NC3{web_er_ikke_noget_problem_for_en_nisse__ej_heller_sqli}

(this flag should probably have been found by exploiting the SQLi in var/www/html/dev/index.php)
