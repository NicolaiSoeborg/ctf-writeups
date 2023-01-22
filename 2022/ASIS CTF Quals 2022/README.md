# ASIS CTF Quals 2022

URL: https://asisctf.com/

Team: Kalmarunionen

Place: 1 (of 532)

## Flags

Our team solved 23 out of 26 challenges.
Of the 3 unsolved challenges two of them had zero solves when the CTF ended (`Allotment` & `hugeblog`).

After the CTF ended we got a small hint for `hugeblog`.

## Challenge: `hugeblog`

Description:

> I patched some bugs of `miniblog#` from zer0pts-CTF 2022. Can you pwn it again?
> Note: AES knowledge is helpful but you don't need to know the math behind it.
> http://hugeblog.asisctf.com:9000
> Download source code from [here](./hugeblog_84365d0b6614fc6fd9e36029c8cda091646d632f.txz).

We are given a simple Flask app with login functionality, add/delete/view blog posts and import/export of "blog post database".

At first glance there is a clear SSTI in the view blog post route:

```python
flask.render_template_string(post['content'],
                             title=post['title'],
                             author=post['author'],
                             date=post['date'])
```

We control `post['content']`, but when making new blog posts the `/api/new`-endpoint checks for `{%` and `{{`.

### Just bit flip it?

The first idea was just just create a blog post with the content:

> `z{ config.__class__.from_envvar.__globals__.__builtins__.__import__('os').popen('cat /oh-i-have-the-flag.txt').read() }}`

The binary representation of `z` is `1111010` and `{` is `1111011`, so all we need is a single bit flip!
Instead of waiting for a lucky cosmic ray, we can download a backup, flip the correct bit, upload the malicious backup and visit the page displaying the injected SSTI to get RCE.

So lets look at the backup.  The backup is a uncompressed (`STORED`) ZIP archive containing each blog post as a JSON file.
The ZIP needs to contain the comment `SIGNATURE:{username}:{passhash}`.
Finally the ZIP is encrypted using a AES in CFB mode. The AES-key is static and the IV is random for each backup (and appended to the backup).

Is flipping a byte doable?
 * Offsets can easily be predicted because the file is uncompressed
 * It wont break the ZIP-comment (and we can just calculate a new if it did)
 * Flipping a byte in the encryption layer will make the next 16 bytes random, meaning we can't predict the correct CRC32 (and change the stored CRC32 sum / make sure the payload collide)
 * During unpacking, if the CRC32 checksum fails an empty file will be unpacked :(

What we learned after the CTF is that `ZipFile.extractall()` ends up calling:

```python
with self.open(member, pwd=pwd) as source, open(targetpath, "wb") as target:
    shutil.copyfileobj(source, target)
```

The `copyfileobj` method of `shutil` will _copy data from file-like object fsrc to file-like object fdst_.
In this case _fsrc_ is a `ZipExtFile` object which implements a `.read()` method (and _fdst_ is an actual file on disk).

`copyfileobj` will copy data in chunks of size 65536 (`COPY_BUFSIZE`) using something like:

```python
while True:
    buf = fsrc.read(COPY_BUFSIZE)
    if not buf:
        break
    fdst.write(buf)
```

The `.read()` method of `ZipExtFile` ends up calling `._read1()` which internally calls `self._update_crc(chunk)`, this way a running CRC32 is calculated and when EOF is reached, a `BadZipFile` is raised if the CRC32 doesn't match the stored CRC32 in the ZIP file.

So if we set have a blog post which JSON representation take up 65536+1 bytes, then the first 65536 bytes will be dumped to disk!

But the newly dumped file needs to be valid JSON for the page displaying the SSTI to work.

### Broken JSON

Current attack:

> `exported backup = ENC([ZIP_HEADER][RAW_FILE_CONTENT][ZIP_FOOTER])`
> `[RAW_FILE_CONTENT]` is: `{"author": "…", "title": "…", "content": "z{ payload }} AAA…AAA"}`

We know how long `[ZIP_HEADER]` is, so we can XOR the bit corresponding to `z` with 1 to we flip it to `{`.
We also knows that the file will end with `…AAAA` and be missing `"}`, making it invalid JSON.
We could align the last part of the `A`'s with `"}`, but that wont work as JSON would escape it as: `…AAA\"}"}`

So we have to also bit-flip the 65536-3 byte to change it from `\` anything JSON-string like, e.g. XOR with 23 to get `…AAAK"}"}` (and last two bytes getting removed due to CRC32 dropping last chunk).

### Bit-flips ⇒ garbage

We can't do bitflips without introducing garbage!

Last byte should be: `…AA` and we flip it to `…"?` with `?` being a random byte with prob. 1/256 of being `}`

Also we need to push the payload 1 block forward
And failure prob. is higher if random bytes are not JSON-string friendly.

#### Cipher feedback (CFB)

![Wikipedia: Cipher feedback (CFB) - Encryption diagram](./CFB_encryption.svg)

