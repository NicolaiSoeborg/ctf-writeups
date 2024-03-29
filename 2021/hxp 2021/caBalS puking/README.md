# caBalS puking

Challenge description:

> Hey, did you hear the good news? We were finally able to get ADB access to kirschju’s phone. All we could find on the file system were two Signal backup files, though. Nevertheless, with hxp’s ever-delayed challenge development process, there is hope that we might find a flag in the backup.

> The first backup coincides closely with the registration time of the target Signal account, so we believe it represents the state of an empty account. The second backup file is a lot larger, for sure there’s some valuable piece of information in there.

> We’re also attaching the Signal app retrieved from the phone for your reference, but it doesn’t seem to be modified compared to a vanilla app.


Looking at [the challenge files](./caBalS%20puking-2672391a1b33417f.tar.xz) we get:

 * `signal-2021-11-29-22-02-26.backup`  ("initial database")
 * `signal-2021-11-30-00-18-47.backup`  ("database w/ flag")
 * `Signal.apk`

## Analysing backup files

We found this great tool to decrypt Signal backups:

<https://github.com/mossblaser/signal_for_android_decryption>

We used this tool to analyse and understand the two backups.

```python
initialisation_vector, salt = read_backup_header(backup_file)
cipher_key, hmac_key = derive_keys(passphrase, salt)
```

The header is a `BackupFrame`-without MAC (more on that later)

The passphrase is split into a cipher key and a MAC key by first doing 250000-rounds of SHA512 stretching and then splitting into two 32 bytes keys using HKDF-SHA256.
We don't know the key and the key is auto-generated by Signal when creating a backup, so we can't attack these keys.

Normally a backup from Signal would be a full dump of the database with a completely new random IV and salt, but the two files we get has the same IV and salt (!)

```
IV = 87166ab8af3c58629ff5c5eb5b471ebc
salt = 0e6621b28a618a652893e84299b8fc8204e80f0a3a00d612c31a8cb890f9f8e9
```

The encryption primitive is [AES-CTR](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Counter_(CTR)), so this is _just_ a simple IV reuse attack!

To attack it we can take any known part of the initial database, XOR that with the encrypted initial database (to get the keystream "at that point") and then XOR that with the corresponding point in the database that has the flag. I.e:

```
 known_pt ^ initial_ct ^ flag_ct => flag_pt
[_____ keystream _____]
```

So we need to fulfill the following two assumptions:

> We can find known _cribs_ in the ciphertext and their offsets

Example of those would be: "it always starts/ends with a header/footer with known bytes" or "at some point the byte sequence XYZ will occur and the file is small enough that we can just try all possible offsets"

> The cribs offsets will be shifted or the two ciphertexts will differ at the offset

If the two ciphertext is identical at a specific offset and we _guess_ the plaintext at that offset in the "initial backup", then we are not attacking Counter Mode at that offset -- we are guessing and learning nothing new.

Instead what we hope happens is that some parts partially overlap, which means we will get a partial plaintext and because the underlying plaintext is protobuf and SQLite we might be able to predict more bytes given the partial plaintext.  We can then use that newly predicted plaintext to recover more of the initial database, and so forth.

[TODO: Insert example]

So lets dig into the raw bytes so we can start the known-plaintext attack.

## Signal Backup Format (for Android)

The Signal `.backup` consist of multiple _chunks_.

Chunks without attachments has the following structure:

| **Length**  | 4    | size - 10   | 10  |
|-------------|------|-------------|-----|
| **Content** | size | BackupFrame | MAC |

With `size` being a big-endian number and MAC is a HMAC-SHA256 using `hmac_key`.

The field `BackupFrame` is the AES-CTR encrypted protobuf using the "global" IV.
Note: that the IV is increased after both every BackupFrame and Payload-chunk.

A BackupFrame-protobuf structure can contain multiple types, e.g. SqlStatement (`INSERT INTO sms ...`), KeyValue-pairs, Preference, etc, but also a "out of protobuf payload" for Attachment, Sticker and Avatars.

For the first types, the raw data will be inside the protobuf structure.
For big data types the struct will contain a "has payload = true" field and a size of the payload.

| **Length**  | (defined in parent BackupFrame) | 10  |
|-------------|---------------------------------|-----|
| **Content** | Payload                         | MAC |

We can map the structure of the initial database by simply parsing the first 4-byte length field and then skipping that many bytes (to seek to the next BackupFrame header).
This works very well for the first 87 BackupFrames as these has no payloads, but at offset 0x45c0 we find something which is too big to be the length of a BackupFrame.

### Payloads in initial database

So which payloads are stored in the initial (empty) database? ... Stickers of course!

![How would society function without this animated webp image your browser probably cant display?](sticker-3.webp)

Almost all of the file size of the empty backup is due to the 78 default stickers.

So back to the initial problem, how do we know which sticker is starting at offset 0x45c0?
Solution: decrypt all of the default stickers from your own Signal database and find the lengths of them, then for each length try to move the file pointer that amount and see if the next chunk looks like a `BackupFrame` header (i.e. starts with `\x00\x00` due to the BackupFrame being small).

We implemented this in [`find-stickers.py`](find-stickers.py) looking from the bottom of the file and waiting for 4 bytes that points the the last known "good offset".

The script quickly finds a single solution where each sticker is used exactly once and all of the file is either mapped to a BackupFrame or a payload matching a default sticker.

Because the initial database and the database with the flag diverge, we get a sticker overlapping the flag!

I.e. we have something similar to the following structure:

| Initial Backup | Flag Backup             |
|----------------|-------------------------|
| std settings   | std settings            |
| Sticker 1      | `INSERT INTO mms(...)`  |
| Sticker 2      | Sticker 1               |
| Sticker _n_    | Sticker 2               |
| _EOF_          | Sticker _n_             |
|                | EOF                     |

Now we are back to the trivial nonce reuse attack, just needing to carefully align the `sticker plaintext` XOR `initial db at sticker offset` XOR `flag db at counter offset` and we get a decrypted chunk of the flag DB.

A big shout out to all the teammates in Kalmarunionen bringing useful insights and working on the challenge (killerdog, eevee, andyandpandy, etc), and of course hxp for making the challenge.

![Image of a received MMS with the flag](flag.jpg)

Flag: `hxp{f0rmattin5+crypt0=<3}`