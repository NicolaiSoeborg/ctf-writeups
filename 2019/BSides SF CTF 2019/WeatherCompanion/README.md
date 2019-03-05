Open app using `jadx`, but it's heavily obfuscated.

Use `frida` to hook `StringBuilder` in early startup.

Find private key of service account.

Spend lot of time not figuring out why bucket `flag/` can't be accessed.

Finally found out that the flag was located in bucket `weather-companion/flag.txt`

Command: `GOOGLE_APPLICATION_CREDENTIALS=./gcloud-private-key.json gsutil cp gs://weather-companion/flag.txt .`

Flag: `CTF{buck3t_s3at5}`
