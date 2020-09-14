from Crypto.Cipher import AES
from Crypto.Protocol.SecretSharing import Shamir

data = [
    ("01", "c4ee528d1e7d1931e512ff263297e25c"),
    ("02", "4b58b8b5285d2e8642a983881ed28fc7"),
    ("03", "7180fe06299e1774e0a18f48441efdaf"),
    ("04", "48359d52540614247337a5a1191034a7"),
    ("05", "1fcd4a7279840854989b7ad086354b21"),
    ("06", "f69f8e4ecde704a140705927160751d1"),
    ("07", "b0ca40dc161b1baa61930b6b7c311c30"),
    ("08", "04ed6f6bf5ec8c8c2a4d18dcce04ae48"),
    ("09", "430ad338b7b603d1770f94580f23cb38"),
    ("10", "d51669551515b6d31ce3510de343370f"),
    ("11", "b303ee7908dcbc07b8e9dac7e925a417"),
    ("12", "3c4a692ad1b13e27886e2b4893f8d761"),
    ("13", "a8e53ef9ee51cf682f621cb4ea0cb398"),
    ("14", "feb294f9380c462807bb3ea0c7402e12"),
    ("15", "9b2b15a72430189048dee8e9594c9885"),
    ("16", "f4d52e11f6f9b2a4bfbe23526160fdfd"),
    ("17", "d0f902472175a3f2c47a88b3b3108bb2"),
    ("18", "cc29eb96af9c82ab0ba6263a6e5a3768"),
    ("19", "913227d2d7e1a01b4ec52ff630053b73"),
    ("20", "8669dd2b508c2a5dfd24945f8577bd62")]

shares = [(int(idx, 10), bytes.fromhex(h)) for (idx, h) in data]

key = Shamir.combine(shares)
print(key)

# cbc:254dc5ae7bb063ceaf3c2da953386948:08589c6b40ab64c434064ec4be41c9089eefc599603bc7441898c2e8511d03f6
cipher = AES.new(key, AES.MODE_CBC, iv=bytes.fromhex("254dc5ae7bb063ceaf3c2da953386948"))
pt = cipher.decrypt(bytes.fromhex("08589c6b40ab64c434064ec4be41c9089eefc599603bc7441898c2e8511d03f6"))
print(pt)

# b'_z3r0_kn0wl3dg3_'
# b'flag{n0t_s0_s3cur3_4ft3r_4ll}\n\x00\x00'

