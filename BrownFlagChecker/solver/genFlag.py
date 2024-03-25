from Crypto.Cipher import AES
from hashlib import md5


key = b"H4VIn9_7Hi5_KEY_ME4n5_you_4rE_che47In9_ON_me_7f6301e1920cb86cf8e"
hash = md5(key).digest()
flag = b"LINECTF{72f9fc0fdf5129a4930286e5b9794e10}" 
if len(flag) % 16 != 0:
    flag += b"\x00" * (16 - (len(flag) % 16))

# print(len(hash))
iv = bytes([i for i in range(16)])
aes = AES.new(key=hash, iv =iv, mode=AES.MODE_CBC)
enc = aes.encrypt(flag)
print(f"Encrypted flag: {list(enc)}")
print(f"Encrypt flag len: {len(enc)}")