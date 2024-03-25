from Crypto.Cipher import AES

# Key: H4VIn9_7Hi5_KEY_ME4n5_you_4rE_che47In9_ON_me_7f6301e1920cb86cf8e
offset = ["GUY", "ICE", "MOO", "VIM", "DOG", "CAT", "QRS", "ZIP", "BAT", "EYE", "DEF", "SPE", "WIN", "ATK", "CRY", "ABC", "RED", "AIR", "COW", "EGG"]

data = [
    bytes([ 188, 212, 252, 120, 165, 17, 251, 138, 212, 35, 208, 189, 53, 5, 33, 220 ]),
    bytes([ 158, 214, 103, 179, 141, 19, 141, 231, 73, 115, 82, 248, 180, 86, 248, 88 ]),   
    bytes([ 251, 167, 60, 163, 232, 141, 60, 116, 218, 203, 50, 132, 133, 236, 42, 237 ]),
    bytes([ 110, 49, 250, 85, 224, 57, 39, 250, 43, 144, 120, 182, 198, 114, 105, 223 ]),
    bytes([ 187, 189, 170, 69, 52, 207, 117, 202, 215, 211, 28, 19, 5, 62, 99, 78 ]),
    bytes([ 96, 58, 231, 123, 36, 218, 112, 111, 153, 42, 238, 178, 26, 150, 198, 51 ]),
    bytes([ 113, 41, 44, 14, 107, 47, 63, 47, 217, 113, 17, 178, 75, 99, 66, 244 ]),
    bytes([ 203, 221, 134, 62, 31, 3, 229, 47, 163, 177, 215, 244, 110, 168, 48, 208 ]),
    bytes([ 217, 174, 203, 90, 216, 252, 132, 243, 170, 197, 139, 157, 8, 45, 29, 143 ]),
    bytes([ 245, 209, 92, 90, 178, 233, 107, 33, 231, 44, 116, 250, 17, 0, 2, 220 ]),
    bytes([ 46, 68, 209, 132, 231, 5, 74, 122, 167, 103, 83, 138, 211, 202, 97, 217 ]),
    bytes([ 245, 24, 185, 114, 105, 76, 121, 204, 196, 19, 139, 224, 57, 102, 158, 89 ]),
    bytes([ 207, 116, 77, 239, 73, 187, 116, 170, 150, 110, 231, 245, 99, 9, 103, 137 ]),
    bytes([ 1, 80, 176, 96, 71, 226, 12, 246, 163, 189, 156, 65, 176, 97, 158, 52 ]),
    bytes([ 105, 158, 187, 97, 159, 171, 28, 20, 60, 142, 9, 195, 54, 252, 248, 248 ]),
    bytes([ 228, 73, 99, 112, 233, 54, 83, 141, 156, 20, 202, 240, 3, 188, 43, 61 ]),
    bytes([ 239, 175, 161, 68, 123, 200, 221, 248, 31, 156, 58, 248, 204, 194, 87, 139 ]),
    bytes([ 114, 94, 168, 77, 38, 71, 141, 175, 166, 142, 173, 155, 253, 190, 82, 111 ]),
    bytes([ 98, 78, 179, 48, 215, 99, 155, 148, 92, 236, 69, 21, 199, 245, 83, 88 ]),
    bytes([ 226, 66, 241, 66, 29, 42, 174, 199, 193, 236, 25, 106, 67, 69, 119, 226, 5, 211, 145, 227, 114, 89, 107, 170, 150, 65, 8, 77, 142, 145, 70, 243, 95, 134, 178, 42, 5, 178, 42, 138, 8, 155, 252, 102, 43, 7, 228, 61, 236, 87, 250, 28, 138, 253, 187, 8, 120, 6, 219, 120, 53, 79, 91, 224 ])
]

inp = "GUY"
ciphertextOffset = "EGG"
keyOffsetPairs = [
    ('BAT', 'COW'), 
    ('SPE', 'EYE'), 
    ('WIN', 'ABC'), 
    ('CRY', 'ICE'), 
    ('CAT', 'DOG'), 
    ('VIM', 'ATK'), 
    ('ZIP', 'RED'), 
    ('DEF', 'QRS'), 
    ('AIR', 'MOO')
]

assert len(offset) == len(data)
mapping = {offset[i] : data[i] for i in range(len(offset))}

ciphertext = mapping[ciphertextOffset]
for (keyOffest, ivOffset) in keyOffsetPairs[::-1]:
    # print(keyOffest, ivOffset)
    key = mapping[keyOffest]
    iv = mapping[ivOffset]

    aes = AES.new(key=key, iv=iv, mode=AES.MODE_CBC)
    p = aes.decrypt(ciphertext)
    # print(p)
    ciphertext = p
    # break

print(p)