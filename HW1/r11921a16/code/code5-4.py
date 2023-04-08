import re
from io import BytesIO
# from baudot import decode_to_str, codecs, handlers

ciphertext = input("Cipher Text of Round 4: ")
ciphertext = ciphertext.replace('!', '').replace(',', '').replace('.', '').replace(' ', '')
plaintext = ''

for i in range(len(ciphertext)):
    plaintext += '1' if re.search(r"[a-z]", ciphertext[i]) else '0'

print(plaintext)
# for i in range(0, len(plaintext), 5):
# 	print(plaintext[i:i+5], end=" ")