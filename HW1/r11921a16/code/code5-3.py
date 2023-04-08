import base64

c1_hex = input("c1 base64 = ")
c1_hex = base64.b64decode(c1_hex).hex()
c1_hex= int(c1_hex, 16)

m1_hex = input("m1 string = ")
m1_hex = m1_hex.encode("utf-8").hex()
m1_hex = int(m1_hex, 16)

key_hex = hex(c1_hex ^ m1_hex).split('x')[1]

c2_hex = input("c2 base64 = ")
c2_hex = base64.b64decode(c2_hex).hex()
c2_hex_len = len(c2_hex)


if len(key_hex) >= c2_hex_len:
    key_hex = key_hex[:c2_hex_len]
else:
    c2_hex = c2_hex[:len(key_hex)]
c2_hex = int(c2_hex, 16)

key_hex = int(key_hex, 16)
plaintext = hex(c2_hex ^ key_hex).split('x')[1]
print(bytes.fromhex(plaintext).decode('utf-8'))