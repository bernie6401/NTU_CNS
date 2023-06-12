import base64
import gmpy2
# from hashlib import sha256
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256


def initialize(message, c_or_m):
    if c_or_m == 'c':
        return gmpy2.mpz(int(base64.urlsafe_b64decode(message).hex(), 16))
    elif c_or_m == 'm':
        return gmpy2.mpz(int(pkcs1_15._EMSA_PKCS1_V1_5_ENCODE(SHA256.new(message.encode()), 256).hex(), 16))

ciphertext = {
    0 : "P3CrfkIst3dMk-mb7-iFeKTHXjSUfT4pfizXwfSfWBTgr43r072K0ObHOYzeVYiYKGzDR9ASOfvmqzEk6h0wp41w9vXxdLjEbkm5jEgcSp7BKf9nWx3p_eWq9vfAH-fFz4KbbYaukKuqjMwy_RwxG6BzjWBLpCAjJSjtES9rHWmQsoWDZ_EKZqkTg49pVk4gwgNWr3ENno1C-R2_jMqaic-Gz8zlwwArIlEC6PaADnmRr_fxrS8k16gLjJWuvl_dI4fFAZv7-DwovUrVHsX1tsaw-SzrhmalP-w8sd7bx8eXO2yauL9myCWJGQKvtqS-EMGeYZSaU6NJ0u3h4CAkAQ==",
    1 : "VRTs7trtGbg5GmYJ9gWrAZivbsmDlawB388dk3qXdl1E1q6pdQdeJ0o7KsmxrnA-RaG4LyckKJ9jjl0jr6-bPLpyRc3WJx96tjYAVO_edfnLL6PJ-p5FGpXK9J5A8ZzTUAYgVmo8D3fFCvdk1Z4w1YwgfxXv25XQzy1oWnKMMi19Vkk7720PMnFkNjrGlbKsjq0_HUzjrieEXUFYDLXyBsyOADQetaqkUWvlssKwrHjux4omY1E-n1-LRfOLzBIlM3MNITV6tpexh0crYbWH6i6WAcXKXIsalrLiEcO3SJxFrj1-digynTG93Yhi4SR0yEjI72q6pr4TxDYf9TZCvQ==",
    2 : "J3XJZ7658Y3GiE4FWQQOtsElOjJQwaU04RmlPQT8y9W3RTyqiUxdicEvVDR14586PX3Q2f11uUiyDyGuol3cnUzyRcLYA_xT3Xu9SEbI4eI1ex0cZ9b4LGPD5Qu5kmoPblt9uqLFaryuiaNxgCLFT-qEXv4eqmDO5lNaoVxJe98h6R1KwklAQsS0pIZcNmTfBQLMyn-RLxBfzlF2FMrzIGuL5A2MQR4hfLTYnvh-VgsA_cPwFwf6AURek6lCFH3jjSJpEeKCnFkpT_UJBjZy8YZwKhPHLngk5xp86HxzI5bBNYxOrmrGB834iRcZv3fbS5YwqU5RSEpD99kycYJPRA==",
    3 : "jPtL9XigArSjtHfAiw2PMkq-i30G1fufTMZ0IZYihEU9-8KGvuhV29Dceh56sa15gfVdJR3dFP93h7ymj2U-pa0TdKyWYgv4qhoUJ4qvzmO0EAjLombfcG2aV7qx59TbSoI9LJuH4su3Gfhxg7kkev_9qLZHt0IQdSxysrsMlSfQfjkarzxICf9hOF0n6diWjaWy10OL12IAHzhZ_DteBVTaKgZYmol0UyaAXLGXExR37Pcio42uOB2FltGvte6CMs5JBbaVQKY6HO8PsY7oOUQC1GqNDzqjtUlbldIpmuhs_rdU-XB67OXYM7PrHjBnAkLl4BZ-Bht9XACRuzHFoQ=="
}

plaintext = {
    0 : "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9eyJ1c2VybmFtZSI6Imd1ZXN0IiwiZmxhZzEiOiJDTlN7Slc3XzE1X04wN19hXzkwMGRfUExBQ0VfNzBfSDFERV81ZWNyRTc1fSIsImV4cCI6MTY4NjM2NzA4MX0",
    1 : "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9eyJ1c2VybmFtZSI6Imd1ZXN0IiwiZmxhZzEiOiJDTlN7Slc3XzE1X04wN19hXzkwMGRfUExBQ0VfNzBfSDFERV81ZWNyRTc1fSIsImV4cCI6MTY4NjM2NzMxNn0",
    2 : "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9eyJ1c2VybmFtZSI6Imd1ZXN0IiwiZmxhZzEiOiJDTlN7Slc3XzE1X04wN19hXzkwMGRfUExBQ0VfNzBfSDFERV81ZWNyRTc1fSIsImV4cCI6MTY4NjM2NzM5OX0",
    3 : "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9eyJ1c2VybmFtZSI6Imd1ZXN0IiwiZmxhZzEiOiJDTlN7Slc3XzE1X04wN19hXzkwMGRfUExBQ0VfNzBfSDFERV81ZWNyRTc1fSIsImV4cCI6MTY4NjM2ODM0M30"
}

c = m = {}
for i in range(4):
    c[i] = initialize(ciphertext[i], 'c')
    m[i] = initialize(plaintext[i], 'm')

# print(m)

e = gmpy2.mpz(65537) # The default parameter in openssl
# for i in range(20):
a_N = c[0]**e - m[0]
b_N = c[1]**e - m[1]
c_N = c[2]**e - m[2]
# print(gmpy2.gcd(a_N, c_N))
# print(gmpy2.gcd(c_N, b_N))
print(gmpy2.gcd(a_N, b_N, c_N))
    # e -= 2