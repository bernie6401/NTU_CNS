from pwn import *
from accumulator import RSA_Accumulator
from Crypto.Util.number import inverse


r = remote('cns.csie.org', 4001)
context.arch = 'amd64'


p = 0xfe7fa2d93be7396c7172a7186f4e561949f53e436a7ed65da22786637b7e76081f65b972be84ea612787a07878c1bf9454edf81059f84158efe34b4207f96d71
q = 0xb76082ea921f3d4729e59d765ff014ad745b6421f1bacc359417e0c2a1aaa318bd96ba0f6476e09bd1db72fa4dfc7fa5aa0ee1bef7bc4f268fb42673e539d3b1
def bad_setup():
    acc = RSA_Accumulator(1024)
    acc.N = p * q
    acc.g = 0xa8ccac65582e3accb0e246c4d79b9d054e85e086b6d5c48df6f79bf60ad4c77d797ba7fdba0b0a83071f16e427bff7d7d7ab768d4694f90a5eef5278201f8848221b998a7f5322a66f9eac87d5d4f801a2af3fa7a983f9678732b6b16b40c2e2b8e5612e9834f2e64b0aa91f91c479113b0d263dc81572f5b5d367d4911008cd
    
    acc.add(b"Member0")
    acc.add(b"Member1")
    acc.add(b"Member2")
    digest = acc.Digest()
    return acc, digest

for i in range(4):
    r.recvline()

phi = (p-1)*(q-1)

acc, digest = bad_setup()
message = b"Member3"    # A new member that is not in member set
m = acc.HashToPrime(message)
inv_m = inverse(m, phi)
proof_new = pow(digest, inv_m, acc.N)   # Construct a fake proof

r.sendline(b'0')
r.sendline(message)
r.sendline(str(proof_new).encode())

r.interactive()