from pwn import *
from accumulator import RSA_Accumulator
from Crypto.Util.number import inverse
from hashlib import sha256

r = remote('cns.csie.org', 4002)
context.arch = 'amd64'

r.recvline()
N = int(r.recvline().strip().split()[-1].decode().split("0x")[-1], 16)
g = int(r.recvline().strip().split()[-1].decode().split("0x")[-1], 16)
log.info(f"N = {N}\ng = {g}")

magic1 = open('D:/NTU/First Year/2nd semester/Cryptography and Network Security/HW3/hw3/release/accumulator/shattered-1.pdf', 'rb').read()
magic2 = open('D:/NTU/First Year/2nd semester/Cryptography and Network Security/HW3/hw3/release/accumulator/shattered-2.pdf', 'rb').read()

r.recvuntil(b"Enter your choice? [0,1,2] ")
r.sendline(b"1")
r.recvuntil(b"Give me your message: ")
r.sendline(magic1.hex().encode())

print(r.recvline())

r.interactive()