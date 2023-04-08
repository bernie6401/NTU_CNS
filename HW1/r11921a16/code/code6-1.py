from pwn import *
from Crypto.Util.number import bytes_to_long, long_to_bytes
from Crypto.Util.number import inverse

r = remote('cns.csie.org', 6001)
context.arch = 'amd64'

r.recvuntil(b"P = ")
p = int(r.recvline().strip().decode())
r.recvuntil(b"g = ")
g = int(r.recvline().strip().decode())
r.recvuntil(b"cipher = (")
c1 = int(r.recvuntil(b", ").decode().replace(", ", ""))
c2 = int(r.recvuntil(b")").decode().replace(")", ""))

log.info("P = {}".format(p))
log.info("g = {}".format(g))
log.info("c1 = {}".format(c1))
log.info("c2 = {}".format(c2))


m2 = '1'
r.recvuntil(b"Do you want to encrypt something? (y/n): ")
r.sendline(b'y')
r.recvuntil(b"Give me your message: ")
r.sendline(m2.encode())
r.recvuntil(b"Your cyphertext (")
c1_ = int(r.recvuntil(b", ").decode().replace(", ", ""))
c2_ = int(r.recvuntil(b")").decode().replace(")", ""))

log.info("c1\' = {}".format(c1_))
log.info("c2\' = {}".format(c2_))
m2 = bytes_to_long(m2.encode())
log.info("m2 = {}".format(m2))


tmp = c2_ * inverse(m2, p) % p
flag = c2 * inverse(tmp, p) % p
flag = bytes.fromhex(hex(flag).replace('0x', "")).decode('utf-8')

log.info(flag)

r.close()

r.interactive()