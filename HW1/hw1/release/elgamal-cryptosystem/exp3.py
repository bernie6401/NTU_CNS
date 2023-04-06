from pwn import *
from Crypto.Util.number import bytes_to_long, long_to_bytes
from Crypto.Util.number import inverse

r = remote('cns.csie.org', 6003)
context.arch = 'amd64'


r.recvuntil(b"P = ")
p = int(r.recvline().strip().decode())
r.recvuntil(b"g = ")
g = int(r.recvline().strip().decode())
r.recvuntil(b"cipher = (")
c1 = int(r.recvuntil(b", ").decode().replace(", ", ""))
c2 = int(r.recvuntil(b")\n").decode().replace(")\n", ""))

log.info("P = {}".format(p))
log.info("g = {}".format(g))
log.info("c1 = {}".format(c1))
log.info("c2 = {}".format(c2))


message_user_input = str(c1)
m = []
# print(r.recvline())
for i in range(1, 6):
    r.recvuntil(b'Do you want to decrypt something? (y/n): ')
    r.sendline(b'y')
    r.recvuntil(b'Give me your c1: ')
    r.sendline(message_user_input.encode())
    r.recvuntil(b'(1~5): ')
    # r.recvline()
    r.sendline(str(i).encode())
    m.append(int(r.recvline().decode()))

    log.info("m{} = {}".format(i, m[-1]))


tmp = ((m[0]**5)*inverse(m[1]**10, p)*(m[2]**10)*inverse(m[3]**5, p)*m[4]) % p
flag = bytes.fromhex(long_to_bytes((c2 * inverse(tmp, p)) % p).hex().replace("0x", "")).decode('utf-8')

log.info(flag)

r.close()