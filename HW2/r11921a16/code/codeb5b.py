from pwn import *

r = remote('cns.csie.org', 12346)
context.arch = 'amd64'

a_init = 0x9b78f3e598a4eefdb785ad571a91017b85418cd79347515da91d5b95fe99886eab96937f681d52315ca3042240371ed438db3f33150439d71e7fb07f9772a2bd
c_init = 0xe97d1423cba3ef9f5367193ca722b5c4e8da6d561c9cc98ba7ffbc0688f50ad3fce7ae84d21b69b0df1f24e8ddc533fc97da8441bc1f2031f293999a78520fb3
        

r.sendline(b'y')
r.recvline()
p = int(r.recvline().decode().split(" ")[-1].strip())
g = 2
r.recvline()
y = int(r.recvline().decode().split(" ")[-1].strip())

log.info("P = {}\ng = {}\ny = {}\n".format(p, g, y))

for i in range(2):
    r.recvlines(2)
    r.recvuntil(b"a = ")
    a = int(r.recvline().decode().split(" ")[-1].strip())
    r.sendlineafter(b"c = ", str(i).encode())
    if i == 0:
        r0 = int(r.recvline().decode().split(" ")[-1].strip())
        r1 = (a_init * r0 + c_init) % p
    else:
        w = int(r.recvline().decode().split(" ")[-1].strip())
        plaintext = w - r1
    
plaintext = bytes.fromhex(hex(plaintext).replace("0x", "")).decode('utf-8')
log.info("Flag 2 = {}".format(plaintext))
r.close()